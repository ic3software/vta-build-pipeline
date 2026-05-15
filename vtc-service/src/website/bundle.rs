//! Bundle extraction primitives (§12.1, Phase 5 M5.5.3).
//!
//! `POST /v1/website/deploy` accepts a tar.gz bundle. The handler
//! streams the body into a temp file, computes its SHA-256, then
//! runs every entry through [`verify_entries`] before extraction.
//! A bundle that contains any of:
//!
//! - `..` segments
//! - absolute paths
//! - symlink entries
//! - hidden top-level paths (segments starting with `.`)
//! - executable bits set on regular files
//! - blocklisted extensions
//! - a declared decompressed size exceeding the operator's cap
//!   (defense-in-depth against gzip bombs that claim small
//!   compressed bytes but explode on extraction)
//!
//! is rejected **before** any extract happens. Survivors extract
//! to a fresh staging directory via [`extract_to`]; the caller
//! atomically swaps the staging dir into place. Extraction itself
//! is wrapped in `Read::take(cap)` so a malformed/lying tar header
//! can't sneak past the verify pass and still write more bytes than
//! the cap allows.

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

use crate::error::AppError;

/// Multiplier applied to the operator's compressed-bundle cap to
/// derive a decompressed-size ceiling. A real-world tar.gz of HTML
/// + assets rarely exceeds 4× compression; 10× leaves comfortable
/// headroom while still catching adversarial 1000:1 zip bombs.
pub const DECOMPRESSION_EXPANSION_RATIO: u64 = 10;

/// Reasons a bundle entry can fail the pre-extract verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// Entry path contained `..` segments.
    DotDot(String),
    /// Entry path was absolute.
    Absolute(String),
    /// Entry was a symlink (or hardlink).
    SymlinkOrHardlink(String),
    /// Entry path component starts with `.`.
    Hidden(String),
    /// Entry has the executable bit set on a regular file.
    ExecBit(String),
    /// Entry extension is in the blocklist.
    BlockedExtension(String, String),
    /// Cumulative declared (verify) or streamed (extract)
    /// decompressed size exceeds the operator's cap. Defends
    /// against gzip bombs that pack a small compressed payload
    /// into many gigabytes on disk.
    Oversize { declared: u64, cap: u64 },
    /// Underlying I/O / tar error.
    Io(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::DotDot(p) => write!(f, "entry path contains `..`: {p}"),
            BundleError::Absolute(p) => write!(f, "entry path is absolute: {p}"),
            BundleError::SymlinkOrHardlink(p) => {
                write!(f, "entry is a symlink/hardlink: {p}")
            }
            BundleError::Hidden(p) => write!(f, "entry path component is hidden: {p}"),
            BundleError::ExecBit(p) => write!(f, "entry has executable bit set: {p}"),
            BundleError::BlockedExtension(p, ext) => {
                write!(f, "entry extension {ext} is blocklisted: {p}")
            }
            BundleError::Oversize { declared, cap } => {
                write!(
                    f,
                    "decompressed bundle size {declared} exceeds cap {cap} (zip-bomb guard)"
                )
            }
            BundleError::Io(msg) => write!(f, "tar I/O error: {msg}"),
        }
    }
}

impl From<BundleError> for AppError {
    fn from(e: BundleError) -> Self {
        match e {
            BundleError::Io(msg) => AppError::Internal(msg),
            other => AppError::Validation(other.to_string()),
        }
    }
}

/// Verify every entry in a `.tar.gz` bundle before extraction.
/// Returns `Ok(())` if the bundle is safe to extract or the first
/// rejection on the first unsafe entry.
///
/// `decompressed_cap_bytes` is the operator-derived ceiling on
/// total declared entry size — pass `compressed_cap *
/// DECOMPRESSION_EXPANSION_RATIO`. If the sum of `entry.header()
/// .size()?` across the archive exceeds the cap, the bundle is
/// rejected before any disk I/O happens. Pass `u64::MAX` to opt
/// out (tests).
pub fn verify_entries(
    bundle_bytes: &[u8],
    blocklist: &[String],
    decompressed_cap_bytes: u64,
) -> Result<(), BundleError> {
    let gz = GzDecoder::new(bundle_bytes);
    let mut archive = Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| BundleError::Io(e.to_string()))?;

    let mut total: u64 = 0;
    for entry in entries {
        let entry = entry.map_err(|e| BundleError::Io(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| BundleError::Io(e.to_string()))?
            .into_owned();
        let path_str = path.to_string_lossy().to_string();

        // Reject symlinks/hardlinks.
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(BundleError::SymlinkOrHardlink(path_str));
        }

        // Reject absolute paths.
        if path.is_absolute() {
            return Err(BundleError::Absolute(path_str));
        }

        // Reject `..` segments + hidden components.
        for component in path.components() {
            use std::path::Component;
            match component {
                Component::ParentDir => return Err(BundleError::DotDot(path_str)),
                Component::Normal(seg) if seg.to_string_lossy().starts_with('.') => {
                    return Err(BundleError::Hidden(path_str));
                }
                _ => {}
            }
        }

        // Reject blocklisted extensions.
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let dotted = format!(".{}", ext.to_ascii_lowercase());
            if blocklist.iter().any(|b| b.eq_ignore_ascii_case(&dotted)) {
                return Err(BundleError::BlockedExtension(path_str, dotted));
            }
        }

        // Reject exec bit on regular files (Unix mode word in
        // header).
        if entry_type.is_file() {
            let mode = entry
                .header()
                .mode()
                .map_err(|e| BundleError::Io(e.to_string()))?;
            if mode & 0o111 != 0 {
                return Err(BundleError::ExecBit(path_str));
            }
        }

        // Accumulate declared decompressed size. Tar headers can
        // lie about size (the extract path enforces the same cap
        // streaming), but rejecting on the cheap check first
        // avoids spending CPU on a hostile bundle.
        let size = entry.header().size().unwrap_or(0);
        total = total.saturating_add(size);
        if total > decompressed_cap_bytes {
            return Err(BundleError::Oversize {
                declared: total,
                cap: decompressed_cap_bytes,
            });
        }
    }

    Ok(())
}

/// Extract `bundle_bytes` into `target_dir`. Caller is responsible
/// for the atomic rename / symlink swap; this function only
/// writes files.
///
/// `decompressed_cap_bytes` wraps the gzip stream in
/// `Read::take(cap)` so the unpack writes at most `cap` bytes
/// before the underlying reader EOFs — a tar entry whose header
/// claims a small size but streams more is truncated and the
/// extract returns an error. Pass `u64::MAX` to opt out.
pub fn extract_to(
    bundle_bytes: &[u8],
    target_dir: &Path,
    decompressed_cap_bytes: u64,
) -> Result<(), AppError> {
    std::fs::create_dir_all(target_dir)
        .map_err(|e| AppError::Internal(format!("create_dir_all {target_dir:?}: {e}")))?;

    let gz = GzDecoder::new(bundle_bytes).take(decompressed_cap_bytes);
    let mut archive = Archive::new(gz);
    archive.set_preserve_permissions(false);
    archive.set_overwrite(true);

    archive
        .unpack(target_dir)
        .map_err(|e| AppError::Internal(format!("tar unpack: {e}")))?;
    Ok(())
}

/// Convenience: combine `verify_entries` + `extract_to` so the
/// route handler can call once. `decompressed_cap_bytes` is
/// applied to both phases.
pub fn verify_and_extract(
    bundle_bytes: &[u8],
    target_dir: &Path,
    blocklist: &[String],
    decompressed_cap_bytes: u64,
) -> Result<(), AppError> {
    verify_entries(bundle_bytes, blocklist, decompressed_cap_bytes)?;
    extract_to(bundle_bytes, target_dir, decompressed_cap_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};

    fn block() -> Vec<String> {
        vec![".cgi".into(), ".php".into(), ".exe".into()]
    }

    fn build_bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);
            for (name, body) in entries {
                let mut hdr = Header::new_gnu();
                hdr.set_path(name).unwrap();
                hdr.set_size(body.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                tar.append(&hdr, *body).unwrap();
            }
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn happy_bundle_passes_verification() {
        let bundle = build_bundle(&[
            ("index.html", b"<html></html>"),
            ("assets/logo.png", b"PNG"),
        ]);
        verify_entries(&bundle, &block(), u64::MAX).expect("ok");
    }

    #[test]
    fn rejects_dotdot_segment() {
        // The `tar` crate's writer rejects `..` paths up front, so
        // we hand-roll the header bytes. The path field is the
        // first 100 bytes of the 512-byte header; writing a name
        // with `..` directly bypasses the writer's safety net and
        // simulates a malicious bundle.
        let bundle = build_bundle(&[("placeholder", b"x")]);
        // Patch the path bytes in the gzip-decompressed tar to
        // start with `../`.
        let mut decoded = Vec::new();
        let mut gz = GzDecoder::new(&bundle[..]);
        std::io::copy(&mut gz, &mut decoded).unwrap();
        // First 100 bytes of the header = entry path. Overwrite
        // with `../escape\0...`.
        let new_name = b"../escape";
        decoded[..new_name.len()].copy_from_slice(new_name);
        for b in &mut decoded[new_name.len()..100] {
            *b = 0;
        }
        // Recompute checksum (header bytes 148..156 are the
        // octal checksum field).
        for b in &mut decoded[148..156] {
            *b = b' ';
        }
        let sum: u32 = decoded[..512].iter().map(|&b| b as u32).sum();
        let cksum = format!("{sum:06o}\0 ");
        decoded[148..156].copy_from_slice(cksum.as_bytes());

        // Re-gzip the patched tar.
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut gz, &decoded).unwrap();
        let patched = gz.finish().unwrap();

        let err = verify_entries(&patched, &block(), u64::MAX).expect_err("must reject");
        assert!(matches!(err, BundleError::DotDot(_)), "got {err:?}");
    }

    #[test]
    fn rejects_hidden_top_level() {
        let bundle = build_bundle(&[(".secret", b"x")]);
        let err = verify_entries(&bundle, &block(), u64::MAX).expect_err("must reject");
        assert!(matches!(err, BundleError::Hidden(_)), "got {err:?}");
    }

    #[test]
    fn rejects_blocklisted_extension() {
        let bundle = build_bundle(&[("evil.cgi", b"#!/bin/sh\n")]);
        let err = verify_entries(&bundle, &block(), u64::MAX).expect_err("must reject");
        assert!(
            matches!(err, BundleError::BlockedExtension(_, _)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_exec_bit() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);
            let body = b"#!/bin/sh\n";
            let mut hdr = Header::new_gnu();
            hdr.set_path("script.sh").unwrap();
            hdr.set_size(body.len() as u64);
            hdr.set_mode(0o755); // exec bit
            hdr.set_cksum();
            tar.append(&hdr, &body[..]).unwrap();
            tar.finish().unwrap();
        }
        let bundle = gz.finish().unwrap();
        let err = verify_entries(&bundle, &block(), u64::MAX).expect_err("must reject");
        assert!(matches!(err, BundleError::ExecBit(_)), "got {err:?}");
    }

    #[test]
    fn extracts_happy_bundle() {
        let bundle = build_bundle(&[("index.html", b"<html></html>")]);
        let dir = tempfile::tempdir().unwrap();
        extract_to(&bundle, dir.path(), u64::MAX).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"<html></html>"
        );
    }

    #[test]
    fn rejects_oversize_declared_total() {
        // The bundle declares two 100-byte entries (200 bytes total
        // decompressed). Verifying with a 150-byte cap must reject
        // before any disk I/O.
        let payload = vec![b'X'; 100];
        let bundle = build_bundle(&[
            ("a.html", payload.as_slice()),
            ("b.html", payload.as_slice()),
        ]);
        let err = verify_entries(&bundle, &block(), 150).expect_err("must reject");
        match err {
            BundleError::Oversize { cap, declared } => {
                assert_eq!(cap, 150);
                assert!(declared > 150, "declared={declared}");
            }
            other => panic!("expected Oversize, got {other:?}"),
        }
    }
}
