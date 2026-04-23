//! Minimal hex helpers used across the SDK and CLI binaries.
//!
//! The workspace used to carry six copies of `hex_lower` (vta-sdk,
//! vta-cli-common × 2, pnm-cli, vta-service × 2). Centralising here
//! ensures the canonical-lowercase digest format used everywhere
//! (bundle ids, SHA-256 digests, nonces) doesn't drift between call
//! sites.

/// Encode a byte slice as lowercase hex, two chars per byte.
///
/// Wrapped for portability rather than depending on a third-party `hex`
/// crate — the function is 10 lines and the workspace already has its
/// own multibase stack for anything more structured.
pub fn lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_formats_bytes() {
        assert_eq!(lower(&[0x0a, 0xff, 0x00]), "0aff00");
        assert_eq!(lower(&[]), "");
        assert_eq!(lower(&[0x00]), "00");
    }
}
