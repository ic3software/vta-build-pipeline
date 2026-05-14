//! Deploy-mode storage primitives (§12.1, Phase 5 M5.4.1).
//!
//! Two modes, both flat-filesystem:
//!
//! - **Live** — `root_dir` is the served root directly. Bundle
//!   deploys (M5.5) extract into a sibling staging directory and
//!   then atomically rename over `root_dir` so concurrent reads
//!   never see a partial extraction.
//! - **Managed** — `root_dir/gen-N/` for each deployed generation,
//!   with `root_dir/current` as a symlink to the active
//!   generation. Rollback flips the symlink atomically.
//!
//! Phase 5 M5.4 ships only the **read** primitives — selecting the
//! served root, resolving the current generation in managed mode.
//! Write primitives (atomic-rename deploy + symlink flip) land in
//! M5.5 with the management API.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

/// In-memory representation of the website root. Cheap to clone;
/// rebuilt at boot from [`crate::config::WebsiteConfig`].
#[derive(Debug, Clone)]
pub enum WebsiteRoot {
    /// Serve files directly from `root`. Bundle deploys atomic-
    /// rename over `root`.
    Live { root: PathBuf },
    /// Serve files from `root/current/`. `current` is a symlink to
    /// `root/gen-N/` where N is the active generation.
    Managed { root: PathBuf },
}

impl WebsiteRoot {
    /// Build from a config root + deploy mode.
    pub fn new(root_dir: &Path, deploy_mode: &str) -> Result<Self, AppError> {
        let root = root_dir.to_path_buf();
        match deploy_mode {
            "live" => Ok(WebsiteRoot::Live { root }),
            "managed" => Ok(WebsiteRoot::Managed { root }),
            other => Err(AppError::Config(format!(
                "website.deploy_mode must be \"live\" or \"managed\"; got \"{other}\""
            ))),
        }
    }

    /// The directory we actually serve from. Resolves the
    /// `current` symlink in managed mode.
    pub fn serve_root(&self) -> PathBuf {
        match self {
            WebsiteRoot::Live { root } => root.clone(),
            WebsiteRoot::Managed { root } => root.join("current"),
        }
    }

    /// Root path the website manages (parent of the served
    /// directory in managed mode). Used by M5.5 deploys.
    pub fn manage_root(&self) -> &Path {
        match self {
            WebsiteRoot::Live { root } => root,
            WebsiteRoot::Managed { root } => root,
        }
    }
}

/// One generation entry returned by
/// [`list_managed_generations`].
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationEntry {
    pub generation: u32,
    pub is_current: bool,
    pub deployed_at: u64,
    pub size_bytes: u64,
}

/// Enumerate every `gen-N` directory under a managed root, marking
/// the one `current` resolves to.
pub fn list_managed_generations(root: &Path) -> Result<Vec<GenerationEntry>, AppError> {
    let current_target = std::fs::read_link(root.join("current")).ok();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root)
        .map_err(|e| AppError::Internal(format!("read_dir {root:?}: {e}")))?
        .flatten()
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("gen-") else {
            continue;
        };
        let gen_num: u32 = match rest.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let path = entry.path();
        let meta = entry
            .metadata()
            .map_err(|e| AppError::Internal(format!("stat {path:?}: {e}")))?;
        let deployed_at = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size_bytes = du(&path).unwrap_or(0);
        let is_current = current_target.as_deref() == Some(path.as_path())
            || current_target.as_deref() == Some(Path::new(&*name));
        out.push(GenerationEntry {
            generation: gen_num,
            is_current,
            deployed_at,
            size_bytes,
        });
    }
    out.sort_by_key(|g| g.generation);
    Ok(out)
}

/// Sum the file sizes under a directory (recursive). Returns
/// `None` on I/O error rather than failing the caller — the size
/// is informational.
fn du(path: &Path) -> Option<u64> {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let entries = std::fs::read_dir(&p).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Some(total)
}

/// Find the next free generation index in a managed root.
pub fn next_generation(root: &Path) -> Result<u32, AppError> {
    let gens = list_managed_generations(root)?;
    Ok(gens.iter().map(|g| g.generation).max().unwrap_or(0) + 1)
}

/// Atomically point `current` at `gen-N`. Implemented via the
/// `symlink(tmp)` + `rename(tmp, current)` idiom so a concurrent
/// reader never sees a broken symlink.
pub fn swap_current_symlink(root: &Path, target_gen: u32) -> Result<u32, AppError> {
    let target_dir = root.join(format!("gen-{target_gen}"));
    if !target_dir.exists() {
        return Err(AppError::NotFound(format!(
            "generation {target_gen} does not exist under {root:?}"
        )));
    }

    let from = std::fs::read_link(root.join("current"))
        .ok()
        .and_then(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|s| s.strip_prefix("gen-"))
                .and_then(|n| n.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let tmp = root.join(format!(".current.tmp.{}", random_suffix()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("gen-{target_gen}"), &tmp)
        .map_err(|e| AppError::Internal(format!("create temp symlink: {e}")))?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(format!("gen-{target_gen}"), &tmp)
        .map_err(|e| AppError::Internal(format!("create temp symlink: {e}")))?;

    std::fs::rename(&tmp, root.join("current"))
        .map_err(|e| AppError::Internal(format!("symlink swap: {e}")))?;

    Ok(from)
}

/// Drop generations beyond `keep`, oldest first. Returns the
/// count pruned.
pub fn prune_generations(root: &Path, keep: u32) -> Result<u32, AppError> {
    let mut gens = list_managed_generations(root)?;
    // Sort by generation ascending so we keep the highest N.
    gens.sort_by_key(|g| g.generation);
    let total = gens.len() as u32;
    if total <= keep {
        return Ok(0);
    }
    let to_prune = total - keep;
    let mut pruned = 0u32;
    for entry in gens.iter().take(to_prune as usize) {
        if entry.is_current {
            // Never prune the currently-active generation, even
            // if it's the oldest. Skip without incrementing the
            // pruned counter.
            continue;
        }
        let dir = root.join(format!("gen-{}", entry.generation));
        if std::fs::remove_dir_all(&dir).is_ok() {
            pruned += 1;
        }
    }
    Ok(pruned)
}

fn random_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_mode_serves_root_directly() {
        let root = PathBuf::from("/tmp/site");
        let w = WebsiteRoot::new(&root, "live").unwrap();
        assert_eq!(w.serve_root(), root);
        assert_eq!(w.manage_root(), root.as_path());
    }

    #[test]
    fn managed_mode_serves_current_symlink() {
        let root = PathBuf::from("/tmp/site");
        let w = WebsiteRoot::new(&root, "managed").unwrap();
        assert_eq!(w.serve_root(), root.join("current"));
        assert_eq!(w.manage_root(), root.as_path());
    }

    #[test]
    fn rejects_unknown_deploy_mode() {
        let root = PathBuf::from("/tmp/site");
        let err = WebsiteRoot::new(&root, "magical").unwrap_err();
        assert!(format!("{err}").contains("live"), "got {err}");
    }
}
