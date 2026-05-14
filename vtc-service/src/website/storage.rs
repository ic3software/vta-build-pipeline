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
