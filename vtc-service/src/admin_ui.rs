//! Embedded admin UX (§12.2, Phase 5 M5.6 + M5.7).
//!
//! Static HTML/CSS/JS source lives at `vtc-service/admin-ui/` and
//! is baked into the binary at compile time via
//! [`include_dir::include_dir!`]. Per Phase 5 D1 the source is
//! **in-tree** — there is no sibling `OpenVTC/vtc-admin-ui` repo,
//! no signed-tarball fetch, no `VTC_OFFLINE_BUILD=1` env var.
//! `cargo build` builds the admin UX as part of the daemon
//! without any out-of-tree dependencies.
//!
//! Operators wanting a richer SPA replace the files in
//! `admin-ui/` and rebuild.

#![cfg(feature = "admin-ui")]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};

/// In-binary copy of `vtc-service/admin-ui/`. Walked at request
/// time to map paths → file bytes.
pub static ADMIN_UI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/admin-ui");

/// Metadata derived once at startup. Used by the build-info
/// endpoint and the `AdminUiServed` audit envelope.
#[derive(Debug, Clone)]
pub struct AdminUiInfo {
    /// SHA-256 of the baked `index.html`, hex-encoded.
    pub index_sha256: Arc<String>,
    /// Total file count in the baked directory.
    pub file_count: u32,
    /// `"embedded"` (default) or `"external"`.
    pub mode: Arc<String>,
}

impl AdminUiInfo {
    /// Compute from the embedded directory at startup.
    pub fn from_embedded(mode: &str) -> Self {
        let index_bytes = ADMIN_UI_DIR
            .get_file("index.html")
            .map(|f| f.contents())
            .unwrap_or_default();
        let index_sha256 = hex::encode(Sha256::digest(index_bytes));
        let file_count = count_files(&ADMIN_UI_DIR);
        Self {
            index_sha256: Arc::new(index_sha256),
            file_count,
            mode: Arc::new(mode.to_string()),
        }
    }
}

fn count_files(dir: &Dir<'_>) -> u32 {
    let mut total: u32 = 0;
    for f in dir.files() {
        let _ = f;
        total = total.saturating_add(1);
    }
    for sub in dir.dirs() {
        total = total.saturating_add(count_files(sub));
    }
    total
}

/// Look up a request path in the embedded directory. Returns
/// `Some(bytes)` for an exact match; the caller is responsible
/// for the SPA history-mode fallback to `index.html`.
pub fn lookup(rel_path: &str) -> Option<&'static [u8]> {
    let trimmed = rel_path.trim_start_matches('/');
    ADMIN_UI_DIR.get_file(trimmed).map(|f| f.contents())
}

/// Axum handler for `GET /admin/*`. Walks the request path
/// through the embedded directory; falls back to `index.html`
/// for client-side routing (SPA history mode).
pub async fn serve(req: Request<Body>) -> Response {
    let rel = req.uri().path().trim_start_matches("/admin");
    let rel = if rel.is_empty() || rel == "/" {
        "/index.html"
    } else {
        rel
    };

    let bytes = lookup(rel).or_else(|| lookup("/index.html"));
    let Some(bytes) = bytes else {
        return (StatusCode::NOT_FOUND, "admin UX not embedded").into_response();
    };

    let mime = mime_guess::from_path(rel)
        .first_or_octet_stream()
        .to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

// Re-export so the build-info handler in `routes::admin_ui` can
// reach the metadata without duplicating the SHA-256 computation.
use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dir_has_index() {
        assert!(
            ADMIN_UI_DIR.get_file("index.html").is_some(),
            "index.html missing from embedded admin-ui — did the source dir get deleted?"
        );
    }

    #[test]
    fn lookup_returns_bytes_for_known_files() {
        let bytes = lookup("/index.html").expect("index.html");
        let body = std::str::from_utf8(bytes).unwrap();
        assert!(body.contains("VTC Admin"), "got {body}");
    }

    #[test]
    fn lookup_returns_none_for_unknown() {
        assert!(lookup("/missing.html").is_none());
    }

    #[test]
    fn info_carries_sha_of_index_html() {
        let info = AdminUiInfo::from_embedded("embedded");
        assert_eq!(info.index_sha256.len(), 64, "hex sha256 = 64 chars");
        assert!(info.file_count >= 3, "expect index + css + js at minimum");
        assert_eq!(info.mode.as_str(), "embedded");
    }
}
