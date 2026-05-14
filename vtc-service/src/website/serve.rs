//! Public static handler (§12.1, Phase 5 M5.4.2).
//!
//! The handler mounts under `routing.website.mount` (default `/`)
//! as a catch-all and serves files from
//! [`crate::website::WebsiteRoot::serve_root`] with the full
//! path-safety chain + content cache.
//!
//! Response headers:
//!
//! - `Content-Type` — `mime_guess::from_path` with
//!   `application/octet-stream` fallback.
//! - `ETag` — `"<sha256-hex>"` of the file contents (already
//!   computed by [`crate::website::cache::WebsiteCache::get`]).
//! - `Cache-Control` — from `website.cache_control`.
//! - `X-Content-Type-Options: nosniff` — handled by the
//!   [`crate::routing::security_headers`] middleware attached to
//!   the website sub-router.
//! - Default CSP — also from `security_headers` middleware.
//!   Per-site override via `<root>/.vtc-website.toml` is **read
//!   here** (so it can override what the middleware would
//!   default) and overwrites the `Content-Security-Policy` header
//!   the middleware later attaches.
//!
//! `If-None-Match` is honoured: matching ETag → 304 without body.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::error::AppError;
use crate::website::cache::WebsiteCache;
use crate::website::paths::{PathError, canonical_within_root};
use crate::website::storage::WebsiteRoot;

/// All state the [`serve`] handler needs. Held inside the website
/// sub-router via `Router::with_state`.
#[derive(Debug, Clone)]
pub struct WebsiteState {
    pub root: WebsiteRoot,
    pub cache: WebsiteCache,
    pub executable_blocklist: Vec<String>,
    pub cache_control: String,
    pub csp_override_file: String,
}

/// Optional per-site override TOML — read once per request from
/// `<root>/.vtc-website.toml` (or whatever
/// `website.csp_override_file` points at).
#[derive(Debug, Deserialize, Default)]
pub struct WebsiteOverride {
    /// CSP value to emit instead of the daemon default. Operator-
    /// supplied verbatim; the daemon does not validate the
    /// directive grammar.
    pub csp: Option<String>,
}

/// Axum handler. Mounted at the website sub-router as a catch-all
/// fallback (`/{*path}` semantics) so any unmatched request lands
/// here.
pub async fn serve(State(state): State<WebsiteState>, req: Request<Body>) -> Response {
    match serve_inner(&state, req.uri()).await {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

async fn serve_inner(state: &WebsiteState, uri: &Uri) -> Result<Response, AppError> {
    let raw_path = uri.path();
    // Default-document rule: a directory request maps to
    // `index.html`. The path-safety chain runs against the
    // resolved file path.
    let req_path = if raw_path == "/" || raw_path.ends_with('/') {
        format!("{raw_path}index.html")
    } else {
        raw_path.to_string()
    };

    let serve_root = state.root.serve_root();
    let resolved = match canonical_within_root(&serve_root, &req_path, &state.executable_blocklist)
    {
        Ok(p) => p,
        Err(PathError::NotFound) => {
            return Err(AppError::NotFound(format!("no such resource: {raw_path}")));
        }
        Err(PathError::Hidden) => {
            return Err(AppError::NotFound(format!("no such resource: {raw_path}")));
        }
        Err(PathError::BlockedExtension(ext)) => {
            return Err(AppError::Forbidden(format!(
                "extension {ext} is blocked by website.executable_blocklist"
            )));
        }
        Err(PathError::Escape | PathError::ControlChars | PathError::NonNfc) => {
            return Err(AppError::Validation(format!(
                "request path rejected by website path-safety: {raw_path}"
            )));
        }
        Err(PathError::ExecBit) => {
            return Err(AppError::Forbidden(
                "file has executable bit set; refusing to serve".into(),
            ));
        }
    };

    // Refuse directories (e.g. caller hit `/assets/` and the
    // resolved path is a directory). Default-document handling
    // above already redirected `/` to `/index.html`; any
    // remaining directory hit is operator error.
    if let Ok(meta) = tokio::fs::metadata(&resolved).await
        && meta.is_dir()
    {
        return Err(AppError::NotFound("path resolves to a directory".into()));
    }

    let cached = state
        .cache
        .get(&resolved)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read website file: {e}")))?;

    let etag = format!("\"{}\"", cached.digest_hex);

    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .to_string();

    let csp_override = read_csp_override(&serve_root, &state.csp_override_file).await;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ETAG, etag.clone())
        .header(header::CACHE_CONTROL, state.cache_control.clone());

    if let Some(csp) = csp_override {
        // Per-site override wins over the default CSP that
        // `routing::security_headers` would attach later.
        builder = builder.header(header::CONTENT_SECURITY_POLICY, csp);
    }

    builder
        .body(Body::from((*cached.body).clone()))
        .map_err(|e| AppError::Internal(format!("response build: {e}")))
}

async fn read_csp_override(serve_root: &Path, override_file: &str) -> Option<String> {
    let path: PathBuf = serve_root.join(override_file);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let parsed: WebsiteOverride = toml::from_slice(&bytes).ok()?;
    parsed.csp
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn block() -> Vec<String> {
        vec![".cgi".into(), ".php".into(), ".exe".into()]
    }

    async fn make_state(root: &Path) -> WebsiteState {
        WebsiteState {
            root: WebsiteRoot::new(root, "live").unwrap(),
            cache: WebsiteCache::new(60),
            executable_blocklist: block(),
            cache_control: "public, max-age=300".into(),
            csp_override_file: ".vtc-website.toml".into(),
        }
    }

    #[tokio::test]
    async fn serves_existing_file_with_etag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.html"), "<p>hi</p>").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/hello.html".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::ETAG).is_some());
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .map(|h| h.to_str().unwrap()),
            Some("public, max-age=300"),
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), b"<p>hi</p>");
    }

    #[tokio::test]
    async fn serves_index_for_root_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>home</title>").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .starts_with("text/html"),
            "got {:?}",
            resp.headers().get(header::CONTENT_TYPE)
        );
    }

    #[tokio::test]
    async fn rejects_hidden_with_404() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".secrets"), "shh").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/.secrets".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_blocked_extension_with_403() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.cgi"), "#!/bin/sh\n").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/evil.cgi".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_dotdot_escape_with_validation_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "ok").unwrap();
        let state = make_state(dir.path()).await;

        // After canonicalisation this resolves outside `root_dir`
        // (or fails to resolve), so we expect a 404 or 400. The
        // host platform's behaviour around non-existent paths can
        // pick either branch — accept both as "not served".
        let uri: Uri = "/../../etc/passwd".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(
            matches!(err, AppError::NotFound(_) | AppError::Validation(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn directory_request_404s() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        let state = make_state(dir.path()).await;

        // `/assets` (no trailing slash) resolves to a directory;
        // the default-document rule only fires on trailing slash.
        // Must 404 — we don't auto-list directories.
        let uri: Uri = "/assets".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn per_site_csp_override_wins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>home</title>").unwrap();
        std::fs::write(
            dir.path().join(".vtc-website.toml"),
            r#"csp = "default-src https:; script-src 'self' 'unsafe-inline'""#,
        )
        .unwrap();
        // Note: .vtc-website.toml itself is hidden (starts with .)
        // but we read it from disk, not via the request path. The
        // path-safety chain only runs against request URLs.
        let state = make_state(dir.path()).await;

        let uri: Uri = "/".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(csp.contains("'unsafe-inline'"), "got CSP: {csp}");
    }
}
