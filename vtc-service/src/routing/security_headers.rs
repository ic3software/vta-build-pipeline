//! Browser security-header middleware (Phase 5 M5.3.2).
//!
//! Attached to the admin UX + website sub-routers — both surfaces
//! serve HTML/JS to a browser. The API sub-router does **not** get
//! these headers; it's a JSON wire surface for programmatic clients
//! and CSP is meaningless there.
//!
//! Headers attached:
//!
//! - `X-Content-Type-Options: nosniff` — refuses browser MIME
//!   sniffing. Always on.
//! - `Content-Security-Policy` — default policy below. Spec §12.1
//!   lets operators relax this per-site for SPA needs once the
//!   website handler (M5.4) reads a `.vtc-website.toml` override.
//!   `font-src 'self' data:` accommodates the @fontsource-variable
//!   subsets that Vite inlines under its 4 KiB asset threshold;
//!   `style-src 'unsafe-inline'` covers React's `style={{...}}`
//!   prop usage. Neither widens the attack surface beyond what a
//!   typical SPA already accepts.
//!
//! When the response already carries one of these headers (e.g. a
//! handler wants a stricter `Cache-Control: no-store` and bundled
//! its own CSP), the middleware **does not overwrite** — it only
//! fills in missing headers.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{CONTENT_SECURITY_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::middleware::Next;
use axum::response::Response;

/// Default CSP attached to admin UX + website responses.
pub const DEFAULT_CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     font-src 'self' data:; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'";

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn(security_headers)` on the admin UX
/// and website sub-routers.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    if !headers.contains_key(X_CONTENT_TYPE_OPTIONS) {
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        // `from_static` is safe — `DEFAULT_CSP` is ASCII.
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(DEFAULT_CSP),
        );
    }

    response
}
