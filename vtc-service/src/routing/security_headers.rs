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
//! - `X-Frame-Options: DENY` — legacy clickjacking guard. Paired
//!   with `frame-ancestors 'none'` in the CSP below for browsers
//!   that don't honour XFO.
//! - `Referrer-Policy: no-referrer` — passkey-login URLs and the
//!   install-claim ceremony shouldn't leak via outbound `Referer`.
//! - `Strict-Transport-Security` — only on responses that are
//!   already served over HTTPS (the request scheme tells us). HSTS
//!   on plain-HTTP localhost / staging deployments would just
//!   confuse browsers; the daemon emits it when the wire is
//!   actually TLS.
//! - `Content-Security-Policy` — default policy below. Spec §12.1
//!   lets operators relax this per-site for SPA needs once the
//!   website handler (M5.4) reads a `.vtc-website.toml` override.
//!   `font-src 'self' data:` accommodates the @fontsource-variable
//!   subsets that Vite inlines under its 4 KiB asset threshold;
//!   `style-src 'unsafe-inline'` covers React's `style={{...}}`
//!   prop usage. Neither widens the attack surface beyond what a
//!   typical SPA already accepts. `frame-ancestors 'none'` blocks
//!   framing of the admin UX + install ceremony — phishing sites
//!   can't embed `/admin/install?token=…` in an iframe to trick
//!   operators into completing the claim against a wrong RP.
//!
//! When the response already carries one of these headers (e.g. a
//! handler wants a stricter `Cache-Control: no-store` and bundled
//! its own CSP), the middleware **does not overwrite** — it only
//! fills in missing headers.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// Default CSP attached to admin UX + website responses. The
/// `frame-ancestors 'none'` directive is the modern replacement for
/// `X-Frame-Options: DENY`; both ship together because IE/legacy
/// only honours XFO.
pub const DEFAULT_CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     font-src 'self' data:; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'; \
     frame-ancestors 'none'";

/// HSTS — two-year max-age, includeSubDomains. Emitted only on
/// HTTPS requests; an operator running plain-HTTP locally
/// shouldn't get sticky upgrade-to-HTTPS state.
const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn(security_headers)` on the admin UX
/// and website sub-routers.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let scheme_is_https = request.uri().scheme_str() == Some("https");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    if !headers.contains_key(X_CONTENT_TYPE_OPTIONS) {
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    if !headers.contains_key(X_FRAME_OPTIONS) {
        headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    if !headers.contains_key(REFERRER_POLICY) {
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    }
    // `Permissions-Policy` is non-canonical in the `http` crate header
    // map, so we build the name manually. Refuse every default-on
    // browser capability — the admin UX never needs camera, mic, USB,
    // payments, geolocation, etc.
    let permissions_policy: HeaderName = HeaderName::from_static("permissions-policy");
    if !headers.contains_key(&permissions_policy) {
        headers.insert(
            permissions_policy,
            HeaderValue::from_static(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        );
    }
    if scheme_is_https && !headers.contains_key(STRICT_TRANSPORT_SECURITY) {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS_VALUE),
        );
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
