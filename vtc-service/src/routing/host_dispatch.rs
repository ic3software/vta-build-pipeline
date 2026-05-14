//! Subdomain-mode `Host` header check (Phase 5 M5.1.2).
//!
//! Tower middleware that inspects the request `Host` header against
//! the per-surface map declared in [`crate::config::RoutingConfig`].
//! Behaviour:
//!
//! - When **every** surface has `host = None` (pure path mode), the
//!   middleware is a no-op — the parent router does prefix matching
//!   alone.
//! - When **any** surface has a host set, the middleware:
//!   1. Reads `Host` from the request (HTTP/2 `:authority` is
//!      normalised onto the `Host` header by axum before the layer
//!      runs).
//!   2. Matches against the set of configured surface hosts
//!      (case-insensitive, port-aware).
//!   3. On match: pass through. The parent router then routes by
//!      path within whichever surface matches.
//!   4. On miss + `subdomain_mode_strict = true` (default): returns
//!      404 `HostNotRecognised`.
//!   5. On miss + `subdomain_mode_strict = false`: pass through —
//!      the parent router falls back to path matching against all
//!      configured mounts. Debug aid only; not recommended for
//!      production.
//!
//! Per-host/per-path enforcement (e.g. `admin.example.com` 404s
//! `/v1/...` paths) is **not** in this middleware. The path-mode
//! prefix matching inside axum's `Router::nest` already does that —
//! a path that doesn't match the surface's nest boundary returns
//! 404 via the regular handler chain.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{StatusCode, header::HOST};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::config::RoutingConfig;

/// Compiled host map. Cheap to clone, shared across requests via
/// `Arc`. Built once at router-assembly time so the per-request
/// path is a single `HashSet::contains` call.
#[derive(Debug, Clone)]
pub struct HostMap {
    /// Lower-cased configured hosts. Empty when every surface uses
    /// path mode — the layer short-circuits.
    hosts: Arc<HashSet<String>>,
    strict: bool,
}

impl HostMap {
    /// Compile the surface host set from [`RoutingConfig`].
    pub fn from_routing(routing: &RoutingConfig) -> Self {
        let mut hosts = HashSet::new();
        for surface in [&routing.api, &routing.admin_ui, &routing.website] {
            if let Some(h) = surface.host.as_deref() {
                hosts.insert(h.to_ascii_lowercase());
            }
        }
        Self {
            hosts: Arc::new(hosts),
            strict: routing.subdomain_mode_strict,
        }
    }

    /// True when no surface has a `host` set; the middleware is a
    /// no-op in that case.
    pub fn is_path_mode(&self) -> bool {
        self.hosts.is_empty()
    }

    /// True when the configured Host map recognises this header
    /// value (case-insensitive). Returns `true` unconditionally in
    /// path mode so callers can use it as a single decision point.
    fn matches(&self, host_header: &str) -> bool {
        if self.is_path_mode() {
            return true;
        }
        self.hosts.contains(&host_header.to_ascii_lowercase())
    }
}

/// Tower middleware function. Wire via
/// `axum::middleware::from_fn_with_state(host_map.clone(), enforce)`.
pub async fn enforce(
    axum::extract::State(map): axum::extract::State<HostMap>,
    request: Request,
    next: Next,
) -> Response {
    if map.is_path_mode() {
        return next.run(request).await;
    }

    let host = request
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let allowed = match host.as_deref() {
        Some(h) => map.matches(h),
        // Missing Host header — HTTP/1.1 requires it. Treat as
        // unrecognised in strict mode.
        None => false,
    };

    if allowed || !map.strict {
        return next.run(request).await;
    }

    // 404 with the same JSON shape as `AppError::IntoResponse`.
    let body = json!({
        "error": "HostNotRecognised",
        "host": host,
    });
    (StatusCode::NOT_FOUND, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MountConfig;

    fn cfg(
        api_host: Option<&str>,
        admin_host: Option<&str>,
        web_host: Option<&str>,
    ) -> RoutingConfig {
        RoutingConfig {
            api: MountConfig {
                mount: "/v1".into(),
                host: api_host.map(String::from),
            },
            admin_ui: MountConfig {
                mount: "/admin".into(),
                host: admin_host.map(String::from),
            },
            website: MountConfig {
                mount: "/".into(),
                host: web_host.map(String::from),
            },
            subdomain_mode_strict: true,
        }
    }

    #[test]
    fn path_mode_when_no_hosts_set() {
        let map = HostMap::from_routing(&cfg(None, None, None));
        assert!(map.is_path_mode());
        // matches() returns true for anything in path mode.
        assert!(map.matches("anything.example.com"));
    }

    #[test]
    fn matches_recognises_configured_host() {
        let map = HostMap::from_routing(&cfg(
            Some("api.example.com"),
            Some("admin.example.com"),
            None,
        ));
        assert!(!map.is_path_mode());
        assert!(map.matches("api.example.com"));
        assert!(map.matches("ADMIN.example.com")); // case-insensitive
        assert!(!map.matches("other.example.com"));
    }
}
