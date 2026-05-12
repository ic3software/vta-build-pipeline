//! `did:webvh` log publication route.
//!
//! The VTC's identity is a `did:webvh` provisioned by the VTA's
//! `vtc-host` template (see `tasks/vtc-mvp/vta-driven-keys.md` §10).
//! Every `did:webvh` resolver that wants to verify a VC the VTC
//! signs needs to fetch the canonical `did.jsonl` log; this route
//! serves it.
//!
//! ## Wire shape
//!
//! `GET /v1/{scid}/did.jsonl` → `200 application/jsonl` with the
//! log content.
//!
//! Trust-Task-**exempt** because DID resolvers won't carry our
//! private extension header.
//!
//! ## Storage
//!
//! Reads from `<config.store.data_dir>/did/<scid>.jsonl`. The setup
//! wizard wrote the file at first-boot when it opened the VTA's
//! `TemplateBootstrapPayload` — see
//! `vta_sdk::sealed_transfer::template_bootstrap::TemplateOutput`'s
//! `did.jsonl` entry.
//!
//! ## Safety
//!
//! The `scid` parameter is constrained to a charset that matches
//! the did:webvh SCID grammar (alphanumeric only). The match
//! against `config.vtc_did`'s SCID is exact; a mismatch returns
//! 404 (we don't host arbitrary DIDs).

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;

use crate::server::AppState;

/// `GET /v1/{scid}/did.jsonl`
pub async fn did_log(State(state): State<AppState>, Path(scid): Path<String>) -> impl IntoResponse {
    if !is_valid_scid(&scid) {
        return (StatusCode::NOT_FOUND, "did log not found").into_response();
    }
    let config = state.config.read().await;

    // Confirm the requested scid matches the VTC's own DID. The VTC
    // is not a general-purpose did:webvh host — we host exactly one
    // DID, our own.
    match config.vtc_did.as_deref().and_then(extract_scid_from_did) {
        Some(expected) if expected == scid => {}
        _ => return (StatusCode::NOT_FOUND, "did log not found").into_response(),
    }

    let path = config
        .store
        .data_dir
        .join("did")
        .join(format!("{scid}.jsonl"));
    drop(config);

    let body = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "did log not found").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "failed to read did log");
            return (StatusCode::INTERNAL_SERVER_ERROR, "did log read failed").into_response();
        }
    };

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/jsonl"),
        )],
        body,
    )
        .into_response()
}

fn is_valid_scid(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Pull the SCID out of a `did:webvh:<host>:<…path…>:<scid>` —
/// the SCID is the **last** colon-separated component.
fn extract_scid_from_did(did: &str) -> Option<String> {
    let suffix = did.strip_prefix("did:webvh:")?;
    let last = suffix.split(':').next_back()?;
    if is_valid_scid(last) {
        Some(last.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_scid_accepts_alphanumeric() {
        assert!(is_valid_scid("abc123"));
        assert!(is_valid_scid("zQmPLwUBtaqz3a"));
        assert!(is_valid_scid("foo-bar_baz"));
    }

    #[test]
    fn valid_scid_rejects_separators_and_empty() {
        assert!(!is_valid_scid(""));
        assert!(!is_valid_scid("foo/bar"));
        assert!(!is_valid_scid("foo:bar"));
        assert!(!is_valid_scid("../etc/passwd"));
    }

    #[test]
    fn extract_scid_from_did_pulls_last_component() {
        assert_eq!(
            extract_scid_from_did("did:webvh:vtc.example.com:abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            extract_scid_from_did("did:webvh:vtc.example.com:v1:abc123").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn extract_scid_from_did_returns_none_for_non_webvh() {
        assert!(extract_scid_from_did("did:key:z6Mk…").is_none());
        assert!(extract_scid_from_did("not a did").is_none());
    }

    #[test]
    fn extract_scid_from_did_returns_none_when_last_component_invalid() {
        assert!(extract_scid_from_did("did:webvh:vtc.example.com:foo/bar").is_none());
    }
}
