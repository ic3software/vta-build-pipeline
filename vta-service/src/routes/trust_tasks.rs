//! `POST /api/trust-tasks` — the VTA-side trust-task dispatcher.
//!
//! Mirrors `affinidi-webvh-service`'s `did-hosting-control` dispatcher
//! (`routes/trust_tasks.rs`) — body shape, error envelope, and routing
//! semantics are byte-equivalent. Differences:
//!
//! - VTA's authority is its own DID (read from
//!   `AppState::config.vta_did`), not the host's `server_did`.
//! - Handler registry starts empty in Phase 2 (this PR); Phase 3
//!   slices add their handlers under match arms in `dispatch_typed`.
//! - Session-pubkey binding check matches `vti-common::auth`'s
//!   `session_pubkey_b58btc` claim.
//!
//! ## Body-parse failures emit framework-conformant errors
//!
//! Like the webvh-service dispatcher, we accept the body as
//! `axum::body::Bytes` and parse to `TrustTask<Value>` by hand so a
//! malformed body produces a `trust-task-error/0.1` document (per
//! framework SPEC §8.5) instead of axum's plain-text 400 default.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{ErrorPayload, ErrorResponse, RejectReason, TrustTask, TypeUri};
use uuid::Uuid;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// `POST /api/trust-tasks` handler.
///
/// Bearer-auth'd via [`AuthClaims`]; the caller's DID is the
/// transport-authenticated peer for SPEC.md §4.8.1 precedence inside
/// each typed handler.
///
/// Body is accepted as raw bytes so a parse failure surfaces as a
/// `trust-task-error/0.1` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (the workspace-wide 1 MB cap applies).
pub async fn dispatch_trust_task(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => return Ok(body_parse_error_response(&e.to_string())),
    };

    // 2. Session-pubkey binding pre-check.
    //
    // Once `AuthClaims` carries `session_pubkey_b58btc` (Phase 3 work,
    // mirrors `webvh-service`'s pattern) the dispatcher will enforce
    // that the proof's `verificationMethod` matches the JWT-bound
    // pubkey before any handler runs. Phase 2 scaffold elides this —
    // no passkey-bound sessions exist yet on the VTA side.
    let _ = &auth;

    // 3. Dispatch by type URI.
    let outcome = dispatch_typed(&state, &auth, doc).await;
    Ok(outcome)
}

/// Type-dispatch over the inbound document's `type` URI.
///
/// The Phase-2 scaffold has zero registered handlers. Phase 3 slice
/// PRs add a match arm per registered URI; unknown URIs fall through
/// to a `method_not_found` reject.
///
/// Per webvh-service's pattern: the match arm extracts the typed
/// payload, calls the corresponding `operations::*` function, and
/// constructs a typed response document. For now we just route
/// everything to the unknown-URI path.
async fn dispatch_typed(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    let _ = state;
    let _ = auth;
    let type_uri = doc.type_uri.to_string();

    // Match the inbound URI against the URIs this dispatcher routes.
    //
    // Note: `passkey-login-{start,finish}/1.0` are NOT handled here.
    // They are UNAUTHENTICATED bootstrap operations served as dedicated
    // REST routes at `/auth/passkey-login/{start,finish}` — the user
    // has no session before passkey-login-finish issues a JWT, so they
    // can't pass `AuthClaims`. Same pattern as webvh-service's
    // `/auth/passkey/login/{start,finish}`.
    //
    // Phase 3 slice implementations replace each `not_implemented_yet`
    // arm with a real handler.
    match type_uri.as_str() {
        // ─── Auth slice (post-login operations) ──────────────────────
        vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_1_0
        | vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_1_0
        | vta_sdk::trust_tasks::TASK_AUTH_REFRESH_1_0
        | vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0 => {
            not_implemented_yet(doc, "auth-slice handler — Phase 3.1 work")
        }
        // ─── Unknown (or routed via dedicated REST) ──────────────────
        //
        // The two passkey-login URIs land here on the dispatcher path;
        // operators should hit `/auth/passkey-login/{start,finish}`
        // directly. Returning `unsupported_type` is correct — the
        // dispatcher doesn't handle them.
        _ => method_not_found(doc, &type_uri),
    }
}

/// Build a routed `task_failed` rejection for a URI we know about but
/// haven't implemented yet.
fn not_implemented_yet(doc: TrustTask<Value>, reason: &str) -> Response {
    let reject = RejectReason::TaskFailed {
        reason: reason.to_string(),
        details: None,
    };
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
    error_response(routed)
}

/// Build an `unsupported_type` rejection for an unrecognised type URI.
fn method_not_found(doc: TrustTask<Value>, type_uri: &str) -> Response {
    let reject = RejectReason::UnsupportedType {
        type_uri: type_uri.to_string(),
    };
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
    error_response(routed)
}

/// Wrap a routed `ErrorResponse` in an HTTP response with the right
/// status code per the framework's status table.
fn error_response(err_doc: ErrorResponse) -> Response {
    let status = StatusCode::from_u16(status_for_code(&err_doc.payload.code))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&err_doc).unwrap_or_else(|_| Vec::new());
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Build a `trust-task-error/0.1` document for a body-parse failure.
/// Unrouted (no issuer / recipient) — the framework permits this on
/// malformed-body failures since the producer can correlate on the
/// response `id`.
fn body_parse_error_response(reason: &str) -> Response {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    let type_uri: TypeUri = "https://trusttasks.org/spec/trust-task-error/0.1"
        .parse()
        .expect("framework error Type URI parses");
    let err = ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        type_uri,
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    };
    error_response(err)
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the dispatcher's wire-shape contracts. Each
    //! arm's actual handler logic is tested in its owning operations
    //! module (Phase 3 work).

    use super::*;

    #[test]
    fn body_parse_error_wire_shape() {
        let resp = body_parse_error_response("expected `,`");
        // It compiles + the function returns — full HTTP shape is
        // tested in the integration suite when the route is wired
        // into the router (Phase 2.4).
        let _ = resp;
    }

    #[test]
    fn phase_2_uri_registry_present() {
        // Compile-time check: every URI we route in `dispatch_typed`
        // is declared in `vta-sdk::trust_tasks`. If a URI gets renamed
        // or removed in vta-sdk, this stops compiling.
        let _ = vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_1_0;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_1_0;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REFRESH_1_0;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_1_0;
        let _ = vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0;
    }

    /// Cross-crate URI parity harness (mirrors webvh-service's T9
    /// invariant). Every URI declared in `vta-sdk::trust_tasks` must
    /// either:
    ///
    /// 1. Be handled by `dispatch_typed` in this dispatcher, OR
    /// 2. Be on the `REST_ROUTED` allowlist (bootstrap-y operations
    ///    served by dedicated unauth REST handlers — see
    ///    `routes/auth.rs::passkey_login_{start,finish}`).
    ///
    /// Adding a new URI const to vta-sdk without doing one of these
    /// makes this test fail loudly with the offending URI in the
    /// message.
    #[test]
    fn dispatcher_handles_every_vta_sdk_uri() {
        // URIs the dispatcher's `dispatch_typed` function explicitly
        // matches — keep in lockstep with the match arms above.
        let dispatched: &[&str] = &[
            vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_REFRESH_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0,
        ];

        // URIs deliberately routed via dedicated unauth REST endpoints
        // (not the authenticated /api/trust-tasks dispatcher).
        // Bootstrap operations the user invokes BEFORE they have a session.
        let rest_routed: &[&str] = &[
            vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0,
        ];

        for declared in vta_sdk::trust_tasks::ALL_URIS {
            assert!(
                dispatched.contains(declared) || rest_routed.contains(declared),
                "vta-sdk declares URI `{declared}` but it is neither dispatched nor on the \
                 REST_ROUTED allowlist — wire it into `dispatch_typed` or add it to one of \
                 the lists above"
            );
        }
    }
}
