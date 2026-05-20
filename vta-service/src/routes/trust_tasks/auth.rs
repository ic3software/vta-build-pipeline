//! Auth-slice trust-task handlers.
//!
//! Only `revoke-session/1.0` is dispatched here. Pre-authentication
//! operations (challenge, authenticate, refresh, passkey-login) cannot
//! pass `AuthClaims` and so live on dedicated unauth REST routes in
//! `routes::auth` — see the `REST_ROUTED` allowlist in the parity
//! harness for the full list.

use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::protocols::auth::{RevokeSessionRequest, RevokeSessionResponse};

use crate::acl::Role;
use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::auth::session::{delete_session, get_session};
use crate::server::AppState;

use super::helpers::{reject_with, success_response};

/// Handler for `spec/vta/auth/revoke-session/1.0`.
///
/// Parses the request payload, looks up the session, authorises the
/// caller (session owner OR `Role::Admin`), deletes the session, and
/// returns a `#response`-typed success document with an empty body.
///
/// Mirrors `routes::auth::revoke_session` (the legacy
/// `DELETE /auth/sessions/{session_id}` REST handler) — same audit
/// event key (`session.revoke`), same authorisation rule.
pub(super) async fn handle_revoke_session(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    // 1. Parse the payload.
    let req: RevokeSessionRequest = match serde_json::from_value(doc.payload.clone()) {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("revoke-session payload parse: {e}"),
                },
            );
        }
    };

    // 2. Look up the session.
    let session = match get_session(&state.sessions_ks, &req.session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return reject_with(
                &doc,
                RejectReason::TaskFailed {
                    reason: format!("session not found: {}", req.session_id),
                    details: None,
                },
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed in revoke-session");
            return reject_with(
                &doc,
                RejectReason::InternalError {
                    reason: format!("session lookup: {e}"),
                },
            );
        }
    };

    // 3. Authorise: caller owns the session OR has Role::Admin. Same
    //    rule as the legacy REST handler.
    if session.did != auth.did && auth.role != Role::Admin {
        tracing::warn!(
            caller = %auth.did,
            session_did = %session.did,
            session_id = %req.session_id,
            "revoke-session rejected: caller is not owner or admin"
        );
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: "cannot revoke another user's session".to_string(),
            },
        );
    }

    // 4. Delete.
    if let Err(e) = delete_session(&state.sessions_ks, &req.session_id).await {
        tracing::error!(error = %e, session_id = %req.session_id, "session delete failed");
        return reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("session delete: {e}"),
            },
        );
    }

    // 5. Audit.
    audit!(
        "session.revoke",
        actor = &auth.did,
        resource = &req.session_id,
        outcome = "success"
    );
    tracing::info!(
        caller = %auth.did,
        session_id = %req.session_id,
        "session revoked via trust-task"
    );

    // 6. Build the success response document.
    success_response(&doc, RevokeSessionResponse::default())
}
