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
use base64::Engine as _;
use serde_json::Value;
use trust_tasks_https::status_for_code;
use trust_tasks_rs::{ErrorPayload, ErrorResponse, RejectReason, TrustTask, TypeUri};
use uuid::Uuid;
use vta_sdk::protocols::acl_management::create::CreateAclBody;
use vta_sdk::protocols::acl_management::delete::DeleteAclBody;
use vta_sdk::protocols::acl_management::get::GetAclBody;
use vta_sdk::protocols::acl_management::list::ListAclBody;
use vta_sdk::protocols::acl_management::update::UpdateAclBody;
use vta_sdk::protocols::auth::{RevokeSessionRequest, RevokeSessionResponse};
use vta_sdk::protocols::context_management::create::CreateContextBody;
use vta_sdk::protocols::context_management::delete::{DeleteContextBody, DeleteContextPreviewBody};
use vta_sdk::protocols::context_management::get::GetContextBody;
use vta_sdk::protocols::context_management::list::ListContextsBody;
use vta_sdk::protocols::context_management::update::UpdateContextBody;
use vta_sdk::protocols::context_management::update_did::UpdateContextDidBody;
use vta_sdk::protocols::key_management::create::CreateKeyBody;
use vta_sdk::protocols::key_management::get::GetKeyBody;
use vta_sdk::protocols::key_management::list::ListKeysBody;
use vta_sdk::protocols::key_management::rename::RenameKeyBody;
use vta_sdk::protocols::key_management::revoke::RevokeKeyBody;
use vta_sdk::protocols::key_management::secret::GetKeySecretBody;
use vta_sdk::protocols::key_management::sign::SignRequestBody;
use vta_sdk::protocols::seed_management::list::ListSeedsBody;
use vta_sdk::protocols::seed_management::rotate::RotateSeedBody;

use crate::acl::Role;
use crate::audit::audit;
use crate::auth::AuthClaims;
use crate::auth::session::{delete_session, get_session};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

/// Transport label passed to operations for audit-log discrimination
/// between the legacy REST path (`"rest"`) and the new trust-task
/// envelope (`"trust-task"`).
const TRANSPORT_TRUST_TASK: &str = "trust-task";

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
        // ─── Auth slice (authenticated operations) ───────────────────
        //
        // Only `revoke-session/1.0` reaches this dispatcher because
        // challenge/authenticate/refresh are pre-authentication and
        // can't pass AuthClaims. They live on dedicated REST routes
        // (see REST_ROUTED in the parity harness below).
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0 => {
            handle_revoke_session(state, auth, doc).await
        }
        // ─── ACL slice ────────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_ACL_LIST_1_0 => handle_acl_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0 => handle_acl_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_GET_1_0 => handle_acl_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0 => handle_acl_update(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0 => handle_acl_delete(state, auth, doc).await,
        // ─── Contexts slice ──────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0 => {
            handle_contexts_list(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0 => {
            handle_contexts_create(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0 => handle_contexts_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0 => {
            handle_contexts_update(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0 => {
            handle_contexts_update_did(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0 => {
            handle_contexts_preview_delete(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0 => {
            handle_contexts_delete(state, auth, doc).await
        }
        // ─── Keys slice ──────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0 => handle_keys_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0 => handle_keys_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_GET_1_0 => handle_keys_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0 => handle_keys_rename(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0 => handle_keys_revoke(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0 => handle_keys_sign(state, auth, doc).await,
        // ─── Seeds slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0 => handle_seeds_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0 => handle_seeds_rotate(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 => {
            handle_seeds_export_mnemonic(state, auth, doc).await
        }
        // ─── Unknown / REST-routed ───────────────────────────────────
        //
        // Pre-auth URIs (passkey-login-{start,finish}, challenge,
        // authenticate, refresh) hit dedicated REST endpoints, not
        // the dispatcher. A client mistakenly sending them through
        // the envelope path gets `unsupported_type` here — which is
        // correct from the dispatcher's POV.
        _ => method_not_found(doc, &type_uri),
    }
}

/// Handler for `spec/vta/auth/revoke-session/1.0`.
///
/// Parses the request payload, looks up the session, authorises the
/// caller (session owner OR `Role::Admin`), deletes the session, and
/// returns a `#response`-typed success document with an empty body.
///
/// Mirrors `routes::auth::revoke_session` (the legacy
/// `DELETE /auth/sessions/{session_id}` REST handler) — same audit
/// event key (`session.revoke`), same authorisation rule.
async fn handle_revoke_session(
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
    tracing::info!(caller = %auth.did, session_id = %req.session_id, "session revoked via trust-task");

    // 6. Build the success response document.
    success_response(&doc, RevokeSessionResponse::default())
}

// ─── ACL slice handlers ──────────────────────────────────────────────────

/// Handler for `spec/vta/acl/list/1.0`.
async fn handle_acl_list(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: ListAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::list_acl(
        &state.acl_ks,
        auth,
        req.context.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/create/1.0`.
async fn handle_acl_create(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let role = match Role::parse(&req.role) {
        Ok(r) => r,
        Err(_) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid role: {}", req.role),
                },
            );
        }
    };
    match operations::acl::create_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &req.did,
        role,
        req.label,
        req.allowed_contexts,
        req.expires_at,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/get/1.0`.
async fn handle_acl_get(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: GetAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::get_acl(&state.acl_ks, auth, &req.did, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/update/1.0`. Admin-only — matches the
/// legacy REST `PATCH /acl/{did}` policy.
async fn handle_acl_update(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let role = match req.role.as_deref() {
        Some(r) => match Role::parse(r) {
            Ok(parsed) => Some(parsed),
            Err(_) => {
                return reject_with(
                    &doc,
                    RejectReason::MalformedRequest {
                        reason: format!("invalid role: {r}"),
                    },
                );
            }
        },
        None => None,
    };
    match operations::acl::update_acl(
        &state.acl_ks,
        &state.audit_ks,
        &state.contexts_ks,
        auth,
        &req.did,
        operations::acl::UpdateAclParams {
            role,
            label: req.label,
            allowed_contexts: req.allowed_contexts,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/acl/delete/1.0`.
async fn handle_acl_delete(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_manage() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeleteAclBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::acl::delete_acl(
        &state.acl_ks,
        &state.audit_ks,
        auth,
        &req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Contexts slice handlers ─────────────────────────────────────────────

/// Handler for `spec/vta/contexts/list/1.0`.
async fn handle_contexts_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let _req: ListContextsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::list_contexts(&state.contexts_ks, auth, TRANSPORT_TRUST_TASK).await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/create/1.0`. Super-admin only.
async fn handle_contexts_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::create_context(
        &state.contexts_ks,
        auth,
        &req.id,
        req.name,
        req.description,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/get/1.0`.
async fn handle_contexts_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    let req: GetContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::get_context_op(
        &state.contexts_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update/1.0`. Super-admin only.
async fn handle_contexts_update(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context(
        &state.contexts_ks,
        auth,
        &req.id,
        operations::contexts::UpdateContextParams {
            name: req.name,
            did: req.did,
            description: req.description,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/update-did/1.0`. Admin only.
async fn handle_contexts_update_did(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: UpdateContextDidBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::update_context_did(
        &state.contexts_ks,
        auth,
        &req.id,
        req.did,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/preview-delete/1.0`. Super-admin only.
async fn handle_contexts_preview_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeleteContextPreviewBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::contexts::preview_delete_context(
        &state.contexts_ks,
        &state.keys_ks,
        &state.acl_ks,
        &state.did_templates_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        auth,
        &req.id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/contexts/delete/1.0`. Super-admin only.
async fn handle_contexts_delete(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_super_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: DeleteContextBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let ks = operations::Keyspaces::from_app_state(state);
    match operations::contexts::delete_context(&ks, auth, &req.id, req.force, TRANSPORT_TRUST_TASK)
        .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Keys slice handlers ─────────────────────────────────────────────────

/// Handler for `spec/vta/keys/list/1.0`.
async fn handle_keys_list(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    let req: ListKeysBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::list_keys(
        &state.keys_ks,
        auth,
        operations::keys::ListKeysParams {
            offset: req.offset,
            limit: req.limit,
            status: req.status,
            context_id: req.context_id,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/create/1.0`. Admin only.
async fn handle_keys_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: CreateKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &state.audit_ks,
        auth,
        operations::keys::CreateKeyParams {
            key_type: req.key_type,
            derivation_path: Some(req.derivation_path),
            // Trust-task envelope auto-generates key_id from derivation
            // path; explicit-key_id specification stays on the legacy
            // REST path until Phase 3 hardening extends CreateKeyBody.
            key_id: None,
            mnemonic: req.mnemonic,
            label: req.label,
            context_id: req.context_id,
        },
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/get/1.0`.
async fn handle_keys_get(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    let req: GetKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::get_key(&state.keys_ks, auth, &req.key_id, TRANSPORT_TRUST_TASK).await {
        Ok(record) => success_response(&doc, record),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/rename/1.0`. Admin only.
async fn handle_keys_rename(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RenameKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::rename_key(
        &state.keys_ks,
        &state.audit_ks,
        auth,
        &req.key_id,
        &req.new_key_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/revoke/1.0`. Admin only.
async fn handle_keys_revoke(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RevokeKeyBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::revoke_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.audit_ks,
        auth,
        &req.key_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/keys/sign/1.0`. Application-or-higher (write).
///
/// Decodes the base64url payload before invoking the signing oracle —
/// matches the legacy REST handler's behaviour. The signature in the
/// response is also base64url-encoded.
async fn handle_keys_sign(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_write() {
        return app_error_to_reject(&doc, e);
    }
    let req: SignRequestBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&req.payload))
    {
        Ok(b) => b,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("invalid base64url payload: {e}"),
                },
            );
        }
    };
    match operations::keys::sign_payload(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        auth,
        &req.key_id,
        &payload_bytes,
        &req.algorithm,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Seeds slice handlers ────────────────────────────────────────────────

/// Handler for `spec/vta/seeds/list/1.0`. Admin only.
async fn handle_seeds_list(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let _req: ListSeedsBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::seeds::list_seeds(&state.keys_ks, TRANSPORT_TRUST_TASK).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/seeds/rotate/1.0`. Admin only.
async fn handle_seeds_rotate(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: RotateSeedBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        &auth.did,
        req.mnemonic.as_deref(),
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Handler for `spec/vta/seeds/export-mnemonic/1.0`. Admin only.
/// One-shot mnemonic export under `MnemonicExportGuard`; the returned
/// payload zeroizes on drop.
async fn handle_seeds_export_mnemonic(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> Response {
    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let req: GetKeySecretBody = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match operations::keys::get_key_secret(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_ks,
        auth,
        &req.key_id,
        TRANSPORT_TRUST_TASK,
    )
    .await
    {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, e),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Parse a trust-task document's `payload` field as the typed body
/// `T`, or return a `MalformedRequest` rejection response.
///
/// Consolidates the per-handler boilerplate where the only thing that
/// changes is the target type.
fn parse_payload<T: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<T, Response> {
    serde_json::from_value::<T>(doc.payload.clone()).map_err(|e| {
        reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload parse: {e}"),
            },
        )
    })
}

/// Map an `AppError` (the operation-layer error type) into a routed
/// trust-task error response with the appropriate framework reject
/// code:
///
/// - `Authentication` / `Unauthorized` / `Forbidden` → `permission_denied`
/// - `Validation` / `TrustTaskMalformed` → `malformed_request`
/// - `NotFound` / `Conflict` → `task_failed`
/// - everything else → `internal_error`
fn app_error_to_reject(doc: &TrustTask<Value>, err: AppError) -> Response {
    let message = err.to_string();
    let reason = match err {
        AppError::Authentication(_) | AppError::Unauthorized(_) | AppError::Forbidden(_) => {
            RejectReason::PermissionDenied { reason: message }
        }
        AppError::Validation(_) | AppError::TrustTaskMalformed(_) => {
            RejectReason::MalformedRequest { reason: message }
        }
        AppError::NotFound(_) | AppError::Conflict(_) => RejectReason::TaskFailed {
            reason: message,
            details: None,
        },
        _ => RejectReason::InternalError { reason: message },
    };
    reject_with(doc, reason)
}

/// Build a routed rejection document for the given reason and wrap it
/// in an HTTP response. The framework computes the status code from
/// the reject's standard code.
fn reject_with(doc: &TrustTask<Value>, reason: RejectReason) -> Response {
    let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reason);
    error_response(routed)
}

/// Build a routed success document with the given payload and wrap
/// it in an HTTP 200 response.
fn success_response<R: serde::Serialize>(doc: &TrustTask<Value>, payload: R) -> Response {
    let response_doc = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
    let body = match serde_json::to_vec(&response_doc) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialise success response doc");
            return reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response serialisation: {e}"),
                },
            );
        }
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Build a routed `task_failed` rejection for a URI we know about but
/// haven't implemented yet. Kept available for Phase 3.2+ slices that
/// will add new handlers — each lands as a `not_implemented_yet`
/// placeholder before being filled in.
#[allow(dead_code)]
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

    /// Pins the framework's current `TypeUri::from_str` constraint:
    /// the wire-format `type` field MUST use the canonical
    /// `/spec/<slug>/<major.minor>` shape. Flat URIs are rejected at
    /// JSON deserialization.
    ///
    /// **Design implication.** The workspace's URI registry in
    /// `vta-sdk::trust_tasks` currently exposes flat URIs (no `/spec/`
    /// segment). Those constants are fine for INTERNAL identifiers /
    /// match arms / HTTP `Trust-Task:` header tags — they're just
    /// string-equal matches. But the WIRE FORMAT in the JSON `type`
    /// field must be canonical. Phase 3 work needs to reconcile this:
    /// either (a) move the registry to canonical form, or (b) keep
    /// flat consts and convert on the wire boundary.
    ///
    /// See `docs/05-design-notes/trust-task-uri-registry.md` for the
    /// pending resolution.
    #[test]
    fn framework_requires_canonical_uri_in_wire_type_field() {
        // Canonical form parses — with HIERARCHICAL slug
        // (`vta/auth/revoke-session`) per SPEC.md slug grammar
        // (`acl/grant`-style nesting is permitted).
        let canonical = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/spec/vta/auth/revoke-session/1.0",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_ok(),
            "canonical URI must parse: {:?}",
            parsed.err()
        );

        // Flat form is rejected.
        let flat = serde_json::json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/vta/auth/revoke-session/1.0",
            "issuer": "did:example:alice",
            "recipient": "did:example:vta",
            "issuedAt": "2026-05-20T00:00:00Z",
            "payload": { "session_id": "sess-1" }
        });
        let bytes = serde_json::to_vec(&flat).unwrap();
        let parsed: Result<TrustTask<Value>, _> = serde_json::from_slice(&bytes);
        assert!(
            parsed.is_err(),
            "flat URI must NOT parse — if this changes, the framework \
             relaxed its parser and Phase 3 design can simplify"
        );
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
            vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0,
            vta_sdk::trust_tasks::TASK_ACL_LIST_1_0,
            vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_ACL_GET_1_0,
            vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0,
            vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_GET_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0,
            vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0,
            vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0,
        ];

        // URIs deliberately routed via dedicated unauth REST endpoints
        // (not the authenticated /api/trust-tasks dispatcher).
        // Pre-authentication operations the user invokes BEFORE they
        // have a session, so they can't pass AuthClaims through the
        // dispatcher's extractor.
        let rest_routed: &[&str] = &[
            vta_sdk::trust_tasks::TASK_AUTH_CHALLENGE_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_AUTHENTICATE_1_0,
            vta_sdk::trust_tasks::TASK_AUTH_REFRESH_1_0,
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
