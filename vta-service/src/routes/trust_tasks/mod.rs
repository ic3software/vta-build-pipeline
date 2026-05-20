//! `POST /api/trust-tasks` — the VTA-side trust-task dispatcher.
//!
//! Mirrors `affinidi-webvh-service`'s `did-hosting-control` dispatcher
//! (`routes/trust_tasks.rs`) — body shape, error envelope, and routing
//! semantics are byte-equivalent.
//!
//! ## Module layout
//!
//! - [`helpers`]: shared wire-shape helpers (`parse_payload`,
//!   `reject_with`, `success_response`, `app_error_to_reject`, etc.)
//!   used by every slice's handler module. `pub(super)` only.
//! - One module per Phase 3 slice (`auth`, `acl`, `contexts`, `keys`,
//!   `seeds`, `audit`, `discovery`, …). Each module's handler
//!   functions are `pub(super) async fn handle_<op>(state, auth, doc)
//!   -> Response`. The dispatcher's match arms call them.
//! - The cross-crate URI parity harness lives in the test module
//!   below; it asserts every URI declared in `vta-sdk::trust_tasks`
//!   is either dispatched or on the `REST_ROUTED` allowlist.
//!
//! ## Adding a new URI
//!
//! 1. Add the `TASK_*` const to `vta-sdk::trust_tasks` and extend its
//!    `ALL_URIS` array.
//! 2. Add a `handle_*` function in the appropriate slice module
//!    (create a new one if no slice fits).
//! 3. Add a match arm in `dispatch_typed` that calls the handler.
//! 4. Add the URI to the `dispatched` array in
//!    `tests::dispatcher_handles_every_vta_sdk_uri`.
//!
//! ## Body-parse failures emit framework-conformant errors
//!
//! Like the webvh-service dispatcher, we accept the body as
//! `axum::body::Bytes` and parse to `TrustTask<Value>` by hand so a
//! malformed body produces a `trust-task-error/0.1` document (per
//! framework SPEC §8.5) instead of axum's plain-text 400 default.

use axum::extract::State;
use axum::response::Response;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

mod acl;
mod audit;
mod auth;
mod contexts;
mod discovery;
mod helpers;
mod keys;
mod seeds;

use helpers::{body_parse_error_response, method_not_found};

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
/// Each match arm delegates to the slice's `handle_*` function. Phase
/// 3 slices land in their own modules — new slices add a `mod foo;`
/// declaration at the top and a match arm here.
///
/// Unknown URIs fall through to `method_not_found` which returns
/// `unsupported_type` per the framework's status table.
async fn dispatch_typed(state: &AppState, auth: &AuthClaims, doc: TrustTask<Value>) -> Response {
    let type_uri = doc.type_uri.to_string();

    // Note: `passkey-login-{start,finish}/1.0`, `challenge/1.0`,
    // `authenticate/1.0`, and `refresh/1.0` are NOT handled here.
    // They are UNAUTHENTICATED operations served as dedicated REST
    // routes (`/auth/*`) — the user has no session JWT, so they
    // can't pass `AuthClaims` through the dispatcher's extractor.
    // The parity harness's `REST_ROUTED` allowlist tracks them.
    match type_uri.as_str() {
        // ─── Auth slice (authenticated operations) ───────────────────
        vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0 => {
            auth::handle_revoke_session(state, auth, doc).await
        }
        // ─── ACL slice ────────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_ACL_LIST_1_0 => acl::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0 => acl::handle_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_GET_1_0 => acl::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0 => acl::handle_update(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0 => acl::handle_delete(state, auth, doc).await,
        // ─── Contexts slice ──────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0 => {
            contexts::handle_list(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0 => {
            contexts::handle_create(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0 => contexts::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0 => {
            contexts::handle_update(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0 => {
            contexts::handle_update_did(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0 => {
            contexts::handle_preview_delete(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0 => {
            contexts::handle_delete(state, auth, doc).await
        }
        // ─── Keys slice ──────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0 => keys::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0 => keys::handle_create(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_GET_1_0 => keys::handle_get(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0 => keys::handle_rename(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0 => keys::handle_revoke(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0 => keys::handle_sign(state, auth, doc).await,
        // ─── Seeds slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0 => seeds::handle_list(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0 => seeds::handle_rotate(state, auth, doc).await,
        vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0 => {
            seeds::handle_export_mnemonic(state, auth, doc).await
        }
        // ─── Audit slice ─────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_AUDIT_LIST_LOGS_1_0 => {
            audit::handle_list_logs(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0 => {
            audit::handle_get_retention(state, auth, doc).await
        }
        vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0 => {
            audit::handle_update_retention(state, auth, doc).await
        }
        // ─── Discovery ───────────────────────────────────────────────
        vta_sdk::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0 => {
            discovery::handle_capabilities(state, auth, doc).await
        }
        // ─── Unknown / REST-routed ───────────────────────────────────
        //
        // A client mistakenly sending a REST-routed URI through the
        // envelope path gets `unsupported_type` here — correct from
        // the dispatcher's POV; the operation lives elsewhere.
        _ => method_not_found(doc, &type_uri),
    }
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the dispatcher's wire-shape contracts + the
    //! cross-crate URI parity harness. Each arm's actual handler
    //! logic is tested in its owning operations module (or by the
    //! Phase 5 integration suite once full AppState scaffolding is
    //! in place).

    use trust_tasks_rs::TrustTask;

    use super::*;

    #[test]
    fn body_parse_error_wire_shape() {
        let resp = body_parse_error_response("expected `,`");
        // Function returns; full HTTP-shape assertions live in the
        // Phase 5 integration tests once the route is reachable
        // through a real router setup.
        let _ = resp;
    }

    /// Pins the framework's current `TypeUri::from_str` constraint:
    /// the wire-format `type` field MUST use the canonical
    /// `/spec/<slug>/<major.minor>` shape. Flat URIs are rejected.
    ///
    /// If the framework parser relaxes (accepts both), the test fails
    /// on the flat-rejection assert and we know Phase 3 can simplify.
    #[test]
    fn framework_requires_canonical_uri_in_wire_type_field() {
        // Canonical form parses — with HIERARCHICAL slug
        // (`vta/auth/revoke-session`) per SPEC.md slug grammar.
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
    ///    `routes/auth.rs::passkey_login_{start,finish}` and the
    ///    legacy `/auth/{challenge,,refresh}` routes).
    ///
    /// Adding a new URI const to vta-sdk without doing one of these
    /// makes this test fail loudly with the offending URI in the
    /// message.
    #[test]
    fn dispatcher_handles_every_vta_sdk_uri() {
        // URIs the dispatcher's `dispatch_typed` function explicitly
        // matches — keep in lockstep with the match arms above.
        let dispatched: &[&str] = &[
            // Auth (only revoke-session)
            vta_sdk::trust_tasks::TASK_AUTH_REVOKE_SESSION_1_0,
            // ACL
            vta_sdk::trust_tasks::TASK_ACL_LIST_1_0,
            vta_sdk::trust_tasks::TASK_ACL_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_ACL_GET_1_0,
            vta_sdk::trust_tasks::TASK_ACL_UPDATE_1_0,
            vta_sdk::trust_tasks::TASK_ACL_DELETE_1_0,
            // Contexts
            vta_sdk::trust_tasks::TASK_CONTEXTS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_GET_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0,
            vta_sdk::trust_tasks::TASK_CONTEXTS_DELETE_1_0,
            // Keys
            vta_sdk::trust_tasks::TASK_KEYS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_CREATE_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_GET_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_RENAME_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_REVOKE_1_0,
            vta_sdk::trust_tasks::TASK_KEYS_SIGN_1_0,
            // Seeds
            vta_sdk::trust_tasks::TASK_SEEDS_LIST_1_0,
            vta_sdk::trust_tasks::TASK_SEEDS_ROTATE_1_0,
            vta_sdk::trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0,
            // Audit
            vta_sdk::trust_tasks::TASK_AUDIT_LIST_LOGS_1_0,
            vta_sdk::trust_tasks::TASK_AUDIT_GET_RETENTION_1_0,
            vta_sdk::trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0,
            // Discovery
            vta_sdk::trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0,
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
