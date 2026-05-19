mod acl;
#[cfg(feature = "tee")]
mod attestation;
mod audit;
mod auth;
mod backup;
mod bootstrap;
mod cache;
mod capabilities;
mod config;
mod contexts;
mod did_templates;
#[cfg(feature = "webvh")]
mod did_webvh;
mod health;
pub mod keys;
#[cfg(feature = "webvh")]
mod passkey_vms;
#[cfg(feature = "webvh")]
mod protocol;
mod vta;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use crate::server::AppState;

/// Maximum request body size (1 MB). Protects against memory exhaustion,
/// especially critical in TEE deployments where enclave memory is limited.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Tighter body cap for unauthenticated endpoints that drive expensive
/// crypto on attacker-controlled bytes (DIDComm `pack`/`unpack`,
/// signature verify, sealed-transfer parse). Sized to fit a generous
/// JWE / sealed-transfer payload but reject 1 MB blob floods that the
/// rate limiter alone cannot starve out.
const UNAUTH_BODY_SIZE: usize = 64 * 1024;

/// Per-client-IP rate-limit budget for unauthenticated endpoints.
///
/// 5 req/sec with a 10-request burst — loose enough that a legit operator
/// running provisioning scripts doesn't hit it, tight enough that a
/// sustained flood from one IP is rejected with 429. These endpoints do
/// real crypto work (attestation, HPKE seal, Ed25519 verify) so throttling
/// them protects VTA CPU regardless of any reverse proxy upstream.
const UNAUTH_RPS: u64 = 5;
const UNAUTH_BURST: u32 = 10;

/// Health-check route — served without the request/response trace layer.
/// Minimal response only; detailed info requires authentication.
pub fn health_router() -> Router<AppState> {
    Router::new().route("/health", get(health::health))
}

pub fn router() -> Router<AppState> {
    // Per-IP rate-limit layer applied to every unauthenticated endpoint.
    // Authenticated routes stay unthrottled — JWT auth is itself a gate,
    // and legitimate operator traffic against the management plane
    // shouldn't be rate-limited.
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(UNAUTH_RPS)
            .burst_size(UNAUTH_BURST)
            .key_extractor(tower_governor::key_extractor::SmartIpKeyExtractor)
            .finish()
            .expect("governor config values are static and non-zero"),
    );
    let unauth_layer = GovernorLayer::new(governor_config);

    let unauth = Router::new()
        // Sealed-transfer bootstrap (token or attestation gated inside)
        .route("/bootstrap/request", post(bootstrap::request))
        // Auth flow entry points
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        // Tighter body cap on unauth endpoints — see UNAUTH_BODY_SIZE.
        // Layered on this sub-router (not the global one) so authenticated
        // endpoints keep the regular MAX_BODY_SIZE budget needed for backup
        // import etc.
        .layer(DefaultBodyLimit::max(UNAUTH_BODY_SIZE));
    #[cfg(feature = "webvh")]
    let unauth = unauth
        // Public did.jsonl retrieval — matches webvh's world-readable
        // log model, security is cryptographic not access-gated. Rate-
        // limited via the same governor layer as the other unauth
        // endpoints.
        .route("/did/{did}/log", get(did_webvh::get_did_log_public_handler));
    let unauth = unauth.layer(unauth_layer);

    // Authenticated provision-integration (context-admin gated). Kept
    // separate from `unauth` so the rate-limiter doesn't apply — the
    // endpoint already hard-gates on `AdminAuth`.
    #[cfg(feature = "webvh")]
    let auth_provision = Router::new().route(
        "/bootstrap/provision-integration",
        post(bootstrap::provision_integration),
    );

    let router = Router::new().merge(unauth);
    #[cfg(feature = "webvh")]
    let router = router.merge(auth_provision);

    let router = router
        .route(
            "/auth/sessions",
            get(auth::session_list).delete(auth::revoke_sessions_by_did),
        )
        .route("/auth/sessions/{session_id}", delete(auth::revoke_session))
        .route(
            "/config",
            get(config::get_config).patch(config::update_config),
        )
        .route("/keys", get(keys::list_keys).post(keys::create_key))
        .route(
            "/keys/{key_id}",
            get(keys::get_key)
                .delete(keys::invalidate_key)
                .patch(keys::rename_key),
        )
        .route("/keys/{key_id}/secret", get(keys::get_key_secret))
        .route("/keys/{key_id}/sign", post(keys::sign_with_key))
        .route("/keys/import/wrapping-key", get(keys::get_wrapping_key))
        .route("/keys/import", post(keys::import_key))
        .route("/keys/seeds", get(keys::list_seeds))
        .route("/keys/seeds/rotate", post(keys::rotate_seed))
        // Context routes
        .route(
            "/contexts",
            get(contexts::list_contexts_handler).post(contexts::create_context_handler),
        )
        .route(
            "/contexts/{id}",
            get(contexts::get_context_handler)
                .patch(contexts::update_context_handler)
                .delete(contexts::delete_context_handler),
        )
        .route(
            "/contexts/{id}/did",
            put(contexts::update_context_did_handler),
        )
        .route(
            "/contexts/{id}/delete-preview",
            get(contexts::preview_delete_context_handler),
        )
        // DID template routes (global scope — Phase 2)
        .route(
            "/did-templates",
            get(did_templates::list_handler).post(did_templates::create_handler),
        )
        .route(
            "/did-templates/{name}",
            get(did_templates::get_handler)
                .put(did_templates::update_handler)
                .delete(did_templates::delete_handler),
        )
        .route(
            "/did-templates/{name}/render",
            post(did_templates::render_handler),
        )
        // DID templates — context scope (Phase 3)
        .route(
            "/contexts/{id}/did-templates",
            get(did_templates::list_context_handler).post(did_templates::create_context_handler),
        )
        .route(
            "/contexts/{id}/did-templates/{name}",
            get(did_templates::get_context_handler)
                .put(did_templates::update_context_handler)
                .delete(did_templates::delete_context_handler),
        )
        .route(
            "/contexts/{id}/did-templates/{name}/render",
            post(did_templates::render_context_handler),
        )
        // ACL routes (flattened for consistency)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
        )
        // Audit log routes
        .route("/audit/logs", get(audit::list_audit_logs))
        .route(
            "/audit/retention",
            get(audit::get_retention).patch(audit::update_retention),
        )
        // Cache routes (token caching / key-value store)
        .route(
            "/cache/{key}",
            get(cache::get_cached)
                .put(cache::put_cached)
                .delete(cache::delete_cached),
        );

    // TEE attestation routes (feature-gated)
    #[cfg(feature = "tee")]
    let router = router
        .route("/attestation/status", get(attestation::status))
        .route(
            "/attestation/report",
            get(attestation::cached_report).post(attestation::generate_report),
        )
        // Mnemonic export (super admin only, time-limited)
        .route(
            "/attestation/mnemonic",
            get(attestation::mnemonic_status).post(attestation::mnemonic_export),
        )
        // Auto-generated DID log (unauthenticated — public data)
        .route("/attestation/did-log", get(attestation::did_log));
    // `GET /attestation/admin-credential` retired in Phase 3 —
    // sealed-bootstrap Mode B replaces it via `POST /bootstrap/request`.

    // Protocol management routes (DIDComm enable/disable/migrate;
    // spec docs/05-design-notes/didcomm-protocol-management.md).
    // Plus the symmetric REST routes (spec
    // docs/05-design-notes/runtime-service-management.md §3.4).
    #[cfg(feature = "webvh")]
    let router = router
        .route(
            "/services/didcomm/enable",
            post(protocol::enable_didcomm_handler),
        )
        .route(
            "/services/didcomm/disable",
            post(protocol::disable_didcomm_handler),
        )
        .route("/services/rest/enable", post(protocol::enable_rest_handler))
        .route("/services/rest/update", post(protocol::update_rest_handler))
        .route(
            "/services/rest/disable",
            post(protocol::disable_rest_handler),
        )
        .route(
            "/services/rest/rollback",
            post(protocol::rollback_rest_handler),
        )
        .route("/services", get(protocol::list_services_handler))
        .route("/services/didcomm/drain", get(protocol::list_drain_handler))
        .route(
            "/services/didcomm/update",
            post(protocol::update_didcomm_handler),
        )
        .route(
            "/services/didcomm/rollback",
            post(protocol::rollback_didcomm_handler),
        )
        .route(
            "/mediators/drain/cancel",
            post(protocol::drain_cancel_handler),
        )
        .route("/mediators/report", get(protocol::mediator_report_handler));

    // WebVH routes (feature-gated)
    #[cfg(feature = "webvh")]
    let router = router
        .route(
            "/webvh/servers",
            get(did_webvh::list_servers_handler).post(did_webvh::add_server_handler),
        )
        .route(
            "/webvh/servers/{id}",
            axum::routing::patch(did_webvh::update_server_handler)
                .delete(did_webvh::remove_server_handler),
        )
        .route(
            "/webvh/dids",
            get(did_webvh::list_dids_handler).post(did_webvh::create_did_handler),
        )
        .route(
            "/webvh/dids/{did}",
            get(did_webvh::get_did_handler).delete(did_webvh::delete_did_handler),
        )
        .route("/webvh/dids/{did}/log", get(did_webvh::get_did_log_handler))
        .route(
            "/webvh/dids/{did}/register-server",
            post(did_webvh::register_did_with_server_handler),
        )
        .route(
            "/contexts/{ctx_id}/dids/{scid}/update",
            post(did_webvh::update_did_handler),
        )
        .route(
            "/contexts/{ctx_id}/dids/{scid}/rotate-keys",
            post(did_webvh::rotate_did_keys_handler),
        )
        // Passkey-as-verificationMethod enrolment. See
        // `docs/02-vta/passkey-verification-methods.md` (forthcoming).
        // First-time enrolment expects a short-lived enrolment-scope
        // JWT minted by `pnm passkey-enroll-token`; subsequent calls
        // use a passkey-derived session JWT.
        .route(
            "/did/verification-methods/passkey/challenge",
            post(passkey_vms::enroll_challenge_handler),
        )
        .route(
            "/did/verification-methods/passkey",
            post(passkey_vms::enroll_submit_handler).get(passkey_vms::list_passkeys_handler),
        )
        .route(
            "/did/verification-methods/passkey/{fragment}",
            delete(passkey_vms::revoke_passkey_handler),
        );

    // VTA management routes
    let router = router
        .route("/vta/restart", post(vta::restart))
        .route("/metrics", get(vta::metrics))
        .route("/backup/export", post(backup::export))
        .route("/backup/import", post(backup::import));

    // Authenticated health details and capabilities
    let router = router
        .route("/health/details", get(health::health_details))
        .route("/capabilities", get(capabilities::capabilities));

    // Apply global request body size limit to protect enclave memory
    router.layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
}
