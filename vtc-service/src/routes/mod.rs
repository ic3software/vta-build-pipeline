mod acl;
mod admin;
mod auth;
mod community;
mod config;
mod health;
pub(crate) mod install;

use axum::Router;
use axum::routing::{delete, get, post};

use vti_common::trust_task::{TrustTask, TrustTaskRouter};

use crate::server::AppState;

/// Build the public router.
///
/// Migrates the pre-MVP route table under `/v1/` and attaches a
/// Trust-Task header check to every endpoint per spec §9.4. The
/// existing handlers are unchanged in behaviour — only the wire
/// surface moves. Trust Task IDs use a `*/legacy/*` namespace
/// because these endpoints will be re-shaped during M0.5+ to align
/// with the install + passkey + admin flows; the placeholder IDs
/// give the wire surface a stable identifier from day one (soft
/// gate from spec §9.4 / plan M0.1.1).
///
/// `/health` is the **single** Trust-Task-exempt endpoint — kept at
/// the root path for trivial monitoring integration.
pub fn router() -> Router<AppState> {
    let auth_challenge =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/legacy/challenge/1.0")
            .expect("static Trust-Task URL");
    let auth_authenticate =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/legacy/authenticate/1.0")
            .expect("static Trust-Task URL");
    let auth_refresh = TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/legacy/refresh/1.0")
        .expect("static Trust-Task URL");
    let auth_sessions_manage =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/manage/1.0")
            .expect("static Trust-Task URL");
    let auth_sessions_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/revoke/1.0")
            .expect("static Trust-Task URL");
    let config_manage =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0")
            .expect("static Trust-Task URL");
    let acl_manage = TrustTask::new("https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0")
        .expect("static Trust-Task URL");
    let acl_entry = TrustTask::new("https://trusttasks.org/openvtc/vtc/acl/legacy/entry/1.0")
        .expect("static Trust-Task URL");
    let community_profile =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0")
            .expect("static Trust-Task URL");
    let admin_config = TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0")
        .expect("static Trust-Task URL");
    let install_claim_start =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/start/1.0")
            .expect("static Trust-Task URL");
    let install_claim_finish =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0")
            .expect("static Trust-Task URL");

    TrustTaskRouter::<AppState>::new()
        .route_exempt("/health", get(health::health))
        // Auth routes
        .route_with_task("/v1/auth/challenge", post(auth::challenge), auth_challenge)
        .route_with_task("/v1/auth/", post(auth::authenticate), auth_authenticate)
        .route_with_task("/v1/auth/refresh", post(auth::refresh), auth_refresh)
        .route_with_task(
            "/v1/auth/sessions",
            get(auth::session_list).delete(auth::revoke_sessions_by_did),
            auth_sessions_manage,
        )
        .route_with_task(
            "/v1/auth/sessions/{session_id}",
            delete(auth::revoke_session),
            auth_sessions_revoke,
        )
        // Config
        .route_with_task(
            "/v1/config",
            get(config::get_config).patch(config::update_config),
            config_manage,
        )
        // ACL
        .route_with_task(
            "/v1/acl",
            get(acl::list_acl).post(acl::create_acl),
            acl_manage,
        )
        .route_with_task(
            "/v1/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
            acl_entry,
        )
        // Community profile (GET + PUT share one Trust Task today;
        // a spec-aligned split into community/profile/show/1.0 +
        // community/profile/update/1.0 lands when TrustTaskRouter
        // gains per-method task selectors in Phase 1+).
        .route_with_task(
            "/v1/community/profile",
            get(community::profile::get_profile).put(community::profile::put_profile),
            community_profile,
        )
        // Admin config (M0.8 — GET + PATCH share one task; will
        // split into admin/config/show/1.0 + patch/1.0 when
        // TrustTaskRouter gains per-method selectors).
        .route_with_task(
            "/v1/admin/config",
            get(admin::config::get_config).patch(admin::config::patch_config),
            admin_config,
        )
        // Install claim (M0.5.2) — distinct Trust Tasks because the
        // two phases of the WebAuthn ceremony have different
        // semantics. Both are POST-only.
        .route_with_task(
            "/v1/install/claim/start",
            post(install::claim_start),
            install_claim_start,
        )
        .route_with_task(
            "/v1/install/claim/finish",
            post(install::claim_finish),
            install_claim_finish,
        )
        .into_router()
}
