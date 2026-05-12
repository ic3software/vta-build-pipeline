mod acl;
mod admin;
mod auth;
mod community;
mod config;
pub(crate) mod did_log;
mod health;
pub(crate) mod install;
pub(crate) mod join_requests;
pub(crate) mod members;
pub(crate) mod policies;
pub(crate) mod status_lists;

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
    let admin_config_reload =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/reload/1.0")
            .expect("static Trust-Task URL");
    let admin_config_restart =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0")
            .expect("static Trust-Task URL");
    let admin_config_export =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/export/1.0")
            .expect("static Trust-Task URL");
    let admin_config_import =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/config/import/1.0")
            .expect("static Trust-Task URL");
    let install_claim_start =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/start/1.0")
            .expect("static Trust-Task URL");
    let install_claim_finish =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0")
            .expect("static Trust-Task URL");
    let admin_bootstrap = TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/bootstrap/1.0")
        .expect("static Trust-Task URL");
    let admin_passkeys_list =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0")
            .expect("static Trust-Task URL");
    let admin_passkeys_register =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0")
            .expect("static Trust-Task URL");
    let admin_passkeys_revoke =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/admin/passkeys/revoke/1.0")
            .expect("static Trust-Task URL");
    let members_list = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/list/1.0")
        .expect("static Trust-Task URL");
    let members_show = TrustTask::new("https://trusttasks.org/openvtc/vtc/members/show/1.0")
        .expect("static Trust-Task URL");
    // `members_update` (`members/update/1.0`) shares the
    // `members/{did}` mount with `show` for now — TrustTaskRouter
    // doesn't support per-method Trust-Task selectors yet
    // (same Phase-0 workaround `admin/config` + `community/profile`
    // use). When that lands, split show + update.
    let members_promote =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/promote-to-admin/1.0")
            .expect("static Trust-Task URL");
    let members_self_remove =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/members/self-remove/1.0")
            .expect("static Trust-Task URL");
    // `members_admin_remove` (`members/admin-remove/1.0`) shares
    // the `members/{did}` mount with show + update for now —
    // TrustTaskRouter doesn't support per-method Trust-Task
    // selectors yet. The standalone task exists on disk +
    // index.json so the soft-gate surface stays complete.
    // POST + GET share `/v1/join-requests`. The `join-requests/list/1.0`
    // Trust Task exists in index.json + on-disk spec/schema so the
    // soft-gate surface stays complete; the wire enforcement here
    // collapses to `join-requests/submit/1.0` until TrustTaskRouter
    // gains per-method selectors (same workaround community/profile,
    // admin/config, members/{did} use).
    let join_submit = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0")
        .expect("static Trust-Task URL");
    let join_show = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/show/1.0")
        .expect("static Trust-Task URL");
    let join_approve =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/approve/1.0")
            .expect("static Trust-Task URL");
    let join_reject = TrustTask::new("https://trusttasks.org/openvtc/vtc/join-requests/reject/1.0")
        .expect("static Trust-Task URL");
    // Policies (Phase 2 M2.3). Three distinct Trust Tasks for the
    // three POST endpoints — upload, activate, test — so SIEM
    // filters + soft-gate consumers can target each precisely.
    let policies_upload = TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/upload/1.0")
        .expect("static Trust-Task URL");
    let policies_activate =
        TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/activate/1.0")
            .expect("static Trust-Task URL");
    let policies_test = TrustTask::new("https://trusttasks.org/openvtc/vtc/policies/test/1.0")
        .expect("static Trust-Task URL");
    // Read endpoints (M2.4). GET /v1/policies and
    // GET /v1/policies/{id} share their mounts with the POST
    // /v1/policies upload and POST /v1/policies/{id}/activate
    // endpoints respectively — TrustTaskRouter doesn't yet support
    // per-method selectors (same workaround community/profile,
    // admin/config, members/{did}, join-requests use). The
    // standalone `policies/list/1.0` + `policies/show/1.0` Trust
    // Tasks exist on disk + in index.json so the soft-gate
    // surface stays complete; the wire enforcement collapses to
    // the POST task on the shared mount.

    TrustTaskRouter::<AppState>::new()
        .route_exempt("/health", get(health::health))
        // `did:webvh` log publication (Trust-Task-exempt — DID
        // resolvers don't carry our extension header). The VTC is
        // not a general-purpose did:webvh host: the handler matches
        // the URL `scid` against the VTC's own DID and 404s on any
        // other request. See `tasks/vtc-mvp/vta-driven-keys.md` §10.
        .route_exempt("/v1/{scid}/did.jsonl", get(did_log::did_log))
        // BitstringStatusList publication (M2.11). Trust-Task-
        // exempt — external verifiers don't carry our extension
        // header (same rationale as `did.jsonl`).
        .route_exempt("/v1/status-lists/{purpose}", get(status_lists::show))
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
        // Reload + restart (M0.8.3). Reload applies hot-reloadable
        // settings in-place; restart requires a supervisor (412
        // `SupervisorRequired` otherwise).
        .route_with_task(
            "/v1/admin/config/reload",
            post(admin::config::reload_config),
            admin_config_reload,
        )
        .route_with_task(
            "/v1/admin/config/restart",
            post(admin::config::restart_config),
            admin_config_restart,
        )
        // Export / import (M0.8.4). Export returns the portable
        // (db-layer overrides + community profile) JSON; import runs
        // diff-and-confirm via `?confirm=true|false`.
        .route_with_task(
            "/v1/admin/config/export",
            post(admin::config::export_config),
            admin_config_export,
        )
        .route_with_task(
            "/v1/admin/config/import",
            post(admin::config::import_config),
            admin_config_import,
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
        // Admin bootstrap (M0.6.2) — closes the install carve-out
        // and writes the first admin ACL entry. Unauthenticated
        // because the setup-session JWT IS the auth credential.
        .route_with_task(
            "/v1/admin/bootstrap",
            post(admin::bootstrap::bootstrap),
            admin_bootstrap,
        )
        // Admin passkey management (M0.6.3). Step-up UV is enforced
        // via the two-phase ceremony: `register/start` and
        // `revoke/start` issue a UV challenge bound to an existing
        // passkey; `register/finish` and `revoke/finish` reject if
        // the UV assertion doesn't verify.
        .route_with_task(
            "/v1/admin/passkeys",
            get(admin::passkeys::list),
            admin_passkeys_list,
        )
        .route_with_task(
            "/v1/admin/passkeys/register/start",
            post(admin::passkeys::register_start),
            admin_passkeys_register.clone(),
        )
        .route_with_task(
            "/v1/admin/passkeys/register/finish",
            post(admin::passkeys::register_finish),
            admin_passkeys_register,
        )
        .route_with_task(
            "/v1/admin/passkeys/revoke/start",
            post(admin::passkeys::revoke_start),
            admin_passkeys_revoke.clone(),
        )
        .route_with_task(
            "/v1/admin/passkeys/revoke/finish",
            post(admin::passkeys::revoke_finish),
            admin_passkeys_revoke,
        )
        // Members (Phase 1 M1.4–M1.6).
        .route_with_task(
            "/v1/members",
            get(members::read::list_members),
            members_list,
        )
        // `/v1/members/me` for self-remove (M1.11.1). Must be
        // declared BEFORE the `/v1/members/{did}` mount otherwise
        // axum's path-trie picks the parameterised route first
        // and routes "me" as a literal DID.
        .route_with_task(
            "/v1/members/me",
            axum::routing::delete(members::remove::self_remove),
            members_self_remove,
        )
        .route_with_task(
            "/v1/members/{did}",
            get(members::read::show_member)
                .patch(members::update::update_member)
                .delete(members::remove::admin_remove),
            // GET + PATCH + DELETE share `members/show/1.0` at the
            // router layer pending per-method selectors; the
            // standalone `members/update/1.0` and
            // `members/admin-remove/1.0` Trust Tasks exist on
            // disk + in index.json so the soft-gate surface stays
            // complete.
            members_show,
        )
        .route_with_task(
            "/v1/members/{did}/promote-to-admin/start",
            post(members::promote::promote_start),
            members_promote.clone(),
        )
        .route_with_task(
            "/v1/members/{did}/promote-to-admin/finish",
            post(members::promote::promote_finish),
            members_promote,
        )
        // Join requests (Phase 1 M1.7–M1.10).
        .route_with_task(
            "/v1/join-requests",
            // Submit (unauth) + admin list share the mount; the
            // submit Trust Task `join-requests/submit/1.0` covers
            // both methods here. Per-method selectors land
            // alongside the same router work admin/config awaits.
            post(join_requests::submit::submit).get(join_requests::read::list_join_requests),
            join_submit,
        )
        .route_with_task(
            "/v1/join-requests/{id}",
            get(join_requests::read::show_join_request),
            join_show,
        )
        .route_with_task(
            "/v1/join-requests/{id}/approve",
            post(join_requests::decide::approve),
            join_approve,
        )
        .route_with_task(
            "/v1/join-requests/{id}/reject",
            post(join_requests::decide::reject),
            join_reject,
        )
        // Policies (Phase 2 M2.3). Three POST endpoints, three
        // Trust Tasks. `upload` mints + persists; `activate` flips
        // the per-purpose active pointer; `test` evaluates a stored
        // policy without mutating state.
        .route_with_task(
            "/v1/policies",
            get(policies::read::list_policies).post(policies::admin::upload),
            policies_upload.clone(),
        )
        .route_with_task(
            "/v1/policies/{id}",
            get(policies::read::show_policy),
            // Reuses the upload task on the shared mount; the
            // `policies/show/1.0` Trust Task lives in index.json
            // + on disk for the soft-gate surface (see above).
            policies_upload.clone(),
        )
        .route_with_task(
            "/v1/policies/{id}/activate",
            post(policies::admin::activate),
            policies_activate,
        )
        .route_with_task(
            "/v1/policies/{id}/test",
            post(policies::admin::test),
            policies_test,
        )
        .into_router()
}
