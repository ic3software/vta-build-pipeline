//! Integration coverage for the M1.11 + M1.12 removal endpoints.
//!
//! - `DELETE /v1/members/me` (self-remove): happy path per
//!   disposition, sole-admin protection, missing-member 404.
//! - `DELETE /v1/members/{did}` (admin-remove): admin auth,
//!   self-target refused, last-admin protection.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::{KeyspaceHandle, Store};

use vtc_service::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::routes;
use vtc_service::server::AppState;

const RP_ORIGIN: &str = "https://vtc.example.com";
const SELF_REMOVE_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0";
const SHOW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/show/1.0";
const POLICY_UPLOAD_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/upload/1.0";
const POLICY_ACTIVATE_TASK: &str = "https://trusttasks.org/openvtc/vtc/policies/activate/1.0";

const ADMIN_DID: &str = "did:key:zAdmin1";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    admin_token: String,
    acl_ks: KeyspaceHandle,
    members_ks: KeyspaceHandle,
    sessions_ks: KeyspaceHandle,
    jwt_keys: Arc<JwtKeys>,
    _dir: tempfile::TempDir,
}

async fn build_fixture() -> Fixture {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let community_ks = store.keyspace("community").unwrap();
    let config_ks = store.keyspace("config").unwrap();
    let passkey_ks = store.keyspace("passkey").unwrap();
    let install_ks = store.keyspace("install").unwrap();
    let members_ks = store.keyspace("members").unwrap();
    let join_requests_ks = store.keyspace("join_requests").unwrap();
    let policies_ks = store.keyspace("policies").unwrap();
    let active_policies_ks = store.keyspace("active_policies").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();
    let install_store = InstallTokenStore::new(install_ks.clone());

    // Install workspace default policies the same way `server::run`
    // does at boot (M2.5). The admin-remove handler (M2.7)
    // consults `removal.rego.allow` and the disposition resolver
    // reads `removal.rego.min_disposition`; an empty policy set
    // would fail closed.
    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .expect("install default policies");

    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: ADMIN_DID.into(),
            role: VtcRole::Admin,
            label: Some("primary admin".into()),
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&members_ks, &Member::fresh(ADMIN_DID))
        .await
        .unwrap();

    let session_id = "test-admin-session";
    store_session(
        &sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: ADMIN_DID.into(),
            challenge: "test".into(),
            state: SessionState::Authenticated,
            created_at: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
        },
    )
    .await
    .unwrap();

    let admin_claims = jwt_keys.new_claims(
        ADMIN_DID.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        3600,
        true,
    );
    let admin_token = jwt_keys.encode(&admin_claims).unwrap();

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        public_url = "{RP_ORIGIN}"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks: sessions_ks.clone(),
        acl_ks: acl_ks.clone(),
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks: members_ks.clone(),
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: None,
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        admin_token,
        acl_ks,
        members_ks,
        sessions_ks,
        jwt_keys,
        _dir: dir,
    }
}

/// Mint a `Member`-role session token for a freshly-seeded
/// member. The auth layer still uses vti-common's Role taxonomy
/// (PR-1's M1.2 plumbing note), so the token's `role` claim is
/// the lowercase Role string the JWT decoder accepts —
/// `"reader"` maps to the lowest privilege bucket, which lets
/// the AuthClaims extractor populate `auth.did` without
/// gating-by-role at the route layer. Self-remove only checks
/// auth.did, so this is sufficient for the wire test.
async fn seed_member_with_session(fix: &Fixture, did: &str, role: VtcRole) -> String {
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &fix.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role: role.clone(),
            label: None,
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&fix.members_ks, &Member::fresh(did))
        .await
        .unwrap();

    let session_id = format!("session-{}", did.replace([':', '/'], "-"));
    store_session(
        &fix.sessions_ks,
        &Session {
            session_id: session_id.clone(),
            did: did.into(),
            challenge: "test".into(),
            state: SessionState::Authenticated,
            created_at: now,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
        },
    )
    .await
    .unwrap();

    // Map VtcRole → vti-common's Role string for the JWT.
    let vti_role = match role {
        VtcRole::Admin => "admin",
        // Every non-Admin VtcRole degrades to vti-common's
        // `reader` for the JWT — AuthClaims uses vti-common Role
        // until the auth layer is rewritten. Self-remove doesn't
        // gate on role beyond "authenticated" so this is fine.
        _ => "reader",
    };
    let claims =
        fix.jwt_keys
            .new_claims(did.into(), session_id, vti_role.into(), vec![], 3600, true);
    fix.jwt_keys.encode(&claims).unwrap()
}

async fn send(
    router: &axum::Router,
    method: &str,
    uri: &str,
    trust_task: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("Trust-Task", trust_task);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = router
        .clone()
        .oneshot(
            req.body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or(Body::empty()),
            )
            .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

// ---------------------------------------------------------------------------
// M1.11.1 — DELETE /v1/members/me
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_remove_tombstones_member_by_default() {
    let fix = build_fixture().await;
    let member_did = "did:key:zMember1";
    let token = seed_member_with_session(&fix, member_did, VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["disposition"], "tombstone");
    assert_eq!(body["removed"], true);

    assert!(
        get_acl_entry(&fix.acl_ks, member_did)
            .await
            .unwrap()
            .is_none()
    );
    let tomb = get_member(&fix.members_ks, member_did)
        .await
        .unwrap()
        .expect("Tombstone Member row retained");
    assert!(tomb.removed_at.is_some());
    assert!(tomb.current_vmc_id.is_none());
}

#[tokio::test]
async fn self_remove_with_purge_deletes_member_row() {
    let fix = build_fixture().await;
    let member_did = "did:key:zMember2";
    let token = seed_member_with_session(&fix, member_did, VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        Some(&token),
        Some(json!({ "disposition": "purge" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["disposition"], "purge");

    assert!(
        get_acl_entry(&fix.acl_ks, member_did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_member(&fix.members_ks, member_did)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn self_remove_with_historical_keeps_row_verbatim() {
    let fix = build_fixture().await;
    let member_did = "did:key:zMember3";
    let token = seed_member_with_session(&fix, member_did, VtcRole::Member).await;
    // Stamp a credential pointer so we can confirm Historical
    // retains it.
    let mut m = get_member(&fix.members_ks, member_did)
        .await
        .unwrap()
        .unwrap();
    m.current_vmc_id = Some("vmc-test".into());
    store_member(&fix.members_ks, &m).await.unwrap();

    let (status, _) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        Some(&token),
        Some(json!({ "disposition": "historical" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let kept = get_member(&fix.members_ks, member_did)
        .await
        .unwrap()
        .unwrap();
    assert!(kept.removed_at.is_some());
    assert_eq!(kept.current_vmc_id.as_deref(), Some("vmc-test"));
}

#[tokio::test]
async fn self_remove_refused_for_sole_admin() {
    let fix = build_fixture().await;
    // The fixture's sole admin is ADMIN_DID — try to remove them.
    let (status, body) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "got {body}");
    assert!(
        get_acl_entry(&fix.acl_ks, ADMIN_DID)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn self_remove_works_when_second_admin_exists() {
    let fix = build_fixture().await;
    // Promote a second admin so the no-last-admin invariant is
    // satisfied.
    let _other_token = seed_member_with_session(&fix, "did:key:zSecondAdmin", VtcRole::Admin).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert!(
        get_acl_entry(&fix.acl_ks, ADMIN_DID)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn self_remove_requires_authentication() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "DELETE",
        "/v1/members/me",
        SELF_REMOVE_TASK,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// M1.12.1 — DELETE /v1/members/{did}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_remove_member_works() {
    let fix = build_fixture().await;
    let target = "did:key:zVictim";
    let _ = seed_member_with_session(&fix, target, VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{target}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "policy violation" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["disposition"], "tombstone");
    assert!(get_acl_entry(&fix.acl_ks, target).await.unwrap().is_none());
}

#[tokio::test]
async fn admin_remove_self_refused_with_self_remove_hint() {
    let fix = build_fixture().await;
    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{ADMIN_DID}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let msg = body.to_string();
    assert!(msg.contains("/v1/members/me"), "got {msg}");
}

#[tokio::test]
async fn admin_remove_of_admin_target_is_denied_by_default_policy() {
    let fix = build_fixture().await;
    // Phase 2 M2.7 wires `removal.rego` into the admin-remove
    // path. The default removal policy (spec §7.1) denies
    // `target_role == "admin"` — admins should only be removed
    // via promotion + step-up UV (spec §10.4 / §5.3), never via
    // a casual admin-remove. This used to be a 200 in Phase 1
    // because there was no policy step.
    //
    // The no-last-admin invariant is now unreachable through
    // admin-remove for a different reason: every removable
    // target has role != "admin", so the invariant guard never
    // fires in this path.
    let second_admin = "did:key:zSecondAdmin";
    let _ = seed_member_with_session(&fix, second_admin, VtcRole::Admin).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{second_admin}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "ouster" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {body}");
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("removal denied by policy"),
        "error body should explain the policy denial: {body}"
    );
    // Both admins still present — the policy denied the change.
    assert!(
        get_acl_entry(&fix.acl_ks, ADMIN_DID)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_acl_entry(&fix.acl_ks, second_admin)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn admin_remove_404_for_unknown_did() {
    let fix = build_fixture().await;
    let (status, _) = send(
        &fix.router,
        "DELETE",
        "/v1/members/did:key:zNobody",
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_remove_overlong_reason_rejected() {
    let fix = build_fixture().await;
    let target = "did:key:zV";
    let _ = seed_member_with_session(&fix, target, VtcRole::Member).await;

    let (status, _) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{target}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "x".repeat(1025) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// M2.7 — policy step at admin-remove time
// ---------------------------------------------------------------------------

/// Upload + activate a removal policy via the admin endpoints.
/// `source` is the full Rego module body.
async fn activate_removal_policy(fix: &Fixture, source: &str) {
    let (status, body) = send(
        &fix.router,
        "POST",
        "/v1/policies",
        POLICY_UPLOAD_TASK,
        Some(&fix.admin_token),
        Some(json!({ "purpose": "removal", "regoSource": source })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "upload failed: {body}");
    let id = body["id"].as_str().unwrap();
    let (status, body) = send(
        &fix.router,
        "POST",
        &format!("/v1/policies/{id}/activate"),
        POLICY_ACTIVATE_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate failed: {body}");
}

/// A deny-all custom removal.rego blocks admin-remove even for
/// non-admin targets. Confirms the policy gate runs in front of
/// the legacy disposition path.
#[tokio::test]
async fn admin_remove_member_blocked_by_deny_all_policy() {
    let fix = build_fixture().await;
    activate_removal_policy(
        &fix,
        "package vtc.removal\nimport rego.v1\n\ndefault allow := false\n",
    )
    .await;

    let target = "did:key:zVictim2";
    let _ = seed_member_with_session(&fix, target, VtcRole::Member).await;

    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{target}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({ "reason": "policy gate test" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {body}");
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("removal denied by policy"),
        "error body should explain the policy denial: {body}"
    );
    // Target still present — policy denied the change.
    assert!(get_acl_entry(&fix.acl_ks, target).await.unwrap().is_some());
}

/// `min_disposition := "purge"` on the active removal.rego
/// resolves `PolicyDefault` → `Purge`, replacing Phase 1's
/// hardcoded Tombstone fallback (Phase 1 plan §D6 placeholder).
#[tokio::test]
async fn admin_remove_uses_policy_min_disposition_for_default() {
    let fix = build_fixture().await;
    activate_removal_policy(
        &fix,
        "package vtc.removal\nimport rego.v1\n\n\
         default allow := false\n\
         allow if {\n  input.action == \"remove\"\n  input.target_role != \"admin\"\n}\n\
         default min_disposition := \"purge\"\n",
    )
    .await;

    let target = "did:key:zPurgeMe";
    let _ = seed_member_with_session(&fix, target, VtcRole::Member).await;

    // Caller does not pass `disposition`; member's preference is
    // `PolicyDefault` (the join-time default) → resolver consults
    // the policy → resolves to Purge → Member row is deleted.
    let (status, body) = send(
        &fix.router,
        "DELETE",
        &format!("/v1/members/{target}"),
        SHOW_TASK,
        Some(&fix.admin_token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["disposition"], "purge");
    // ACL and member both gone (purge semantic).
    assert!(get_acl_entry(&fix.acl_ks, target).await.unwrap().is_none());
}
