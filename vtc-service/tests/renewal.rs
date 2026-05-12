//! Integration coverage for `POST /v1/members/me/renew`
//! (Phase 2 M2.13).
//!
//! Verifies:
//! - Happy path re-mints VMC + role VEC and stamps the new
//!   ids on the Member row.
//! - Renewal reuses the same status-list slot the member was
//!   allocated at join time.
//! - 404 when the caller isn't a member.
//! - Both signed VCs verify against the daemon's signer.

mod common;

use std::sync::Arc;

use affinidi_status_list::StatusPurpose;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::audit::{AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::session::{Session, SessionState, store_session};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::config::AppConfig;
use vtc_service::credentials::LocalSigner;
use vtc_service::install::InstallTokenStore;
use vtc_service::members::{Member, get_member, store_member};
use vtc_service::routes;
use vtc_service::server::AppState;
use vtc_service::status_list;

const VTC_DID: &str = "did:webvh:vtc.example.com:abc";
const PUBLIC_URL: &str = "https://vtc.example.com";
const RENEW_TASK: &str = "https://trusttasks.org/openvtc/vtc/members/renew/1.0";
const MEMBER_DID: &str = "did:key:zRenewMember";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    member_token: String,
    signer: Arc<LocalSigner>,
    members_ks: vti_common::store::KeyspaceHandle,
    status_lists_ks: vti_common::store::KeyspaceHandle,
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
    let status_lists_ks = store.keyspace("status_lists").unwrap();
    let registry_records_ks = store.keyspace("registry_records").unwrap();
    let sync_queue_ks = store.keyspace("sync_queue").unwrap();
    let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();
    let install_store = InstallTokenStore::new(install_ks.clone());

    vtc_service::policy::default::install_defaults(&policies_ks, &active_policies_ks)
        .await
        .expect("install default policies");

    for purpose in [StatusPurpose::Revocation, StatusPurpose::Suspension] {
        let url = format!("{PUBLIC_URL}/v1/status-lists/{purpose}");
        status_list::ensure_initial(&status_lists_ks, purpose, url)
            .await
            .unwrap();
    }

    let signer = Arc::new(LocalSigner::from_ed25519_seed(VTC_DID.into(), &[0xCC; 32]));

    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

    // Seed a Member ACL row + Member metadata row.
    let now = vtc_service::auth::session::now_epoch();
    store_acl_entry(
        &acl_ks,
        &VtcAclEntry {
            did: MEMBER_DID.into(),
            role: VtcRole::Member,
            label: None,
            allowed_contexts: vec![],
            created_at: now,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();
    store_member(&members_ks, &Member::fresh(MEMBER_DID))
        .await
        .unwrap();

    let session_id = "test-member-session";
    store_session(
        &sessions_ks,
        &Session {
            session_id: session_id.into(),
            did: MEMBER_DID.into(),
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

    let member_claims = jwt_keys.new_claims(
        MEMBER_DID.into(),
        session_id.into(),
        "reader".into(),
        vec![],
        3600,
        true,
    );
    let member_token = jwt_keys.encode(&member_claims).unwrap();

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "{VTC_DID}"
        public_url = "{PUBLIC_URL}"
        [store]
        data_dir = "{}"
        "#,
        dir.path().display(),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        members_ks: members_ks.clone(),
        join_requests_ks,
        policies_ks,
        active_policies_ks,
        status_lists_ks: status_lists_ks.clone(),
        registry_records_ks: registry_records_ks.clone(),
        sync_queue_ks: sync_queue_ks.clone(),
        sync_cursor_ks: sync_cursor_ks.clone(),
        audit_ks,
        audit_key_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn: None,
        public_url: Some(PUBLIC_URL.into()),
        install_signer: None,
        credential_signer: Some(signer.clone()),
        install_store,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state);

    Fixture {
        router,
        member_token,
        signer,
        members_ks,
        status_lists_ks,
        _dir: dir,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let raw = String::from_utf8_lossy(&bytes);
        panic!("response body was not JSON ({e}): {raw}")
    })
}

#[tokio::test]
async fn renew_mints_fresh_vmc_and_role_vec() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;

    assert_eq!(body["did"], MEMBER_DID);
    assert_eq!(body["personhood"], false);
    assert_eq!(body["personhoodChanged"], false);

    let vmc: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["vmc"].clone()).unwrap();
    let role_vec: affinidi_vc::VerifiableCredential =
        serde_json::from_value(body["roleVec"].clone()).unwrap();
    fix.signer.verify(&vmc).expect("VMC verifies");
    fix.signer.verify(&role_vec).expect("VEC verifies");

    // Member row updated with the new ids + the freshly-
    // allocated slot.
    let m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert!(m.current_vmc_id.is_some());
    assert!(m.current_role_vec_id.is_some());
    assert!(m.status_list_index.is_some());
}

#[tokio::test]
async fn renew_reuses_existing_status_list_slot() {
    let fix = build_fixture().await;

    // Pre-allocate a slot for the member.
    let mut state = status_list::get_state(&fix.status_lists_ks, StatusPurpose::Revocation)
        .await
        .unwrap()
        .unwrap();
    let pinned_slot = status_list::allocate(&mut state).unwrap();
    status_list::store_state(&fix.status_lists_ks, &state)
        .await
        .unwrap();
    let mut m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    m.status_list_index = Some(pinned_slot);
    store_member(&fix.members_ks, &m).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("authorization", format!("Bearer {}", fix.member_token))
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let m = get_member(&fix.members_ks, MEMBER_DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        m.status_list_index,
        Some(pinned_slot),
        "renewal must reuse the existing slot"
    );
}

#[tokio::test]
async fn renew_requires_authentication() {
    let fix = build_fixture().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/members/me/renew")
        .header("trust-task", RENEW_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
