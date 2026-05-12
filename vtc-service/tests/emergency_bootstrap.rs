//! End-to-end coverage for `vtc admin emergency-bootstrap` (M0.10)
//! and the daemon-side `EmergencyBootstrapInvoked` audit emission
//! (M0.12.2).
//!
//! Walks the full recovery loop:
//!
//! 1. Stand up a daemon-like state with one bootstrapped admin.
//! 2. Stop the "daemon" — in tests this is just dropping the
//!    request-handling AppState.
//! 3. Call `emergency::run_emergency_bootstrap_with_store` with the
//!    correct master-seed mnemonic.
//! 4. Assert the destructive cleanup ran: admin ACL entries
//!    cleared, sister records gone, carve-out reopened, pending
//!    marker present, fresh install token recorded.
//! 5. Rebuild the AppState (simulates `vtc` daemon restart). The
//!    startup code in `server::run` consumes the pending marker
//!    and writes the `EmergencyBootstrapInvoked` envelope. Tests
//!    drive that branch directly (the integration test doesn't
//!    actually `axum::serve`).
//! 6. Drive a new install/claim against the fresh URL → succeeds.
//!
//! Plus negative coverage: wrong mnemonic refused with no state
//! mutation; pending marker is one-shot (second startup doesn't
//! emit a duplicate envelope).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::acl::{AclEntry, Role, list_acl_entries, store_acl_entry};
use vti_common::audit::{AuditEnvelope, AuditEvent, AuditKeyStore, AuditWriter};
use vti_common::auth::jwt::JwtKeys;
use vti_common::auth::passkey::build_webauthn;
use vti_common::config::StoreConfig;
use vti_common::store::Store;
use webauthn_rs::prelude::CreationChallengeResponse;

use vtc_service::acl::admin::{AdminEntry, RegisteredPasskey, store_admin_entry};
use vtc_service::config::AppConfig;
use vtc_service::emergency::{EmergencyBootstrapOutcome, run_emergency_bootstrap_with_store};
use vtc_service::install::InstallTokenStore;
use vtc_service::routes;
use vtc_service::server::AppState;

const RP_ORIGIN: &str = "https://vtc.example.com";
const CLAIM_START_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

/// In-memory `SeedStore` so tests can drive the emergency module
/// without touching the OS keyring or filesystem.
struct InMemorySeedStore {
    inner: tokio::sync::Mutex<Option<Vec<u8>>>,
}

impl InMemorySeedStore {
    fn new(seed: Vec<u8>) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(seed)),
        }
    }
}

impl vti_common::seed_store::SeedStore for InMemorySeedStore {
    fn get(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, vti_common::error::AppError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let v = self.inner.lock().await;
            Ok(v.clone())
        })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), vti_common::error::AppError>> + Send + '_>,
    > {
        let bytes = secret.to_vec();
        Box::pin(async move {
            let mut v = self.inner.lock().await;
            *v = Some(bytes);
            Ok(())
        })
    }
}

/// Master seed shared across the test — 64 bytes derived from a
/// known BIP-39 mnemonic via the standard `mnemonic.to_seed("")`
/// PBKDF2 path. The mnemonic itself is held alongside so tests can
/// drive both happy + sad paths from the same source of truth.
struct TestSeed {
    mnemonic: String,
    seed: Vec<u8>,
}

fn test_seed() -> TestSeed {
    // 32 bytes of fixed entropy → reproducible 24-word mnemonic.
    let mnemonic = bip39::Mnemonic::from_entropy(&[0xAA; 32]).unwrap();
    let seed = mnemonic.to_seed("").to_vec();
    TestSeed {
        mnemonic: mnemonic.to_string(),
        seed,
    }
}

struct Fixture {
    state: AppState,
    router: axum::Router,
    config: AppConfig,
    store: Store,
    secret_store: Arc<InMemorySeedStore>,
    test_seed: TestSeed,
    admin_did: String,
    _dir: tempfile::TempDir,
}

/// Build the post-bootstrap state: an admin ACL entry, an admin
/// sister record, a credential mapping for one passkey, a closed
/// install carve-out, audit writer wired.
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
    let audit_ks = store.keyspace("audit").unwrap();
    let audit_key_ks = store.keyspace("audit_key").unwrap();
    let install_store = InstallTokenStore::new(install_ks.clone());

    let test_seed = test_seed();
    let secret_store = Arc::new(InMemorySeedStore::new(test_seed.seed.clone()));

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").unwrap());

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

    let webauthn = Some(Arc::new(build_webauthn(RP_ORIGIN).expect("build webauthn")));

    // Seed an audit key + writer.
    let key_store = AuditKeyStore::new(audit_key_ks.clone());
    key_store.ensure_initial(&test_seed.seed).await.unwrap();
    let audit_writer = Some(AuditWriter::new(audit_ks.clone(), key_store));

    // Existing admin state (as if a previous install + bootstrap
    // ran). `pk_user:` records too so the emergency cleanup has
    // something realistic to delete.
    let admin_did = "did:key:zOldAdmin".to_string();
    let user_uuid = uuid::Uuid::new_v4();
    let pk_user = vti_common::auth::passkey::store::PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: Vec::new(),
    };
    vti_common::auth::passkey::store::store_passkey_user(&passkey_ks, &pk_user)
        .await
        .unwrap();

    store_acl_entry(
        &acl_ks,
        &AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("old admin".into()),
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            expires_at: None,
        },
    )
    .await
    .unwrap();

    let mut admin_entry = AdminEntry::new(admin_did.clone());
    admin_entry.passkeys.push(RegisteredPasskey {
        credential_id: "deadbeef".into(),
        label: "lost device".into(),
        transports: vec![],
        registered_at: Utc::now(),
        last_used_at: None,
    });
    store_admin_entry(&passkey_ks, &admin_entry).await.unwrap();

    // Carve-out closed — this is the "every passkey lost" state.
    install_store.close_carveout().await.unwrap();

    let install_signer = Arc::new(
        vtc_service::install::InstallTokenSigner::from_master_seed(&test_seed.seed).unwrap(),
    );

    let state = AppState {
        sessions_ks,
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks,
        audit_ks: audit_ks.clone(),
        audit_key_ks: audit_key_ks.clone(),
        config: Arc::new(RwLock::new(config.clone())),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys),
        atm: None,
        webauthn,
        public_url: Some(RP_ORIGIN.to_string()),
        install_signer: Some(install_signer),
        install_store: install_store.clone(),
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor: None,
    };

    let router = routes::router().with_state(state.clone());

    Fixture {
        state,
        router,
        config,
        store,
        secret_store,
        test_seed,
        admin_did,
        _dir: dir,
    }
}

/// Reproduce the daemon's startup-time consumption of the pending
/// marker. Mirrors `server::run`'s emergency-pending branch so the
/// test doesn't have to spin up the real `axum::serve` loop.
async fn simulate_daemon_restart_audit(state: &AppState) -> Option<AuditEnvelope> {
    let pending = state
        .install_store
        .take_pending_emergency()
        .await
        .unwrap()?;
    let writer = state.audit_writer.as_ref().unwrap();
    let envelope = writer
        .write(
            "did:key:vtc-emergency",
            None,
            AuditEvent::EmergencyBootstrapInvoked(vti_common::audit::EmergencyBootstrapData {
                operator_hostname: pending.operator_hostname,
                invoked_at: pending.invoked_at,
            }),
        )
        .await
        .unwrap();
    Some(envelope)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_clears_admin_reopens_carveout_and_audits_on_restart() {
    let fix = build_fixture().await;

    // Sanity: pre-state is what the test expects.
    let acl_before = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl_before.len(), 1);
    assert_eq!(acl_before[0].did, fix.admin_did);
    assert!(fix.state.install_store.carveout_is_closed().await.unwrap());

    // Step 1–3: run the emergency-bootstrap driver with the correct
    // mnemonic.
    let outcome: EmergencyBootstrapOutcome = run_emergency_bootstrap_with_store(
        fix.test_seed.mnemonic.clone(),
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .expect("emergency bootstrap");

    assert_eq!(outcome.admin_entries_cleared, 1);
    assert_eq!(outcome.admin_records_cleared, 1);
    assert!(
        outcome
            .install_url
            .starts_with("https://vtc.example.com/install?token="),
        "got {}",
        outcome.install_url,
    );

    // Step 4: destructive cleanup ran.
    let acl_after = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl_after.len(), 0, "admin ACL entry must be cleared");
    let admin_after =
        vtc_service::acl::admin::get_admin_entry(&fix.state.passkey_ks, &fix.admin_did)
            .await
            .unwrap();
    assert!(admin_after.is_none());
    assert!(
        !fix.state.install_store.carveout_is_closed().await.unwrap(),
        "carve-out must be reopened",
    );

    // Step 5: simulate daemon restart — pending marker drives the
    // audit envelope, then the marker is consumed.
    let envelope = simulate_daemon_restart_audit(&fix.state)
        .await
        .expect("pending marker present after emergency bootstrap");
    match envelope.event {
        AuditEvent::EmergencyBootstrapInvoked(ref data) => {
            assert!(!data.operator_hostname.is_empty(), "hostname captured");
            assert!(data.invoked_at <= Utc::now());
        }
        ref other => panic!("expected EmergencyBootstrapInvoked, got {other:?}"),
    }

    // Marker is one-shot: a second restart-time consumer sees None
    // and emits no envelope.
    assert!(simulate_daemon_restart_audit(&fix.state).await.is_none());
}

#[tokio::test]
async fn wrong_mnemonic_is_refused_and_state_unchanged() {
    let fix = build_fixture().await;

    let wrong_mnemonic = bip39::Mnemonic::from_entropy(&[0xBB; 32])
        .unwrap()
        .to_string();
    let err = run_emergency_bootstrap_with_store(
        wrong_mnemonic,
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .expect_err("wrong mnemonic must be rejected");

    use vti_common::error::AppError;
    assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");

    // No state mutation.
    let acl = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl.len(), 1, "ACL untouched");
    assert!(
        fix.state.install_store.carveout_is_closed().await.unwrap(),
        "carve-out still closed",
    );
    assert!(
        fix.state
            .install_store
            .take_pending_emergency()
            .await
            .unwrap()
            .is_none(),
        "no pending marker",
    );
}

#[tokio::test]
async fn malformed_mnemonic_is_rejected_as_validation_error() {
    let fix = build_fixture().await;
    let err = run_emergency_bootstrap_with_store(
        "not valid words".to_string(),
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .expect_err("malformed mnemonic must be rejected");
    use vti_common::error::AppError;
    assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
}

#[tokio::test]
async fn fresh_install_url_works_for_claim_start_after_emergency_bootstrap() {
    // Closes the loop: emergency bootstrap should leave the daemon
    // in a state where a *new* operator can claim the new install
    // URL and go through the normal install ceremony.
    let fix = build_fixture().await;

    let outcome = run_emergency_bootstrap_with_store(
        fix.test_seed.mnemonic.clone(),
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .unwrap();

    // Drain the pending marker so a real daemon restart wouldn't
    // re-emit the audit event in the middle of this assertion.
    let _ = simulate_daemon_restart_audit(&fix.state).await;

    // Extract the install token from the URL.
    let token = outcome
        .install_url
        .split("token=")
        .nth(1)
        .expect("install URL has token");

    // Drive `POST /v1/install/claim/start`. Without emergency
    // bootstrap this would 401 (carve-out closed); after, it 200s.
    let req = Request::builder()
        .method("POST")
        .uri("/v1/install/claim/start")
        .header("Trust-Task", CLAIM_START_TASK)
        .header("Content-Type", "application/json")
        .body(Body::from(json!({ "install_token": token }).to_string()))
        .unwrap();
    let res = fix.router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };

    assert_eq!(
        status,
        StatusCode::OK,
        "claim/start after emergency: {body}"
    );
    let _: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("WebAuthn options returned");
}

#[tokio::test]
async fn no_secret_in_store_yields_clean_config_error() {
    // Build the fixture, then nuke the seed so the emergency call
    // hits the "secret not found" branch.
    let fix = build_fixture().await;
    {
        let mut inner = fix.secret_store.inner.lock().await;
        *inner = None;
    }
    let err = run_emergency_bootstrap_with_store(
        fix.test_seed.mnemonic.clone(),
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .expect_err("missing seed must be rejected");
    use vti_common::error::AppError;
    assert!(matches!(err, AppError::Config(_)), "got {err:?}");
}

#[tokio::test]
async fn outcome_install_url_falls_back_to_vtc_scheme_when_public_url_missing() {
    let mut fix = build_fixture().await;
    {
        let mut cfg = fix.state.config.write().await;
        cfg.public_url = None;
    }
    fix.config.public_url = None;

    let outcome = run_emergency_bootstrap_with_store(
        fix.test_seed.mnemonic.clone(),
        &fix.config,
        &fix.store,
        fix.secret_store.as_ref(),
    )
    .await
    .unwrap();
    assert!(
        outcome.install_url.starts_with("vtc://install?token="),
        "got {}",
        outcome.install_url,
    );
}
