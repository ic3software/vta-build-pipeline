//! Integration coverage for `/v1/admin/config`.
//!
//! Exercises the full router stack — Trust-Task header → AdminAuth
//! extractor → handler → three-layer effective view → db-overlay
//! persistence — via `Router::oneshot`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;
use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::config::AppConfig;
use vtc_service::routes;
use vtc_service::server::AppState;

const CONFIG_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0";

fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

struct Fixture {
    router: axum::Router,
    jwt_keys: Arc<JwtKeys>,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn build() -> Fixture {
    build_with(false, None).await
}

async fn build_with(
    with_audit: bool,
    supervisor: Option<vtc_service::supervisor::SupervisorKind>,
) -> Fixture {
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

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:webvh:vtc.example.com:abc"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");

    let audit_writer = if with_audit {
        let key_store = vti_common::audit::AuditKeyStore::new(audit_key_ks.clone());
        key_store.ensure_initial(&[0xAB; 64]).await.unwrap();
        Some(vti_common::audit::AuditWriter::new(
            audit_ks.clone(),
            key_store,
        ))
    } else {
        None
    };

    let state = AppState {
        sessions_ks: sessions_ks.clone(),
        acl_ks,
        community_ks,
        config_ks,
        passkey_ks,
        install_ks: install_ks.clone(),
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
        webauthn: None,
        public_url: None,
        install_signer: None,
        install_store: vtc_service::install::InstallTokenStore::new(install_ks),
        audit_ks,
        audit_key_ks,
        audit_writer,
        shutdown_tx: tokio::sync::watch::channel(false).0,
        supervisor,
    };

    let router = routes::router().with_state(state.clone());
    Fixture {
        router,
        jwt_keys,
        state,
        _dir: dir,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: "did:key:z6MkAdmin".into(),
        challenge: "test".into(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
    };
    store_session(&fix.state.sessions_ks, &session)
        .await
        .unwrap();
    let claims = fix.jwt_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        session_id,
        role.to_string(),
        vec![],
        900,
        false,
    );
    fix.jwt_keys.encode(&claims).expect("encode")
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

// ──────────────────────── GET ────────────────────────

#[tokio::test]
async fn get_returns_effective_config_with_defaults() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    let fields = body["fields"].as_array().unwrap();
    let by_key: std::collections::HashMap<_, _> = fields
        .iter()
        .map(|f| (f["key"].as_str().unwrap(), f))
        .collect();

    assert_eq!(by_key["server.host"]["value"], "0.0.0.0");
    assert_eq!(by_key["server.host"]["source"], "default");
    assert_eq!(by_key["server.host"]["requiresRestart"], true);

    assert_eq!(by_key["server.port"]["value"], 8200);
    assert_eq!(by_key["server.port"]["source"], "default");

    assert_eq!(by_key["log.level"]["value"], "info");
    assert_eq!(by_key["log.level"]["source"], "default");
    assert_eq!(by_key["log.level"]["requiresRestart"], false);
}

#[tokio::test]
async fn get_requires_admin_role() {
    let fix = build().await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_requires_authentication() {
    let fix = build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ──────────────────────── PATCH ────────────────────────

#[tokio::test]
async fn patch_applies_reloadable_key_immediately() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!(["log.level"]));
    assert_eq!(body["pendingRestart"], json!([]));
    assert_eq!(body["rejected"], json!([]));

    // GET reflects the new value with source = db.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (_, body) = body_value(resp).await;
    let level = body["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == "log.level")
        .unwrap();
    assert_eq!(level["value"], "debug");
    assert_eq!(level["source"], "db");
}

#[tokio::test]
async fn patch_restart_required_key_is_pending() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"server.port":9100}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!([]));
    assert_eq!(body["pendingRestart"], json!(["server.port"]));
    assert_eq!(body["rejected"], json!([]));
}

#[tokio::test]
async fn patch_unknown_key_rejected_with_reason() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"made.up.key":"value"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "made.up.key");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("unknown config key")
    );
}

#[tokio::test]
async fn patch_invalid_value_rejected_with_reason() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"verbose"}"#)) // not in enum
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let rejected = body["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["key"], "log.level");
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("must be one of")
    );
}

#[tokio::test]
async fn patch_mixed_batch_partitions_correctly() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let body = json!({
        "log.level": "debug",      // applied
        "server.port": 9100,        // pendingRestart
        "made.up": "x",             // rejected (unknown)
        "log.level_v2": "debug",    // rejected (unknown)
    });
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body["applied"], json!(["log.level"]));
    assert_eq!(body["pendingRestart"], json!(["server.port"]));
    let rejected: Vec<&str> = body["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(rejected.len(), 2);
    assert!(rejected.contains(&"made.up"));
    assert!(rejected.contains(&"log.level_v2"));
}

#[tokio::test]
async fn patch_requires_admin_role() {
    let fix = build().await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_empty_body_returns_empty_response() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header("Trust-Task", CONFIG_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], json!([]));
    assert_eq!(body["pendingRestart"], json!([]));
    assert_eq!(body["rejected"], json!([]));
}

// ──────────────────────── Trust-Task gate ────────────────────────

#[tokio::test]
async fn get_with_wrong_trust_task_returns_415() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/config")
        .header(
            "Trust-Task",
            "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0",
        )
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ──────────────────────── Reload ────────────────────────

const RELOAD_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/reload/1.0";
const RESTART_TASK: &str = "https://trusttasks.org/openvtc/vtc/admin/config/restart/1.0";

async fn reload(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/reload")
        .header("Trust-Task", RELOAD_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

async fn restart(fix: &Fixture, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/restart")
        .header("Trust-Task", RESTART_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    body_value(resp).await
}

#[tokio::test]
async fn reload_no_diff_returns_empty_keys_reloaded() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, body) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keysReloaded"], json!([]));
}

#[tokio::test]
async fn reload_applies_hot_reloadable_diff() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;

    // Write `log.level = "debug"` via PATCH so the db-layer differs
    // from the live in-memory `info`. reload must pick up the
    // delta.
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/admin/config")
        .header(
            "Trust-Task",
            "https://trusttasks.org/openvtc/vtc/admin/config/manage/1.0",
        )
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"log.level":"debug"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keysReloaded"], json!(["log.level"]));

    // In-memory `AppConfig.log.level` now reflects the new value.
    assert_eq!(fix.state.config.read().await.log.level, "debug");

    // Second reload is a no-op (no diff left).
    let (_, body) = reload(&fix, &token).await;
    assert_eq!(body["keysReloaded"], json!([]));
}

#[tokio::test]
async fn reload_requires_admin_role() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "reader").await;
    let (status, _) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reload_503_when_audit_writer_missing() {
    let fix = build_with(false, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, _) = reload(&fix, &token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ──────────────────────── Restart ────────────────────────

#[tokio::test]
async fn restart_without_supervisor_returns_412() {
    let fix = build_with(true, None).await;
    let token = token_for(&fix, "admin").await;
    let (status, body) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("SupervisorRequired"),
        "got {body}",
    );
}

#[tokio::test]
async fn restart_with_supervisor_triggers_shutdown() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;

    // Subscribe to the shutdown channel BEFORE the request so we
    // can assert the flip.
    let mut rx = fix.state.shutdown_tx.subscribe();
    assert!(!*rx.borrow_and_update());

    let (status, body) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["supervisor"], "manual");
    assert!(body["drainTimeoutSeconds"].as_u64().unwrap() > 0);

    // Shutdown was signalled.
    assert!(*rx.borrow_and_update());
}

#[tokio::test]
async fn restart_emits_audit_event_before_signal() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Systemd)).await;
    let token = token_for(&fix, "admin").await;

    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::OK);

    // Confirm exactly one RestartRequested envelope landed.
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<vti_common::audit::AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let restart_events: Vec<_> = envelopes
        .iter()
        .filter(|e| matches!(e.event, vti_common::audit::AuditEvent::RestartRequested(_)))
        .collect();
    assert_eq!(restart_events.len(), 1);
}

#[tokio::test]
async fn restart_requires_admin_role() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "reader").await;
    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn restart_503_when_audit_writer_missing() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(false, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;
    let (status, _) = restart(&fix, &token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn restart_wrong_trust_task_returns_415() {
    use vtc_service::supervisor::SupervisorKind;
    let fix = build_with(true, Some(SupervisorKind::Manual)).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/config/restart")
        .header("Trust-Task", RELOAD_TASK) // wrong
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
