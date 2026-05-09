//! Audience-isolation integration tests for the VTC service.
//!
//! CLAUDE.md identifies VTA-vs-VTC audience isolation as a load-bearing
//! invariant: a JWT minted with `aud = "VTA"` MUST NOT authenticate
//! against a VTC route. The complementary test on the VTA side lives
//! in `vta-service/tests/api_integration.rs`. Both run the assertion
//! through the full route stack so a future refactor that, say,
//! normalises audiences before validation surfaces immediately.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use vti_common::auth::jwt::JwtKeys;
use vti_common::config::StoreConfig;
use vti_common::store::Store;

use vtc_service::config::AppConfig;
use vtc_service::routes;
use vtc_service::server::AppState;

/// Pin jsonwebtoken's default `CryptoProvider` to `aws_lc` once per
/// process. The workspace compiles `jsonwebtoken` with only the
/// `aws_lc_rs` backend feature (the `rust_crypto` bundle pulls in
/// `rsa`, exposed to RUSTSEC-2023-0071); installing the provider
/// explicitly is also defensive against feature-graph surprises
/// from sibling crates under `cargo test --workspace`.
fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

async fn build_test_router() -> (axum::Router, Arc<JwtKeys>, tempfile::TempDir) {
    init_jwt_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("open store");

    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();

    let jwt_seed = [0x42u8; 32];
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&jwt_seed, "VTC").expect("jwt keys"));

    let config: AppConfig = toml::from_str(&format!(
        r#"
        vtc_did = "did:key:z6MkTestVTC"
        [store]
        data_dir = "{}"
        [auth]
        jwt_signing_key = "{}"
        "#,
        dir.path().display(),
        BASE64.encode(jwt_seed),
    ))
    .expect("parse config");

    let state = AppState {
        sessions_ks,
        acl_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        atm: None,
    };

    let router = routes::router().with_state(state);
    (router, jwt_keys, dir)
}

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn vta_audience_token_rejected_by_vtc_route() {
    let (router, _vtc_keys, _dir) = build_test_router().await;

    // Mint a token whose `aud` claim is "VTA". The VTC's JwtKeys was
    // configured with `audience = "VTC"`, so this foreign-audience
    // token must be rejected at decode time.
    let foreign_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap();
    let claims = foreign_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        format!("sess-{}", uuid::Uuid::new_v4()),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let foreign_token = foreign_keys.encode(&claims).expect("encode");

    let req = Request::builder()
        .method("GET")
        .uri("/acl")
        .header("Authorization", format!("Bearer {foreign_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "VTA-audience JWT must be rejected by VTC routes"
    );
}

#[tokio::test]
async fn unknown_audience_token_rejected_by_vtc_route() {
    // Defence-in-depth: any audience that isn't "VTC" must be rejected,
    // not just the well-known "VTA" string. A future "VTM" service or
    // an attacker-supplied token with a custom audience must never
    // authenticate.
    let (router, _vtc_keys, _dir) = build_test_router().await;

    let foreign_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "EVIL-V99").unwrap();
    let claims = foreign_keys.new_claims(
        "did:key:z6MkAdmin".to_string(),
        format!("sess-{}", uuid::Uuid::new_v4()),
        "admin".to_string(),
        vec![],
        900,
        false,
    );
    let foreign_token = foreign_keys.encode(&claims).expect("encode");

    let req = Request::builder()
        .method("GET")
        .uri("/acl")
        .header("Authorization", format!("Bearer {foreign_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_token_rejected_by_vtc_route() {
    let (router, _, _dir) = build_test_router().await;

    let req = Request::builder()
        .method("GET")
        .uri("/acl")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = request(&router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "missing Authorization header must be rejected"
    );
}
