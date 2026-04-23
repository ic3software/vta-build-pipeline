//! Shared test-harness helpers — in-memory keyspaces, default
//! `AppConfig`, and a `bootstrap_test_vta` routine that provisions the
//! minimum VTA state `operations::provision_integration::provision_integration`
//! needs (active seed, `#key-0`, `#sealed-transfer-0`, DID resolver,
//! populated `vta_did`).
//!
//! Gated behind the `test-support` feature *and* `cfg(test)` for the
//! lib's own unit tests. Downstream integration tests (under
//! `tests/`) enable the feature via a `[dev-dependencies]` entry.
//!
//! Kept in the production crate rather than a separate
//! `vta-test-support` sibling because every helper here either returns
//! or closes over crate-private types (`KeyspaceHandle`, the seed-store
//! trait, `ProvisionIntegrationDeps`). A sibling crate would force
//! every one of them to be `pub` in the main API surface, which is the
//! opposite of what we want. Feature-flagging contains the test glue to
//! the build modes that actually need it.

#![cfg(any(test, feature = "test-support"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Duration;
use ed25519_dalek::SigningKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use serde_json::Value;
use tokio::sync::RwLock;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::config::{AppConfig, StoreConfig};
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::PlaintextSeedStore;
use crate::keys::{KeyType as SdkKeyType, save_key_record};
use crate::operations::provision_integration::ProvisionIntegrationDeps;
use crate::store::{KeyspaceHandle, Store};
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::provision_integration::{
    BootstrapAsk, BootstrapRequest, DidTemplateRef, TemplateBootstrapAsk, VerifiedBootstrapRequest,
};

/// A freshly-opened tempdir-backed store plus every keyspace the
/// `ProvisionIntegrationDeps` shape needs. Drops the tempdir on `Drop`
/// so tests never leak.
pub struct TestStore {
    // `_dir` has to outlive the store (it owns the on-disk backing), and
    // `_store` must outlive all keyspace handles (fjall's keyspace
    // handles are weak wrt the store's lifetime). Held here as fields
    // so the caller only has to keep `TestStore` alive.
    _dir: tempfile::TempDir,
    _store: Store,
    pub contexts_ks: KeyspaceHandle,
    pub did_templates_ks: KeyspaceHandle,
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    pub imported_ks: KeyspaceHandle,
    pub webvh_ks: KeyspaceHandle,
    pub sealed_nonces_ks: KeyspaceHandle,
    pub data_dir: PathBuf,
}

/// Open a fresh tempdir-backed `TestStore` with every keyspace wired.
pub async fn open_test_store() -> TestStore {
    let dir = tempfile::tempdir().expect("temp dir");
    let data_dir = dir.path().to_path_buf();
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.clone(),
    })
    .expect("open store");
    TestStore {
        contexts_ks: store.keyspace("contexts").expect("contexts ks"),
        did_templates_ks: store.keyspace("did_templates").expect("did_templates ks"),
        keys_ks: store.keyspace("keys").expect("keys ks"),
        acl_ks: store.keyspace("acl").expect("acl ks"),
        audit_ks: store.keyspace("audit").expect("audit ks"),
        imported_ks: store.keyspace("imported").expect("imported ks"),
        webvh_ks: store.keyspace("webvh").expect("webvh ks"),
        sealed_nonces_ks: store.keyspace("sealed_nonces").expect("nonces ks"),
        _dir: dir,
        _store: store,
        data_dir,
    }
}

/// A minimal `AppConfig` suitable for in-memory tests. All external
/// services (keyring, TEE, cloud secret managers, ...) are left at
/// their defaults.
pub fn test_app_config(data_dir: PathBuf) -> AppConfig {
    AppConfig {
        vta_did: None,
        vta_name: None,
        public_url: None,
        resolver_url: None,
        server: Default::default(),
        log: Default::default(),
        store: StoreConfig { data_dir },
        messaging: None,
        services: Default::default(),
        auth: Default::default(),
        audit: Default::default(),
        secrets: Default::default(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        config_path: PathBuf::new(),
    }
}

/// Build a `ProvisionIntegrationDeps` from a `TestStore`. The returned
/// deps have no DID resolver — use [`bootstrap_test_vta`] when the
/// full happy path is needed.
pub fn test_deps(ts: &TestStore) -> ProvisionIntegrationDeps {
    ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit_ks: ts.audit_ks.clone(),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(test_app_config(ts.data_dir.clone()))),
        did_resolver: None,
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
    }
}

/// Synthesise a super-admin `AuthClaims` for tests that bypass the
/// normal session/JWT gate.
pub fn super_admin_claims() -> AuthClaims {
    AuthClaims {
        did: "did:key:zTestAdmin".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
    }
}

/// Build + sign + verify a template-driven `BootstrapRequest` with no
/// admin rollover and no extra template vars.
pub async fn signed_request(template_name: &str, context_hint: &str) -> VerifiedBootstrapRequest {
    signed_request_with_vars(template_name, context_hint, BTreeMap::new()).await
}

/// Build + sign + verify a template-driven `BootstrapRequest` with the
/// given template vars (e.g. `URL`, `WEBVH_SERVER`).
pub async fn signed_request_with_vars(
    template_name: &str,
    context_hint: &str,
    vars: BTreeMap<String, Value>,
) -> VerifiedBootstrapRequest {
    let seed = [7u8; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pub_bytes: [u8; 32] = signing.verifying_key().to_bytes();
    let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

    let ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
        context_hint: Some(context_hint.into()),
        template: DidTemplateRef {
            name: template_name.into(),
            vars,
        },
        admin_template: None,
        note: None,
    });

    let req = BootstrapRequest::sign(
        &seed,
        &client_did,
        [0u8; 16],
        Duration::minutes(10),
        None,
        ask,
    )
    .await
    .expect("sign bootstrap request");
    req.verify().expect("verify bootstrap request")
}

/// Provision the minimum VTA state a full `provision_integration()`
/// call needs: an active seed, the VTA's `{vta_did}#key-0` signing key
/// + `#sealed-transfer-0` producer-assertion key saved in the keystore,
/// a DID resolver that can resolve the VTA's own `did:key`, and an
/// `AppConfig` with `vta_did` populated.
///
/// Returns `(vta_did, deps_with_resolver)` — the caller plugs the
/// returned deps into `provision_integration()` instead of [`test_deps`].
pub async fn bootstrap_test_vta(ts: &TestStore) -> (String, ProvisionIntegrationDeps) {
    use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};

    // Deterministic 64-byte seed (BIP-32 wants ≥16 bytes; 64 mirrors
    // the mnemonic-derived seed shape used in production setup).
    let raw_seed = [0xC5u8; 64];
    let seed_store = PlaintextSeedStore::new(&ts.data_dir);
    crate::keys::seed_store::SeedStore::set(&seed_store, &raw_seed)
        .await
        .expect("write test seed to plaintext store");

    let now = chrono::Utc::now();
    save_seed_record(
        &ts.keys_ks,
        &SeedRecord {
            id: 0,
            seed_hex: None,
            created_at: now,
            retired_at: None,
        },
    )
    .await
    .expect("save seed record");
    set_active_seed_id(&ts.keys_ks, 0)
        .await
        .expect("set active seed id");

    // Derive a fresh Ed25519 key at a canonical VTA path, convert to
    // did:key, save a keystore record whose id matches the
    // `{vta_did}#key-0` convention `load_vta_vc_issuance_secret` looks up.
    let vta_base_path = "m/26'/1'/0'";
    let root = ExtendedSigningKey::from_seed(&raw_seed).expect("bip-32 root");
    let dp: DerivationPath = vta_base_path.parse().expect("derivation path");
    let derived = root.derive(&dp).expect("derive VTA key");
    let signing = ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
    let pub_bytes = signing.verifying_key().to_bytes();
    let multibase = ed25519_multibase_pubkey(&pub_bytes);
    let vta_did = format!("did:key:{multibase}");
    let key_id = format!("{vta_did}#key-0");

    save_key_record(
        &ts.keys_ks,
        &key_id,
        vta_base_path,
        SdkKeyType::Ed25519,
        &multibase,
        "VTA signing key",
        None,
        Some(0),
    )
    .await
    .expect("save VTA key record");

    // Mirror the real VTA bootstrap: provision `#sealed-transfer-0`
    // (separate from `#key-0`, see review item 12) so
    // `provision_integration` can sign the producer assertion without
    // hitting the "re-bootstrap required" guard in
    // `load_vta_sealed_transfer_secret`.
    let st_base_path = "m/26'/1'/1'";
    let st_dp: DerivationPath = st_base_path.parse().expect("st derivation path");
    let st_derived = root.derive(&st_dp).expect("derive VTA sealed-transfer key");
    let st_signing = ed25519_dalek::SigningKey::from_bytes(st_derived.signing_key.as_bytes());
    let st_pub_bytes = st_signing.verifying_key().to_bytes();
    let st_multibase = ed25519_multibase_pubkey(&st_pub_bytes);
    save_key_record(
        &ts.keys_ks,
        &format!("{vta_did}#sealed-transfer-0"),
        st_base_path,
        SdkKeyType::Ed25519,
        &st_multibase,
        "VTA sealed-transfer producer-assertion key",
        None,
        Some(0),
    )
    .await
    .expect("save VTA sealed-transfer key record");

    let mut config = test_app_config(ts.data_dir.clone());
    config.vta_did = Some(vta_did.clone());
    config.public_url = Some("https://vta.test".into());

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("DID resolver");

    let deps = ProvisionIntegrationDeps {
        keys_ks: ts.keys_ks.clone(),
        acl_ks: ts.acl_ks.clone(),
        audit_ks: ts.audit_ks.clone(),
        contexts_ks: ts.contexts_ks.clone(),
        did_templates_ks: ts.did_templates_ks.clone(),
        imported_ks: ts.imported_ks.clone(),
        webvh_ks: ts.webvh_ks.clone(),
        sealed_nonces_ks: ts.sealed_nonces_ks.clone(),
        seed_store: Arc::new(PlaintextSeedStore::new(&ts.data_dir)),
        config: Arc::new(RwLock::new(config)),
        did_resolver: Some(resolver),
        didcomm_bridge: Arc::new(DIDCommBridge::placeholder()),
    };
    (vta_did, deps)
}
