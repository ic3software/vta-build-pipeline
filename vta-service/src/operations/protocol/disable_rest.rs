//! `disable_rest` operation.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.2,
//! §3.4.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.rest` is currently `true` AND a `#vta-rest`
//!    entry exists in the DID document — refuse with
//!    [`DisableRestError::ServiceNotPresent`] otherwise.
//! 3. Brick-prevention via
//!    [`would_violate_last_service`] — refuse with
//!    [`DisableRestError::LastServiceRefused`] when DIDComm is
//!    also disabled (VTA would have no advertised transport).
//! 4. Read the prior URL from the on-chain DID document for the
//!    snapshot.
//! 5. Persist a [`RestSnapshot::Enabled { url: prior_url }`]
//!    snapshot before the runtime mutation, per spec §3.5a — a
//!    future rollback re-enables REST at the same URL.
//! 6. Patch the document — remove the `#vta-rest` entry via
//!    [`without_rest_service`] — and publish via
//!    [`update_did_webvh`].
//! 7. Persist `services.rest = false` to the config file.
//! 8. Emit [`TelemetryKind::ServicesRestDisable`].
//!
//! REST has no drain semantics — there's nothing to keep listening
//! for after the URL is unadvertised. The Axum process stays running
//! (it's a process-level binding), so the local CLI can still reach
//! the VTA; only the *advertisement* is removed.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::error::VtaError;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::PROTOCOL_LOCK;
use crate::operations::protocol::document::{
    DocumentPatchError, current_rest_service, without_rest_service,
};
use crate::operations::protocol::invariant::{
    CurrentServices, ProposedOp, would_violate_last_service,
};
use crate::operations::protocol::snapshot::{
    self, RestSnapshot, ServiceConfigSnapshot, ServiceKind,
};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

#[derive(Debug, Clone, Default)]
pub struct DisableRestParams;

#[derive(Debug, Clone)]
pub struct DisableRestResult {
    pub new_version_id: String,
    /// Pre-disable URL — recorded so callers / telemetry / audit
    /// can graph what was just unadvertised.
    pub prior_url: String,
}

#[derive(Debug, Error)]
pub enum DisableRestError {
    #[error("REST is not currently enabled — nothing to disable.")]
    ServiceNotPresent,
    #[error(
        "refusing operation: would leave the VTA with no advertised services. \
         Enable DIDComm first via `services didcomm enable --mediator <did>`, \
         then retry."
    )]
    LastServiceRefused,
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for DisableRestError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// Map [`VtaError::LastServiceRefused`] (from the invariant
/// helper) onto our typed variant. Other [`VtaError`] shapes
/// shouldn't surface here — the helper is total over its inputs —
/// but if one ever does we route it through `Storage` so it isn't
/// silently swallowed.
impl From<VtaError> for DisableRestError {
    fn from(value: VtaError) -> Self {
        match value {
            VtaError::LastServiceRefused => Self::LastServiceRefused,
            other => Self::Storage(other.to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn disable_rest(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    snapshot_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    telemetry: &SharedTelemetrySink,
    auth: &AuthClaims,
    _params: DisableRestParams,
    channel: &str,
) -> Result<DisableRestResult, DisableRestError> {
    auth.require_super_admin()
        .map_err(|e| DisableRestError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // 1. Read preconditions: REST must be on (config + on-chain).
    //    Capture the prior URL while we're at it for the snapshot
    //    + telemetry.
    let (vta_did, scid, current_doc, prior_url, didcomm_enabled) =
        read_preconditions(config, webvh_ks).await?;

    // 2. Brick-prevention. If DIDComm is also off, disabling REST
    //    leaves no transport advertised — refuse via the shared
    //    helper (T0.4). Single source of truth for spec §3.2; no
    //    --force escape hatch.
    would_violate_last_service(
        &CurrentServices::new(true, didcomm_enabled),
        ProposedOp::disable(ServiceKind::Rest),
    )?;

    // 3. Persist snapshot BEFORE the runtime mutation per spec
    //    §3.5a. Pre-state is RestSnapshot::Enabled with the prior
    //    URL — rollback re-enables REST at that URL.
    snapshot::write(
        snapshot_ks,
        ServiceConfigSnapshot::Rest(RestSnapshot::Enabled {
            url: prior_url.clone(),
        }),
    )
    .await
    .map_err(|e| DisableRestError::Storage(format!("snapshot write: {e}")))?;

    // 4. Patch the document — remove the #vta-rest entry.
    let patched = without_rest_service(current_doc);

    // 5. Publish via update_did_webvh.
    let update_result = update_did_webvh(
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        did_resolver,
        didcomm_bridge,
        channel,
    )
    .await?;

    // 6. Persist services.rest = false. Same risk window as the
    //    other ops if this fails after publish — operator retries.
    persist_rest_disabled(config).await?;

    // 7. Telemetry. Prior URL is included so an external verifier
    //    knows what URL just stopped being advertised.
    let _ = telemetry
        .record(
            TelemetryEvent::new(TelemetryKind::ServicesRestDisable)
                .with_field("channel", JsonValue::from(channel))
                .with_field(
                    "new_version_id",
                    JsonValue::from(update_result.new_version_id.clone()),
                )
                .with_field("prior_url", JsonValue::from(prior_url.clone())),
        )
        .await;

    info!(
        channel,
        prior_url = %prior_url,
        new_version_id = %update_result.new_version_id,
        vta_did = %vta_did,
        "REST disabled"
    );

    Ok(DisableRestResult {
        new_version_id: update_result.new_version_id,
        prior_url,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
) -> Result<(String, String, JsonValue, String, bool), DisableRestError> {
    let cfg = config.read().await;
    if !cfg.services.rest {
        return Err(DisableRestError::ServiceNotPresent);
    }
    let didcomm_enabled = cfg.services.didcomm;
    let vta_did = cfg
        .vta_did
        .clone()
        .ok_or(DisableRestError::VtaDidNotConfigured)?;
    drop(cfg);

    let record = webvh_store::get_did(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| DisableRestError::VtaDidRecordMissing(vta_did.clone()))?;
    let scid = record.scid.clone();

    let did_log = webvh_store::get_did_log(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| DisableRestError::VtaDidLogMissing(vta_did.clone()))?;
    let current_doc = current_document_from_log(&did_log)?;

    let prior_url = current_rest_service(&current_doc)
        .map(|s| s.url)
        .ok_or(DisableRestError::ServiceNotPresent)?;

    Ok((vta_did, scid, current_doc, prior_url, didcomm_enabled))
}

fn current_document_from_log(did_log: &str) -> Result<JsonValue, DisableRestError> {
    use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(DisableRestError::EmptyLog)?;
    let entry: LogEntry = serde_json::from_str(line)
        .map_err(|e| DisableRestError::Storage(format!("DID log line parse: {e}")))?;
    Ok(entry.get_state().clone())
}

async fn persist_rest_disabled(config: &Arc<RwLock<AppConfig>>) -> Result<(), DisableRestError> {
    let (contents, path) = {
        let mut cfg = config.write().await;
        cfg.services.rest = false;
        let contents = toml::to_string_pretty(&*cfg)
            .map_err(|e| DisableRestError::ConfigPersistence(e.to_string()))?;
        let path = cfg.config_path.clone();
        (contents, path)
    };
    std::fs::write(&path, contents)
        .map_err(|e| DisableRestError::ConfigPersistence(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogConfig, ServerConfig, ServicesConfig, StoreConfig};
    use crate::store::Store;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Mirrors the test fixture in enable_rest / update_rest —
    /// owns the fjall store so a single test can derive multiple
    /// keyspaces from the same handle.
    struct TestFixture {
        _dir: tempfile::TempDir,
        config: Arc<RwLock<AppConfig>>,
        store: Store,
    }

    impl TestFixture {
        fn webvh_ks(&self) -> KeyspaceHandle {
            self.store.keyspace("webvh").unwrap()
        }
    }

    fn build_fixture(rest_initially: bool, didcomm_initially: bool) -> TestFixture {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("vta.toml");
        let cfg = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
            },
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: dir.path().into(),
            },
            services: ServicesConfig {
                rest: rest_initially,
                didcomm: didcomm_initially,
            },
            vta_did: Some("did:webvh:scid123:host:vta".into()),
            vta_name: None,
            public_url: None,
            resolver_url: None,
            messaging: None,
            secrets: Default::default(),
            audit: Default::default(),
            auth: Default::default(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            config_path,
        };
        let initial = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&cfg.config_path, initial).unwrap();

        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        TestFixture {
            _dir: dir,
            config: Arc::new(RwLock::new(cfg)),
            store,
        }
    }

    #[tokio::test]
    async fn read_preconditions_rejects_when_rest_disabled() {
        let fx = build_fixture(false, true);
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, DisableRestError::ServiceNotPresent));
    }

    #[tokio::test]
    async fn read_preconditions_rejects_without_vta_did() {
        let fx = build_fixture(true, true);
        fx.config.write().await.vta_did = None;
        let err = read_preconditions(&fx.config, &fx.webvh_ks())
            .await
            .unwrap_err();
        assert!(matches!(err, DisableRestError::VtaDidNotConfigured));
    }

    /// The brick-prevention helper is wired correctly: invoking it
    /// from a "REST on, DIDComm off" state with a disable-rest op
    /// must surface as `LastServiceRefused`.
    #[test]
    fn brick_prevention_rejects_disable_rest_when_didcomm_off() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, false),
            ProposedOp::disable(ServiceKind::Rest),
        );
        let err = DisableRestError::from(result.unwrap_err());
        assert!(matches!(err, DisableRestError::LastServiceRefused));
    }

    /// Conversely, brick-prevention accepts disabling REST when
    /// DIDComm is on (S3 → S2).
    #[test]
    fn brick_prevention_allows_disable_rest_when_didcomm_on() {
        let result = would_violate_last_service(
            &CurrentServices::new(true, true),
            ProposedOp::disable(ServiceKind::Rest),
        );
        assert!(result.is_ok());
    }

    /// `persist_rest_disabled` writes services.rest = false to
    /// both the in-memory config and the on-disk file.
    #[tokio::test]
    async fn persist_rest_disabled_flips_config_to_false() {
        let fx = build_fixture(true, true);
        assert!(fx.config.read().await.services.rest);

        persist_rest_disabled(&fx.config).await.unwrap();

        assert!(!fx.config.read().await.services.rest);
        let on_disk = std::fs::read_to_string(&fx.config.read().await.config_path).unwrap();
        let reparsed: AppConfig = toml::from_str(&on_disk).unwrap();
        assert!(!reparsed.services.rest);
    }

    /// Confirms the typed `From<VtaError>` path: the helper's
    /// `LastServiceRefused` round-trips into our error variant
    /// correctly, and any other VtaError shape lands in `Storage`
    /// (defensive — the helper is total today, but the impl
    /// shouldn't drop unknown variants).
    #[test]
    fn vta_error_to_disable_rest_error_mapping_is_typed() {
        let mapped = DisableRestError::from(VtaError::LastServiceRefused);
        assert!(matches!(mapped, DisableRestError::LastServiceRefused));

        let mapped = DisableRestError::from(VtaError::ServiceNotPresent);
        assert!(matches!(mapped, DisableRestError::Storage(_)));
    }
}
