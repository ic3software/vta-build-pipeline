//! `register_did_with_server` — promote a serverless WebVH DID to a
//! server-managed one without re-issuing the DID identifier.
//!
//! Use case: an operator brings up a VTA in serverless mode (so the
//! DID exists locally and they publish `did.jsonl` manually or not
//! at all), then later stands up a webvh hosting server and wants
//! the VTA to publish there. Re-running setup would mint a new DID
//! with a different SCID, breaking every integration that already
//! references the existing DID. This op flips the DID's
//! `server_id` from `"serverless"` to a registered server in place,
//! pushes the existing log to the new host, and leaves the DID
//! identifier untouched.
//!
//! Invariants:
//! - DID must currently be serverless. Re-pointing a server-managed
//!   DID at a different host is a separate operation (would require
//!   coordinating teardown on the old host).
//! - Target server must already be registered via `add_webvh_server`.
//! - Local `did.jsonl` is the source of truth and is pushed
//!   verbatim; the host's prior content (if any) is overwritten.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use didwebvh_rs::url::WebVHURL;
use thiserror::Error;
use tracing::info;

use crate::audit;
use crate::auth::AuthClaims;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

use super::WebvhTransport;

/// `server_id` value stored on a DID record that has not yet been
/// associated with a webvh hosting server. Mirrors the literal used
/// in `create_did_webvh` and `update_did_webvh`.
const SERVERLESS_MARKER: &str = "serverless";

#[derive(Debug, Clone)]
pub struct RegisterDidWithServerParams {
    pub did: String,
    pub server_id: String,
}

#[derive(Debug, Clone)]
pub struct RegisterDidWithServerResult {
    pub did: String,
    pub server_id: String,
    /// Number of log entries pushed to the host (informational —
    /// equals the local log's entry count).
    pub log_entry_count: u32,
}

#[derive(Debug, Error)]
pub enum RegisterDidWithServerError {
    #[error("auth: {0}")]
    Auth(String),
    #[error("DID not found: {0}")]
    DidNotFound(String),
    #[error(
        "DID `{did}` is already managed by webvh server `{server_id}`. \
         Re-pointing a server-managed DID at a different host is not supported \
         — only serverless DIDs can be registered."
    )]
    AlreadyServerManaged { did: String, server_id: String },
    #[error(
        "webvh server `{0}` is not registered. \
         Add it first with `pnm webvh add-server --id {0} --did <server-did>`."
    )]
    ServerNotFound(String),
    #[error("DID `{0}` has no published log on disk (cannot push to server)")]
    LogMissing(String),
    #[error("transport setup failed: {0}")]
    Transport(String),
    #[error("publish to server failed: {0}")]
    Publish(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error(
        "server allocated `{allocated}` but DID resolves at `{expected}`. \
         The path component is likely already claimed on this host — \
         choose a different webvh server, or have the host operator \
         release that path."
    )]
    PathAllocationMismatch { allocated: String, expected: String },
    #[error("could not derive URL from DID `{did}`: {reason}")]
    DidUrlParse { did: String, reason: String },
}

impl From<AppError> for RegisterDidWithServerError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// Push an existing serverless DID's log to a registered webvh
/// server and flip the local record's `server_id` so future
/// `update_did_webvh` calls (and therefore future `services`
/// mutations) auto-publish there.
pub async fn register_did_with_server(
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    params: RegisterDidWithServerParams,
    channel: &str,
) -> Result<RegisterDidWithServerResult, RegisterDidWithServerError> {
    auth.require_super_admin()
        .map_err(|e| RegisterDidWithServerError::Auth(e.to_string()))?;

    // 1. Look up the DID record. Refuse if not found, or if already
    //    server-managed.
    let mut record = webvh_store::get_did(webvh_ks, &params.did)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::DidNotFound(params.did.clone()))?;

    if record.server_id != SERVERLESS_MARKER {
        return Err(RegisterDidWithServerError::AlreadyServerManaged {
            did: params.did.clone(),
            server_id: record.server_id.clone(),
        });
    }

    // 2. Look up the target server.
    let server = webvh_store::get_server(webvh_ks, &params.server_id)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::ServerNotFound(params.server_id.clone()))?;

    // 3. Read the local did.jsonl. Source of truth for the push.
    let did_log = webvh_store::get_did_log(webvh_ks, &params.did)
        .await?
        .ok_or_else(|| RegisterDidWithServerError::LogMissing(params.did.clone()))?;

    // 4. Build the transport for the target server (REST or DIDComm
    //    depending on the server DID's advertised endpoints).
    let transport = WebvhTransport::from_server(&server, did_resolver, didcomm_bridge)
        .await
        .map_err(|e| RegisterDidWithServerError::Transport(e.to_string()))?;

    // 5. The serverless DID has no mnemonic (it was minted with one
    //    artifact: a local `did.jsonl`, no host involvement). Ask the
    //    target host to allocate a slot for the DID's *existing* path
    //    component — same path the DID identifier already resolves at —
    //    and use the freshly-issued mnemonic to publish.
    //
    //    `WebVHURL::parse_did_url` returns `path` with leading and
    //    trailing slashes (`/glenn-vta/`). The host's `request_uri`
    //    expects the path without slashes; an empty/`.well-known/`
    //    path gets passed as `None` so the server applies its default.
    let parsed = WebVHURL::parse_did_url(&params.did).map_err(|e| {
        RegisterDidWithServerError::DidUrlParse {
            did: params.did.clone(),
            reason: e.to_string(),
        }
    })?;
    let trimmed_path = parsed.path.trim_matches('/');
    let request_path = if trimmed_path.is_empty() || trimmed_path == ".well-known" {
        None
    } else {
        Some(trimmed_path)
    };

    let uri_response = transport
        .request_uri(request_path)
        .await
        .map_err(|e| RegisterDidWithServerError::Publish(format!("request_uri: {e}")))?;

    // Verify the host allocated the URL the DID already resolves at.
    // If the path is taken, the server allocates a different one — we
    // refuse rather than silently break resolution. The expected URL
    // mirrors `WebvhServer::published_did_url` shape: scheme + host
    // (+ port) + path + `did.jsonl`.
    let port_segment = parsed.port.map(|p| format!(":{p}")).unwrap_or_default();
    let expected_url = format!(
        "https://{host}{port}{path}did.jsonl",
        host = parsed.domain,
        port = port_segment,
        path = parsed.path,
    );
    if uri_response.did_url != expected_url {
        return Err(RegisterDidWithServerError::PathAllocationMismatch {
            allocated: uri_response.did_url,
            expected: expected_url,
        });
    }

    transport
        .publish_did(&uri_response.mnemonic, &did_log)
        .await
        .map_err(|e| RegisterDidWithServerError::Publish(e.to_string()))?;

    // 6. Flip `server_id` on the local record AND persist the
    //    server-issued mnemonic. From here on, `update_did_webvh` will
    //    treat this as a server-managed DID and auto-publish on every
    //    subsequent change (including the `services` runtime mutations)
    //    using this mnemonic.
    record.server_id = params.server_id.clone();
    record.mnemonic = uri_response.mnemonic;
    record.updated_at = Utc::now();
    let log_entry_count = record.log_entry_count;
    webvh_store::store_did(webvh_ks, &record).await?;

    // 6. Audit. Best-effort; log+swallow on error.
    let resource = format!("did:webvh:{}", record.scid);
    if let Err(e) = audit::record(
        audit_ks,
        "did.register_server",
        &auth.did,
        Some(&resource),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await
    {
        tracing::warn!(error = %e, "audit emission failed for did.register_server");
    }

    info!(
        channel,
        did = %record.did,
        server_id = %record.server_id,
        log_entry_count,
        "did:webvh registered with server"
    );

    Ok(RegisterDidWithServerResult {
        did: record.did,
        server_id: record.server_id,
        log_entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::test_support::test_app_config;
    use vta_sdk::webvh::{WebvhDidRecord, WebvhServerRecord};
    use vti_common::config::StoreConfig as VtiStoreConfig;

    async fn setup() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let webvh_ks = store.keyspace("webvh").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        // Force the test_app_config helper to be exercised so any
        // future field addition surfaces as a test failure.
        let _ = test_app_config(dir.path().into());
        (dir, webvh_ks, audit_ks)
    }

    fn serverless_record(did: &str) -> WebvhDidRecord {
        let now = chrono::Utc::now();
        WebvhDidRecord {
            did: did.into(),
            server_id: "serverless".into(),
            mnemonic: "test-mnemonic".into(),
            scid: "scid".into(),
            context_id: "vta".into(),
            portable: true,
            log_entry_count: 1,
            pre_rotation_count: 0,
            next_fragment_id: 1,
            created_at: now,
            updated_at: now,
        }
    }

    fn server_record(id: &str) -> WebvhServerRecord {
        let now = chrono::Utc::now();
        WebvhServerRecord {
            id: id.into(),
            did: format!("did:web:{id}.example"),
            label: None,
            access_token: None,
            access_expires_at: None,
            refresh_token: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn super_admin() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    fn other_user() -> AuthClaims {
        use vti_common::acl::Role;
        AuthClaims {
            did: "did:key:z6Mk-test".into(),
            role: Role::Admin,
            allowed_contexts: vec!["vta".into()],
        }
    }

    /// Concrete instances aren't used in unit tests because building
    /// a real `DIDCacheClient` requires network/cache state. The
    /// preflight checks (auth, DID lookup, server lookup, log
    /// presence, already-server-managed) all fire before transport
    /// is constructed, so we exercise them here. The transport
    /// happy path is covered by the integration test in
    /// tests/api_integration.rs.
    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap()
    }

    fn bridge() -> Arc<DIDCommBridge> {
        Arc::new(DIDCommBridge::placeholder())
    }

    #[tokio::test]
    async fn rejects_non_super_admin() {
        let (_dir, webvh_ks, audit_ks) = setup().await;
        let resolver = resolver().await;
        let bridge = bridge();
        let err = register_did_with_server(
            &webvh_ks,
            &audit_ks,
            &other_user(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: "did:webvh:scid:host:vta".into(),
                server_id: "primary".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::Auth(_)));
    }

    #[tokio::test]
    async fn rejects_when_did_not_found() {
        let (_dir, webvh_ks, audit_ks) = setup().await;
        let resolver = resolver().await;
        let bridge = bridge();
        let err = register_did_with_server(
            &webvh_ks,
            &audit_ks,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: "did:webvh:nonexistent:host:vta".into(),
                server_id: "primary".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::DidNotFound(_)));
    }

    #[tokio::test]
    async fn rejects_when_already_server_managed() {
        let (_dir, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        let mut rec = serverless_record(did);
        rec.server_id = "existing-host".into();
        webvh_store::store_did(&webvh_ks, &rec).await.unwrap();

        let resolver = resolver().await;
        let bridge = bridge();
        let err = register_did_with_server(
            &webvh_ks,
            &audit_ks,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "primary".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            RegisterDidWithServerError::AlreadyServerManaged { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_when_server_not_registered() {
        let (_dir, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        webvh_store::store_did(&webvh_ks, &serverless_record(did))
            .await
            .unwrap();
        webvh_store::store_did_log(&webvh_ks, did, "{}\n")
            .await
            .unwrap();

        let resolver = resolver().await;
        let bridge = bridge();
        let err = register_did_with_server(
            &webvh_ks,
            &audit_ks,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "missing-host".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::ServerNotFound(_)));
    }

    #[tokio::test]
    async fn rejects_when_log_missing() {
        let (_dir, webvh_ks, audit_ks) = setup().await;
        let did = "did:webvh:scid:host:vta";
        webvh_store::store_did(&webvh_ks, &serverless_record(did))
            .await
            .unwrap();
        webvh_store::store_server(&webvh_ks, &server_record("primary"))
            .await
            .unwrap();
        // Note: no `store_did_log` call.

        let resolver = resolver().await;
        let bridge = bridge();
        let err = register_did_with_server(
            &webvh_ks,
            &audit_ks,
            &super_admin(),
            &resolver,
            &bridge,
            RegisterDidWithServerParams {
                did: did.into(),
                server_id: "primary".into(),
            },
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegisterDidWithServerError::LogMissing(_)));
    }
}
