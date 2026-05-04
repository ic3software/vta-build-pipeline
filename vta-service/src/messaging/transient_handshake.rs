//! Transient `DIDCommService` for first-enable handshake.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! "Mediator handshake before promotion".
//!
//! At first-enable time the main `DIDCommService` isn't running
//! (services.didcomm = false), so the live prover used by
//! `migrate` can't be reused. This module spins up a minimal
//! transient service just for the handshake round-trip:
//!
//! 1. Build a stripped-down `BridgeHandler` with a fresh bridge —
//!    just enough router surface to route the trust-ping pong via
//!    the bridge's pending-map. No VtaState needed.
//! 2. Start `DIDCommService` with an empty listener config and
//!    a fresh cancellation token.
//! 3. Hand to [`DIDCommServiceProver`] which runs steps 2-5
//!    against this transient service.
//! 4. Cancel the token so the service tears down.
//!
//! On success or failure, the transient service is shut down
//! before returning. The caller (`enable_didcomm`) then publishes
//! the LogEntry and persists `services.didcomm = true`; the next
//! service restart starts the "real" main service which re-
//! connects to the now-active mediator.

#![cfg(all(feature = "webvh", feature = "didcomm"))]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommHandler, DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError,
    HandlerContext, Router, TRUST_PING_TYPE, handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use vti_common::telemetry::SharedTelemetrySink;

use crate::didcomm_bridge::DIDCommBridge;
use crate::messaging::handshake::{
    HandshakeError, HandshakeOptions, ResolvedMediator, mediator_handshake,
};
use crate::messaging::live_prover::{DIDCommServiceProver, StaticListenerConfigBuilder};

/// Caller-supplied bits the transient service needs to authenticate
/// the VTA's DID to the new mediator.
pub struct TransientHandshakeContext {
    pub vta_did: String,
    pub secrets: Vec<Secret>,
    pub tdk_config: Option<TDKConfig>,
}

/// Run the full handshake against a freshly-spun-up transient
/// `DIDCommService`. Returns `Ok(ResolvedMediator)` on success
/// (caller can use the resolved endpoint for telemetry/registry).
/// Always tears down the transient service before returning,
/// regardless of outcome.
pub async fn run_transient_handshake(
    ctx: TransientHandshakeContext,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    telemetry: &SharedTelemetrySink,
    mediator_did: &str,
    opts: HandshakeOptions,
) -> Result<ResolvedMediator, HandshakeError> {
    // Fresh bridge for this handshake. Starts with no listeners;
    // `add_listener` is called by the prover during step 2.
    let bridge = Arc::new(DIDCommBridge::new(mediator_did));

    let handler = match build_transient_handler(Arc::clone(&bridge)) {
        Ok(h) => h,
        Err(e) => {
            return Err(HandshakeError::Failed {
                stage: crate::messaging::handshake::HandshakeStage::Connect,
                cause: format!("transient handler build failed: {e}"),
            });
        }
    };

    let shutdown = CancellationToken::new();
    let service_config = DIDCommServiceConfig { listeners: vec![] };
    let service = match DIDCommService::start(service_config, handler, shutdown.clone()).await {
        Ok(s) => s,
        Err(e) => {
            return Err(HandshakeError::Failed {
                stage: crate::messaging::handshake::HandshakeStage::Connect,
                cause: format!("transient DIDCommService::start failed: {e}"),
            });
        }
    };
    bridge.set_service(service.clone());

    // Build the live prover against the transient service.
    let config_builder = Arc::new(StaticListenerConfigBuilder::new(
        &ctx.vta_did,
        ctx.secrets,
        ctx.tdk_config,
    ));
    let prover = DIDCommServiceProver::new(service.clone(), Arc::clone(&bridge), config_builder);

    let result = mediator_handshake(
        resolver,
        &prover,
        telemetry,
        mediator_did,
        &ctx.vta_did,
        opts,
    )
    .await;

    // Tear down the transient service. The CancellationToken is
    // the documented shutdown signal; service.shutdown() does the
    // same thing more verbosely.
    shutdown.cancel();
    // Give the transient task a brief window to drop its
    // listener cleanly. This isn't strictly required for
    // correctness — the service will tear down on its own — but
    // it stops a stray-listener warning from racing the next
    // event log.
    tokio::time::sleep(Duration::from_millis(50)).await;

    result
}

/// Minimal `BridgeHandler`-equivalent for the transient handshake.
/// The full `BridgeHandler` requires `VtaState` to power the
/// inner router; for handshake we don't need any of that — just
/// trust-ping and a fallback that ignores everything else (the
/// trust-ping pong arrives on the listener and is routed via
/// `bridge.try_complete` before reaching any handler anyway).
fn build_transient_handler(
    bridge: Arc<DIDCommBridge>,
) -> Result<TransientBridgeHandler, DIDCommServiceError> {
    let router = Router::new()
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .fallback(handler_fn(ignore_handler));
    Ok(TransientBridgeHandler {
        inner: router,
        bridge,
    })
}

struct TransientBridgeHandler {
    inner: Router,
    bridge: Arc<DIDCommBridge>,
}

#[async_trait::async_trait]
impl DIDCommHandler for TransientBridgeHandler {
    async fn handle(
        &self,
        ctx: HandlerContext,
        message: Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
    ) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
        // Route the trust-ping pong via the bridge's pending map
        // before falling through to the router.
        if self.bridge.try_complete(&message) {
            return Ok(None);
        }
        // Log unexpected inbound traffic during handshake.
        if message.thid.is_some() {
            warn!(
                msg_type = %message.typ,
                "transient-handshake: unmatched response (stale or unrelated)"
            );
        }
        self.inner.handle(ctx, message, meta).await
    }
}

#[cfg(test)]
mod tests {
    use crate::messaging::handshake::HandshakeStage;

    /// Sentinel: the construction shape compiles. End-to-end
    /// behaviour requires a mock mediator (deferred).
    #[test]
    fn transient_handshake_module_compiles() {
        // Touch each named type to ensure refactors don't drop
        // the public surface this module is meant to expose.
        let _stage = HandshakeStage::Resolve;
    }
}
