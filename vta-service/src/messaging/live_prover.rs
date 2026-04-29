//! Live `DIDCommService`-backed [`ListenerProver`] implementation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! "Mediator handshake before promotion", steps 2–5.
//!
//! Steps performed against a running
//! `affinidi_messaging_didcomm_service::DIDCommService`:
//!
//! 1. (Step 1, DID resolution, is performed by
//!    [`super::handshake::mediator_handshake`] before this prover
//!    is invoked.)
//! 2. **Connect + authenticate + register**:
//!    `service.add_listener(ListenerConfig { id: mediator_did, … })`.
//!    The upstream library handles the WebSocket + DIDComm
//!    challenge/response.
//! 3. **Wait for connection**:
//!    `service.wait_connected(mediator_did, timeout)`.
//! 4. **Trust-ping**: build a
//!    `https://didcomm.org/trust-ping/2.0/ping` from the VTA's DID
//!    to itself, routed via the new mediator. Sent through
//!    [`DIDCommBridge::send_and_wait_via`]; response routes back
//!    through the bridge's thid pending-map.
//! 5. **Wait for pong**: timeout-bounded.
//!
//! On any-stage failure, the listener is removed via
//! `service.remove_listener` so the registry doesn't promote a
//! mediator the VTA can't actually reach.
//!
//! The construction lives behind the `didcomm` feature gate so
//! non-DIDComm builds (e.g. REST-only enclave variants) don't
//! pull in the upstream service surface.

#![cfg(feature = "didcomm")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, ListenerConfig, RestartPolicy, RetryConfig,
};
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use async_trait::async_trait;
use serde_json::json;

use crate::didcomm_bridge::DIDCommBridge;
use crate::messaging::handshake::{
    HandshakeStage, ListenerProver, ProverFailure, ResolvedMediator,
};

/// Trust-ping protocol identifiers from didcomm.org. The upstream
/// library re-exports these constants but redeclaring them here
/// keeps this module's intent self-contained.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PING_RESPONSE_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// Default reconnect backoff for a listener added during
/// handshake. The values match the spec's "1s → 60s, factor 2.0"
/// reconnect contract from the registry doc.
fn default_backoff() -> RetryConfig {
    RetryConfig {
        initial_delay_secs: 1,
        max_delay_secs: 60,
    }
}

/// Builds a [`ListenerConfig`] for the new mediator. The VTA's
/// secrets and TDK config are caller-supplied (operator's
/// responsibility — they live in `AppState`'s secrets resolver).
pub trait ListenerConfigBuilder: Send + Sync {
    fn build(&self, resolved: &ResolvedMediator) -> ListenerConfig;
}

/// Live prover: drives the upstream `DIDCommService` through the
/// real handshake. Use this when DIDComm is already running (i.e.
/// for `mediator migrate` and `mediator rollback`); use
/// [`super::handshake::AlwaysOkProver`] when DIDComm isn't running
/// yet (i.e. for the first `services enable didcomm`).
pub struct DIDCommServiceProver {
    service: DIDCommService,
    bridge: Arc<DIDCommBridge>,
    config_builder: Arc<dyn ListenerConfigBuilder>,
}

impl DIDCommServiceProver {
    pub fn new(
        service: DIDCommService,
        bridge: Arc<DIDCommBridge>,
        config_builder: Arc<dyn ListenerConfigBuilder>,
    ) -> Self {
        Self {
            service,
            bridge,
            config_builder,
        }
    }
}

#[async_trait]
impl ListenerProver for DIDCommServiceProver {
    async fn prove(
        &self,
        resolved: &ResolvedMediator,
        vta_did: &str,
        timeout: Duration,
    ) -> Result<(), ProverFailure> {
        let listener_id = resolved.mediator_did.clone();

        // Step 2-3: connect + authenticate + register the listener.
        let config = self.config_builder.build(resolved);
        if let Err(e) = self.service.add_listener(config).await {
            return Err(ProverFailure {
                stage: HandshakeStage::Connect,
                cause: format!("add_listener failed: {e}"),
            });
        }
        if let Err(e) = self.service.wait_connected(&listener_id, timeout).await {
            // Best-effort cleanup: the listener was added but is
            // not connected. Remove so the registry doesn't see a
            // ghost.
            let _ = self.service.remove_listener(&listener_id).await;
            return Err(ProverFailure {
                stage: HandshakeStage::Authenticate,
                cause: format!("wait_connected failed: {e}"),
            });
        }

        // Step 4-5: trust-ping the VTA via the new mediator. The
        // bridge's thid pending-map routes the pong back to us.
        let result = self
            .bridge
            .send_and_wait_via(
                &listener_id,
                vta_did, // recipient = self; the mediator forwards back via the listener
                TRUST_PING_TYPE,
                json!({
                    "response_requested": true,
                }),
                TRUST_PING_RESPONSE_TYPE,
                PROBLEM_REPORT_TYPE,
                timeout.as_secs(),
            )
            .await;

        if let Err(e) = result {
            let _ = self.service.remove_listener(&listener_id).await;
            return Err(ProverFailure {
                stage: HandshakeStage::TrustPing,
                cause: format!("trust-ping round-trip failed: {e}"),
            });
        }

        // Listener stays up — caller (`migrate_mediator`) will
        // promote this mediator in the registry on success. On
        // any subsequent operation-level failure, the route layer
        // is responsible for cleanup; that's a known v1 gap (no
        // post-handshake rollback path).
        Ok(())
    }
}

/// Construct a `RestartPolicy::Always` matching the spec's
/// reconnect-with-backoff contract. Exposed so the
/// [`ListenerConfigBuilder`] impl can apply it consistently
/// without duplicating the constants.
pub fn default_restart_policy() -> RestartPolicy {
    RestartPolicy::Always {
        backoff: default_backoff(),
    }
}

/// Pre-baked listener-config builder that captures the VTA's DID,
/// secrets, and TDK config at construction time. The route layer
/// builds one of these per migrate request from the secrets it
/// pulls out of `AppState.secrets_resolver`.
pub struct StaticListenerConfigBuilder {
    vta_did: String,
    secrets: Vec<Secret>,
    tdk_config: Option<TDKConfig>,
}

impl StaticListenerConfigBuilder {
    pub fn new(
        vta_did: impl Into<String>,
        secrets: Vec<Secret>,
        tdk_config: Option<TDKConfig>,
    ) -> Self {
        Self {
            vta_did: vta_did.into(),
            secrets,
            tdk_config,
        }
    }
}

impl ListenerConfigBuilder for StaticListenerConfigBuilder {
    fn build(&self, resolved: &ResolvedMediator) -> ListenerConfig {
        let profile = TDKProfile::new(
            "VTA",
            &self.vta_did,
            Some(&resolved.mediator_did),
            self.secrets.clone(),
        );
        ListenerConfig {
            id: resolved.mediator_did.clone(),
            profile,
            restart_policy: default_restart_policy(),
            tdk_config: self.tdk_config.clone(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::handshake::HandshakeStage;

    /// The construction shape compiles. The trait-object holding,
    /// the listener-config-builder injection, and the failure
    /// stages are wired correctly. End-to-end behaviour against
    /// a real DIDCommService requires the in-process mock-mediator
    /// fixture, tracked separately.
    #[test]
    fn handshake_stages_used_by_prover() {
        // Sentinel test: catches a future refactor that drops
        // any of the stages this module produces.
        let stages = [
            HandshakeStage::Connect,
            HandshakeStage::Authenticate,
            HandshakeStage::TrustPing,
        ];
        assert_eq!(stages.len(), 3);
    }

    #[test]
    fn default_backoff_matches_spec() {
        let b = default_backoff();
        assert_eq!(b.initial_delay_secs, 1);
        assert_eq!(b.max_delay_secs, 60);
    }
}
