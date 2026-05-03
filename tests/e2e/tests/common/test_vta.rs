//! VTA-side fixture for e2e tests.
//!
//! [`TestVta`] holds the minimum identity + resolver + telemetry surface
//! needed to drive VTA-side messaging operations (transient handshake,
//! live prover, etc.) without standing up the full `vta-service` HTTP
//! router. It deliberately does *not* allocate a fjall store, AppConfig,
//! webvh record, or DIDCommBridge — those come in when a test needs the
//! full `enable_didcomm` / `migrate` operations and pull `TestStore` /
//! `bootstrap_test_vta` from `vta_service::test_support` on top of this.
//!
//! Identity is `did:peer:2.*` with one Ed25519 verification key and one
//! X25519 key-agreement key, matching the shape the mediator's own
//! identity uses. The cache-sdk's built-in `PeerResolver` decodes both
//! locally — no DNS or network round trip during a test.
//!
//! # Usage
//!
//! ```ignore
//! let mediator = TestMediator::spawn().await.unwrap();
//! let vta = TestVta::spawn().await.unwrap();
//! let resolved = vta
//!     .run_transient_handshake(mediator.did(), HandshakeOptions::default())
//!     .await
//!     .unwrap();
//! assert_eq!(resolved.mediator_did, mediator.did());
//! ```

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use vta_service::messaging::handshake::{HandshakeError, HandshakeOptions, ResolvedMediator};
use vta_service::messaging::transient_handshake::{
    TransientHandshakeContext, run_transient_handshake,
};
use vti_common::telemetry::{RingBufferTelemetry, SharedTelemetrySink};

/// Errors returned by the VTA fixture itself (separate from operation
/// errors that come back from the VTA library).
#[derive(Debug, thiserror::Error)]
pub enum TestVtaError {
    #[error("did:peer generation failed: {0}")]
    DidGeneration(String),
    #[error("DID resolver init failed: {0}")]
    Resolver(String),
}

/// VTA-side fixture. Cheap to spawn (no I/O beyond key generation).
pub struct TestVta {
    /// `did:peer:2.*` identity for this VTA.
    pub did: String,
    /// Verification + key-agreement secrets, indexed by VM id.
    pub secrets: Vec<Secret>,
    /// DID resolver used for both VTA self-resolution and mediator
    /// resolution. The peer resolver is built-in and offline.
    pub resolver: DIDCacheClient,
    /// Ring-buffer telemetry sink — tests can downcast and inspect
    /// emitted events when the assertion needs to look at them.
    pub telemetry: SharedTelemetrySink,
}

impl TestVta {
    /// Mint a fresh `did:peer:2` and wire up a resolver + telemetry.
    pub async fn spawn() -> Result<Self, TestVtaError> {
        let (did, secrets) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .map_err(|e| TestVtaError::DidGeneration(e.to_string()))?;

        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .map_err(|e| TestVtaError::Resolver(e.to_string()))?;

        let telemetry: SharedTelemetrySink = Arc::new(RingBufferTelemetry::new());

        Ok(Self {
            did,
            secrets,
            resolver,
            telemetry,
        })
    }

    /// Run the transient mediator handshake against `mediator_did`.
    /// Spins up an in-memory `DIDCommService`, drives steps 1–5 of the
    /// handshake, tears the service down on success or failure.
    pub async fn run_transient_handshake(
        &self,
        mediator_did: &str,
        opts: HandshakeOptions,
    ) -> Result<ResolvedMediator, HandshakeError> {
        let ctx = TransientHandshakeContext {
            vta_did: self.did.clone(),
            secrets: self.secrets.clone(),
            tdk_config: None,
        };
        run_transient_handshake(ctx, &self.resolver, &self.telemetry, mediator_did, opts).await
    }
}
