//! Client surface for DIDComm protocol management.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `enable_didcomm` (REST-only by nature — DIDComm is
//! not yet running at first-enable time). The disable / migrate /
//! drain-cancel / report calls — and their DIDComm transport
//! handlers — arrive in Phase 4 verticals.

use serde::{Deserialize, Serialize};

use crate::client::VtaClient;
use crate::error::VtaError;

/// Request body for `POST /services/didcomm/enable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableDidcommRequest {
    pub mediator_did: String,
    /// Skip handshake steps 2-5 (DID resolution always runs).
    /// Emits a `MediatorHandshakeBypassed` telemetry event when set.
    #[serde(default)]
    pub force: bool,
    /// Trust-ping round-trip timeout (default: 10 seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
}

impl EnableDidcommRequest {
    pub fn new(mediator_did: impl Into<String>) -> Self {
        Self {
            mediator_did: mediator_did.into(),
            force: false,
            handshake_timeout_secs: None,
        }
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn handshake_timeout_secs(mut self, secs: u64) -> Self {
        self.handshake_timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableDidcommResponse {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
}

impl VtaClient {
    /// Enable DIDComm on a REST-only VTA. Spec: success criterion #1.
    ///
    /// The VTA must be configured with a vta_did, must currently
    /// have `services.didcomm = false`, and the caller must have
    /// super-admin role. On success, the VTA publishes a new WebVH
    /// LogEntry advertising the mediator and registers it as
    /// active.
    ///
    /// **Phase 3 limitation:** the live mediator handshake (steps
    /// 2-5) requires a running `DIDCommService`, which doesn't
    /// exist yet at first-enable. This call therefore bypasses
    /// steps 2-5; the connection is validated implicitly when the
    /// DIDComm runtime starts up after the next service restart.
    /// To validate a mediator pre-publish today, run
    /// `pnm services enable didcomm` followed by
    /// `pnm mediator migrate --to <same>` — the migrate path runs
    /// the full handshake.
    pub async fn enable_didcomm(
        &self,
        req: EnableDidcommRequest,
    ) -> Result<EnableDidcommResponse, VtaError> {
        // REST-only by nature. Calling this over DIDComm transport
        // will surface as a 404 from the upstream message router,
        // which the rpc() layer turns into a `VtaError::Protocol`.
        // That's the right behaviour — the operation is logically
        // not available over DIDComm transport.
        self.rpc(
            "services-management/1.0/enable-not-available-via-didcomm",
            serde_json::to_value(&req)?,
            "services-management/1.0/enable-not-available-via-didcomm-result",
            30,
            |c, url| c.post(format!("{url}/services/didcomm/enable")).json(&req),
        )
        .await
    }
}
