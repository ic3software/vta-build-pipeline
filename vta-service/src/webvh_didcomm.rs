//! DIDComm transport for webvh server operations.
//!
//! ## Why this is *not* a mirror of `webvh_client.rs`
//!
//! The REST sibling (`crate::webvh_client::WebvhClient`) carries:
//! - explicit signing identity for the daemon challenge/response flow,
//! - typed errors with operator-facing hints (401 vs 403 split),
//! - HTTPS enforcement on the dialed URL,
//! - audience binding via the DIDComm `to:` field.
//!
//! This module deliberately carries none of those. It's not an
//! oversight — DIDComm authcrypt already gives us the equivalents
//! at the envelope layer:
//!
//! - **Signing identity** — the `DIDCommBridge` packs every outbound
//!   message with the VTA's existing DIDComm sender key; the daemon
//!   verifies it via `unpack_signed` exactly the same way it verifies
//!   the JWS-over-REST envelope.
//! - **Audience binding** — DIDComm messages are addressed to a
//!   specific `to:` DID intrinsically; replay against a different
//!   daemon fails because the message is encrypted to *this* daemon's
//!   key-agreement key.
//! - **Typed errors** — DIDComm replies carry `e.p.msg.*`
//!   problem-report codes which the SDK maps to typed `VtaError`
//!   variants via `VtaError::from_problem_report`. The CLI surfaces
//!   them with the same hint discipline as the REST path.
//! - **Transport security** — DIDComm over the mediator is
//!   end-to-end encrypted regardless of the underlying socket; there
//!   is no plaintext-leak surface to defend at this layer.
//!
//! **Do not "add parity" by porting the JWS-flow primitives into
//! this module.** They would duplicate what authcrypt already
//! provides, and the duplicate would drift out of sync with the
//! envelope-layer guarantees.

use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::webvh_client::RequestUriResponse;

// WebVH DIDComm protocol message types
const MSG_DID_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/request";
const MSG_DID_OFFER: &str = "https://affinidi.com/webvh/1.0/did/offer";
const MSG_DID_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/publish";
const MSG_DID_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/confirm";
const MSG_DID_REGISTER: &str = "https://affinidi.com/webvh/1.0/did/register";
const MSG_DID_REGISTER_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/register-confirm";
const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
const MSG_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/did/problem-report";

/// DIDComm-based client for communicating with a WebVH server.
///
/// Routes messages through the DIDComm service's listener connection,
/// avoiding duplicate WebSocket connections to the mediator.
pub struct WebvhDIDCommClient<'a> {
    bridge: &'a DIDCommBridge,
    server_did: &'a str,
}

impl<'a> WebvhDIDCommClient<'a> {
    pub fn new(bridge: &'a DIDCommBridge, server_did: &'a str) -> Self {
        Self { bridge, server_did }
    }

    /// Request a URI allocation from the WebVH server.
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };

        let response = self
            .bridge
            .send_and_wait(
                self.server_did,
                MSG_DID_REQUEST,
                body,
                MSG_DID_OFFER,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;

        serde_json::from_value(response.body)
            .map_err(|e| AppError::Internal(format!("failed to parse did/offer response: {e}")))
    }

    /// Atomic claim-and-publish — see [`crate::webvh_client::WebvhClient::register_did_atomic`].
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
    ) -> Result<RequestUriResponse, AppError> {
        let body = serde_json::json!({
            "path": path,
            "did_log": did_log,
            "force": force,
        });

        let response = self
            .bridge
            .send_and_wait(
                self.server_did,
                MSG_DID_REGISTER,
                body,
                MSG_DID_REGISTER_CONFIRM,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;

        serde_json::from_value(response.body).map_err(|e| {
            AppError::Internal(format!(
                "failed to parse did/register-confirm response: {e}"
            ))
        })
    }

    /// Publish a DID log to the WebVH server.
    pub async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        let body = serde_json::json!({
            "mnemonic": mnemonic,
            "did_log": log_content,
        });

        self.bridge
            .send_and_wait(
                self.server_did,
                MSG_DID_PUBLISH,
                body,
                MSG_DID_CONFIRM,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }

    /// Delete a DID from the WebVH server.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let body = serde_json::json!({ "mnemonic": mnemonic });

        self.bridge
            .send_and_wait(
                self.server_did,
                MSG_DELETE,
                body,
                MSG_DELETE_CONFIRM,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }
}
