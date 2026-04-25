use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use tracing::{debug, info, warn};

use crate::error::VtaError;
use crate::protocols::PROBLEM_REPORT_TYPE;

// Per-step ceiling for mediator round-trips during session setup. The
// upstream calls below are otherwise unbounded — when the mediator is
// unreachable a CLI invocation can hang for the full TCP/TLS retry
// window (30–60s on macOS) before failing. 15s is generous for healthy
// mediators and keeps Ctrl-C responsive.
const MEDIATOR_OP_TIMEOUT: Duration = Duration::from_secs(15);

/// Client-side DIDComm session for request-response messaging via ATM.
///
/// Uses WebSocket streaming to receive responses from the mediator.
/// Designed for CLI tools that send a request and wait for a reply.
#[derive(Clone)]
pub struct DIDCommSession {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    pub(crate) client_did: String,
    pub(crate) vta_did: String,
}

impl DIDCommSession {
    /// Connect to a VTA via DIDComm through a mediator.
    ///
    /// Sets up the ATM and profile for REST-based messaging. Does NOT open a
    /// WebSocket — all communication goes through the mediator's REST API,
    /// avoiding connection storms when the CLI is invoked repeatedly.
    pub async fn connect(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Decode private key and build DIDComm secrets
        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        // Create TDK shared state and insert secrets
        let tdk = TDKSharedState::default().await;
        tdk.secrets_resolver.insert(secrets.signing).await;
        tdk.secrets_resolver.insert(secrets.key_agreement).await;

        // Build ATM (no inbound channel needed — we use REST polling)
        let atm_config = ATMConfig::builder().build()?;
        let atm = ATM::new(atm_config, Arc::new(tdk)).await?;

        // Create profile with mediator
        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        let atm = Arc::new(atm);

        // Flush stale messages from the inbox (accumulated between CLI runs)
        {
            use affinidi_tdk::messaging::messages::Folder;
            match tokio::time::timeout(
                MEDIATOR_OP_TIMEOUT,
                atm.list_messages(&profile, Folder::Inbox),
            )
            .await
            {
                Ok(Ok(messages)) if !messages.is_empty() => {
                    let ids: Vec<String> = messages.iter().map(|m| m.msg_id.clone()).collect();
                    info!(
                        count = ids.len(),
                        "flushing stale queued messages from inbox"
                    );
                    let delete_req = affinidi_tdk::messaging::messages::DeleteMessageRequest {
                        message_ids: ids,
                    };
                    match tokio::time::timeout(
                        MEDIATOR_OP_TIMEOUT,
                        atm.delete_messages_direct(&profile, &delete_req),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => {
                            debug!(
                                deleted = resp.success.len(),
                                errors = resp.errors.len(),
                                "inbox flushed"
                            );
                        }
                        Ok(Err(e)) => warn!("failed to flush stale messages (non-fatal): {e}"),
                        Err(_) => warn!(
                            "timeout flushing stale messages after {}s (non-fatal)",
                            MEDIATOR_OP_TIMEOUT.as_secs()
                        ),
                    }
                }
                Ok(Ok(_)) => {} // Empty inbox
                Ok(Err(e)) => warn!("could not list inbox (non-fatal): {e}"),
                Err(_) => warn!(
                    "timeout listing inbox after {}s (non-fatal)",
                    MEDIATOR_OP_TIMEOUT.as_secs()
                ),
            }
        }

        // Enable WebSocket for streaming message delivery from mediator.
        // Without this, the ATM can only poll via REST and may miss responses
        // that arrive after the initial send_message call returns.
        match tokio::time::timeout(MEDIATOR_OP_TIMEOUT, atm.profile_enable_websocket(&profile))
            .await
        {
            Ok(res) => res?,
            Err(_) => {
                return Err(format!(
                    "timeout enabling WebSocket to mediator after {}s — \
                     mediator may be unreachable",
                    MEDIATOR_OP_TIMEOUT.as_secs()
                )
                .into());
            }
        }

        debug!("DIDComm session connected via mediator {mediator_did} (WebSocket mode)");

        Ok(Self {
            atm,
            profile,
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
        })
    }

    /// Send a DIDComm message and wait for a matching response.
    ///
    /// Packs the message, sends it to the mediator, then uses the WebSocket
    /// live stream to wait for the response. This handles asynchronous
    /// processing where the VTA takes time to respond.
    ///
    /// Problem-report responses are decoded into typed [`VtaError`] variants
    /// based on their `e.p.msg.*` code so DIDComm and REST surface the same
    /// error taxonomy (conflict, not-found, auth, validation, server).
    pub async fn send_and_wait<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        expected_result_type: &str,
        timeout_secs: u64,
    ) -> Result<T, VtaError> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(self.client_did.clone())
            .to(self.vta_did.clone())
            .finalize();

        // Pack encrypted (signed + encrypted to recipient)
        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                &self.vta_did,
                Some(&self.client_did),
                Some(&self.client_did),
            )
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to pack message: {e}")))?;

        debug!(msg_type, msg_id, "sending via DIDComm");

        // Send the message (fire-and-forget to mediator, don't wait for response)
        self.atm
            .send_message(&self.profile, &packed, &msg_id, false, false)
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to send message: {e}")))?;

        // Wait for the response via WebSocket live stream
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let wait_duration = std::time::Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VtaError::DidcommTransport(
                    "timeout waiting for DIDComm response".into(),
                ));
            }
            let wait = wait_duration.min(remaining);

            let next = self
                .atm
                .message_pickup()
                .live_stream_next(&self.profile, Some(wait), true)
                .await
                .map_err(|e| VtaError::DidcommTransport(format!("message pickup error: {e}")))?;

            let (response_msg, _meta) = match next {
                Some(pair) => pair,
                None => continue, // No message yet, keep waiting
            };

            // Check if this is the response we're waiting for (matching thread ID)
            let response_thid = response_msg.thid.as_deref().unwrap_or("");
            if response_thid != msg_id {
                debug!(
                    response_thid,
                    expected = msg_id,
                    response_type = %response_msg.typ,
                    "received message with non-matching thread ID — skipping"
                );
                continue;
            }

            debug!(response_type = %response_msg.typ, "received DIDComm response");

            // Check for problem report — map the `e.p.msg.*` code to the
            // matching VtaError variant so callers can `match` on the same
            // error shapes they get from REST (see `VtaError::from_http`).
            if response_msg.typ == PROBLEM_REPORT_TYPE
                || response_msg.typ.contains("problem-report")
            {
                let code = response_msg
                    .body
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comment = response_msg
                    .body
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Err(problem_report_to_vta_error(code, comment));
            }

            // Verify expected type
            if response_msg.typ != expected_result_type {
                return Err(VtaError::Protocol(format!(
                    "unexpected response type: expected {expected_result_type}, got {}",
                    response_msg.typ
                )));
            }

            // Deserialize response body
            return serde_json::from_value(response_msg.body).map_err(VtaError::from);
        }
    }

    /// Gracefully shut down the DIDComm session.
    pub async fn shutdown(&self) {
        self.atm.graceful_shutdown().await;
    }
}

/// Map a DIDComm problem-report `code` to the matching [`VtaError`] variant.
///
/// Mirrors the HTTP → VtaError mapping in [`VtaError::from_http`] so a caller
/// can use the same `match` arms whether it talks REST or DIDComm.
fn problem_report_to_vta_error(code: &str, comment: String) -> VtaError {
    use crate::protocols::problem_report_codes as c;
    match code {
        c::CONFLICT => VtaError::Conflict(comment),
        c::NOT_FOUND => VtaError::NotFound(comment),
        c::UNAUTHORIZED => VtaError::Auth(comment),
        c::BAD_REQUEST => VtaError::Validation(comment),
        c::INTERNAL => VtaError::Server {
            status: 500,
            body: comment,
        },
        other => VtaError::DidcommRemote {
            code: other.to_string(),
            comment,
        },
    }
}
