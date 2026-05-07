//! DIDComm transport for `provision-integration`.
//!
//! Holder side. Sends a VP-framed [`super::BootstrapRequest`] over an
//! authcrypt'd DIDComm session and receives the sealed
//! `TemplateBootstrap` bundle in the reply. Wire shapes are
//! transport-neutral — the payload that arrives is the same armored
//! bundle the REST endpoint returns.
//!
//! Use this when the holder already has a DIDComm session open to the
//! VTA (e.g., the integration's setup wizard). For file-based offline
//! bootstrap, use the `vta bootstrap provision-integration` CLI on the
//! VTA host.
//!
//! Auth model: DIDComm authcrypt authenticates the sender; the VTA
//! also verifies the VP's `DataIntegrityProof` and rejects with a
//! `Forbidden` problem-report when the DIDComm sender DID and the VP
//! holder DID disagree (privilege-laundering guard).

use crate::didcomm_session::DIDCommSession;
use crate::error::VtaError;
use crate::protocols::provision_integration_management::{
    PROVISION_INTEGRATION, PROVISION_INTEGRATION_RESULT,
};

use super::BootstrapRequest;
use super::http::{AssertionMode, ProvisionIntegrationRequest, ProvisionIntegrationResponse};

/// Read the `holder` DID from a `BootstrapRequest` VP without
/// running full signature verification. The VP's structural shape
/// guarantees `holder` is present at this path; signature
/// verification is the VTA's job. Surfaced separately so the
/// DIDComm dispatch can pre-check sender == holder before sending.
fn vp_holder_did(req: &BootstrapRequest) -> &str {
    req.holder.as_str()
}

/// Default DIDComm round-trip timeout (seconds). Generous so the VTA
/// has time to mint keys, render templates, build the webvh log, and
/// seal the bundle — all of which happen synchronously inside the
/// shared library function before the reply lands.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Send a `provision-integration` request over an existing DIDComm
/// session.
///
/// The holder must have an authcrypt'd DIDComm session open to the
/// VTA — see [`DIDCommSession::connect`]. The session's `client_did`
/// must already hold admin role in the target context's ACL; the VTA
/// rejects with `Forbidden` (mapped to [`VtaError::Auth`]) otherwise.
///
/// Returns the same shape the REST endpoint produces: armored sealed
/// bundle + sha256 digest + summary (including `admin_did` /
/// `admin_rolled_over` when the VP requested rollover via
/// `adminTemplate`).
///
/// `assertion` defaults to [`AssertionMode::DidSigned`] when `None`.
pub async fn provision_integration_didcomm(
    session: &DIDCommSession,
    request: BootstrapRequest,
    context: String,
    assertion: Option<AssertionMode>,
    vc_validity_seconds: Option<i64>,
) -> Result<ProvisionIntegrationResponse, VtaError> {
    // Pre-flight: the VTA enforces `DIDCommSender == VP holder`
    // (privilege-laundering guard). Catch the mismatch here so the
    // operator gets a focused error instead of a misleading
    // "Forbidden" round-trip — and so the suggested fix points at
    // REST transport, which is the right path for the relay use
    // case.
    if session.client_did() != vp_holder_did(&request) {
        return Err(VtaError::UnsupportedTransport(format!(
            "DIDComm transport requires the session DID `{}` to match the VP holder `{}`. \
             To relay a VP signed by a different holder, use REST transport — \
             rebuild the client with `VtaClient::from_credential` / `VtaClient::new` \
             instead of `connect_didcomm`.",
            session.client_did(),
            vp_holder_did(&request),
        )));
    }

    let body_struct = ProvisionIntegrationRequest {
        request,
        context,
        assertion,
        vc_validity_seconds,
    };
    let body = serde_json::to_value(&body_struct).map_err(VtaError::from)?;

    session
        .send_and_wait::<ProvisionIntegrationResponse>(
            PROVISION_INTEGRATION,
            body,
            PROVISION_INTEGRATION_RESULT,
            DEFAULT_TIMEOUT_SECS,
        )
        .await
}
