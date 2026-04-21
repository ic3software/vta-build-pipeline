//! Wire types for `POST /bootstrap/provision-integration`.
//!
//! Mirrors the shape of
//! `vta-service::routes::bootstrap::provision::*` on the client side,
//! so `VtaClient::provision_integration` consumers don't need to
//! depend on vta-service.

use serde::{Deserialize, Serialize};

use super::BootstrapRequest;

/// Request body.
#[derive(Debug, Serialize)]
pub struct ProvisionIntegrationRequest {
    /// The integration's VP-framed bootstrap request (signed by its
    /// ephemeral `client_did`). The caller sends it unverified — the
    /// server verifies on intake.
    pub request: BootstrapRequest,
    /// VTA context to provision into.
    pub context: String,
    /// Optional — default `did-signed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<AssertionMode>,
    /// Optional override for the VC's validity window (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_validity_seconds: Option<i64>,
}

/// Producer assertion mode on the returned sealed bundle. Mirrors the
/// server's `AssertionMode`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionMode {
    #[default]
    DidSigned,
    PinnedOnly,
}

/// Response body.
#[derive(Debug, Deserialize)]
pub struct ProvisionIntegrationResponse {
    /// Armored sealed bundle.
    pub bundle: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    pub digest: String,
    pub summary: ProvisionSummary,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    pub client_did: String,
    /// Long-term admin DID — equals `client_did` when no rollover, or
    /// the VTA-minted DID when the request carried an `adminTemplate`.
    /// Older VTAs that pre-date admin rollover omit this field on the
    /// wire; we default it to `client_did` for backward compat.
    #[serde(default)]
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning. Defaults to `false` for backward compatibility
    /// with VTAs that pre-date admin rollover.
    #[serde(default)]
    pub admin_rolled_over: bool,
    pub integration_did: String,
    pub template_name: String,
    pub template_kind: String,
    /// Name of the admin template, when one was requested.
    #[serde(default)]
    pub admin_template_name: Option<String>,
    pub bundle_id_hex: String,
    pub secret_count: usize,
    pub output_count: usize,
}
