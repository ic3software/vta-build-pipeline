//! Thin wrapper over [`crate::session::resolve_vta_endpoint`] that presents
//! a flat result type and distinguishes "DIDComm only" / "REST only" /
//! "both" for downstream consumers.

use crate::session::{VtaEndpoint, resolve_vta_endpoint};

use super::error::ProvisionError;

#[derive(Clone, Debug)]
pub struct ResolvedVta {
    pub vta_did: String,
    /// DIDComm mediator DID advertised in the VTA document, if any.
    pub mediator_did: Option<String>,
    /// REST URL advertised via the `#vta-rest` service, if any.
    pub rest_url: Option<String>,
}

/// Resolve a VTA DID and extract its transport endpoints.
///
/// Returns an error if the DID cannot be resolved and no fallback URL can
/// be inferred from the DID string.
pub async fn resolve_vta(vta_did: &str) -> Result<ResolvedVta, ProvisionError> {
    match resolve_vta_endpoint(vta_did)
        .await
        .map_err(|e| ProvisionError::Resolve {
            vta_did: vta_did.to_string(),
            message: e.to_string(),
        })? {
        VtaEndpoint::DIDComm {
            vta_did,
            mediator_did,
            rest_url,
        } => Ok(ResolvedVta {
            vta_did,
            mediator_did: Some(mediator_did),
            rest_url,
        }),
        VtaEndpoint::Rest { url } => Ok(ResolvedVta {
            vta_did: vta_did.to_string(),
            mediator_did: None,
            rest_url: Some(url),
        }),
    }
}
