//! DID Verification Method resolver seam.
//!
//! The crate does not ship a DID resolver. Callers implement [`VmResolver`]
//! and pass it in to [`crate::verify_assertion`]. Implementations are
//! typically thin wrappers over an existing resolver (e.g.
//! `affinidi-did-resolver-cache-sdk` in the VTI workspace).

use async_trait::async_trait;
use thiserror::Error;

/// Trait the caller implements to resolve a verificationMethod URL to a
/// public key.
///
/// The crate performs no caching; the resolver implementation owns that.
/// Implementations MUST be `Send + Sync` so they can be used from the
/// async verifier across await points.
#[async_trait]
pub trait VmResolver: Send + Sync {
    /// Resolve a verificationMethod URL (e.g.
    /// `"did:webvh:vta.example.com:alice#passkey-abc"`) to the underlying
    /// key material plus the controller DID.
    async fn resolve_vm(&self, vm_url: &str) -> Result<ResolvedVm, ResolverError>;
}

/// What a successful VM resolution yields.
#[derive(Debug, Clone)]
pub struct ResolvedVm {
    /// Inferred from the multikey multicodec prefix.
    pub algorithm: VerificationAlgorithm,
    /// Raw public-key bytes with the multicodec prefix stripped.
    ///
    /// - P-256: 33 bytes (compressed SEC1 form).
    pub public_key_bytes: Vec<u8>,
    /// The VM's controller DID. Used to confirm the verificationMethod's
    /// DID portion matches the resolved owner — defence in depth.
    pub controller: String,
}

/// Signature algorithm advertised by the resolved VM's multikey.
///
/// `#[non_exhaustive]` so v0.2 can add Ed25519 without breaking
/// downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationAlgorithm {
    /// P-256 / ES256 — multicodec `0x1200`.
    P256,
}

/// Errors a resolver may surface.
///
/// `#[non_exhaustive]` so resolver implementations can grow their error
/// surface without breaking downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ResolverError {
    /// The verificationMethod URL did not name a VM present in the
    /// resolved DID document.
    #[error("verification method not found")]
    NotFound,
    /// The DID itself could not be resolved (transport error, DID method
    /// failure, etc.).
    #[error("DID could not be resolved: {0}")]
    UnresolvableDid(String),
    /// The DID resolved but the VM was malformed (bad multikey, missing
    /// required fields, unsupported type).
    #[error("verification method is malformed: {0}")]
    MalformedVm(String),
    /// Catch-all for implementation-specific failures.
    #[error("{0}")]
    Other(String),
}
