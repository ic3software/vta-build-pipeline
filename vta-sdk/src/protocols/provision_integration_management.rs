//! DIDComm protocol for `provision-integration`.
//!
//! Carries a VP-framed [`crate::provision_integration::BootstrapRequest`]
//! to the VTA in an authcrypt'd DIDComm message; receives the sealed
//! `TemplateBootstrap` bundle back in an authcrypt'd reply.
//!
//! Auth model: DIDComm authcrypt is the auth — the VTA reads `from`
//! as the authenticated sender DID and ACL-checks it (must hold admin
//! role in the target context). The VP's `DataIntegrityProof` is the
//! second proof; both must agree (`from == VP holder`) for the
//! handler to proceed.
//!
//! Both parties exchange the same on-the-wire shapes the REST endpoint
//! at `POST /bootstrap/provision-integration` does — wire format is
//! transport-neutral. See
//! [`crate::provision_integration::http::ProvisionIntegrationRequest`]
//! and [`crate::provision_integration::http::ProvisionIntegrationResponse`].

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/provision-integration/1.0";

/// Inbound VP + provisioning options.
pub const PROVISION_INTEGRATION: &str =
    "https://firstperson.network/protocols/provision-integration/1.0/provision-integration";

/// Outbound sealed bundle + summary.
pub const PROVISION_INTEGRATION_RESULT: &str =
    "https://firstperson.network/protocols/provision-integration/1.0/provision-integration-result";

pub mod request {
    //! Body shape for the inbound DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationRequest`]
    //! — same field semantics, same JSON layout.
    pub use crate::provision_integration::http::{AssertionMode, ProvisionIntegrationRequest};
}

pub mod result {
    //! Body shape for the reply DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationResponse`].
    pub use crate::provision_integration::http::{ProvisionIntegrationResponse, ProvisionSummary};
}
