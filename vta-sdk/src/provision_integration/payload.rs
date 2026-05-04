//! Payload types for the `provision-integration` flow.
//!
//! The concrete struct definitions live in
//! [`crate::sealed_transfer::template_bootstrap`] — they're part of the
//! `SealedPayloadV1::TemplateBootstrap` variant and therefore must
//! compile whenever `sealed-transfer` is enabled, independent of
//! `provision-integration`. This module re-exports them so callers
//! working in the `provision_integration` namespace don't have to
//! reach across crates to find them.

pub use crate::sealed_transfer::template_bootstrap::{
    DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    VtaTrustBundle,
};
