//! # vti-webauthn
//!
//! DID-VM-resolved WebAuthn assertion verifier for the Verifiable Trust
//! Infrastructure.
//!
//! See `docs/05-design-notes/vti-webauthn-crate-design.md` in the parent
//! workspace for the design rationale and the verification algorithm.
//!
//! ## Quick reference
//!
//! - [`verify_assertion`] — main entry point.
//! - [`VerifierConfig`] — RP-ID / origin / UV-policy.
//! - [`VmResolver`] — caller-supplied trait for resolving a
//!   `verificationMethod` URL to a public key.
//! - [`document_binding_challenge`] — helper for deriving the
//!   `clientData.challenge` from a trust-task envelope so the assertion
//!   is bound to the full document, not just a nonce.
//!
//! ## What this crate does NOT do
//!
//! - DID resolution itself (the caller's `VmResolver` does it).
//! - Replay defence at the server-issued-nonce level (caller's nonce store).
//! - Counter persistence ([`VerifiedAssertion::sign_count`] is exposed for
//!   the caller to apply its own policy).
//! - Trust-task envelope semantics (caller wraps/unwraps).
//! - Enrolment / registration (this crate only verifies assertions).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod auth_data;
mod client_data;

pub mod config;
pub mod document_binding;
pub mod error;
pub mod multikey;
pub mod payload;
pub mod resolver;
pub mod verify;

pub use config::{ConfigError, VerifierConfig};
pub use document_binding::{BindingError, document_binding_challenge};
pub use error::VerifyError;
pub use payload::{AssertionPayload, VerifiedAssertion};
pub use resolver::{ResolvedVm, ResolverError, VerificationAlgorithm, VmResolver};
pub use verify::verify_assertion;
