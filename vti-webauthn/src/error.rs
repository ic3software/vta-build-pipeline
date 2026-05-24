//! Verification errors surfaced by [`crate::verify_assertion`].

use thiserror::Error;

use crate::resolver::ResolverError;

/// Reasons a WebAuthn assertion may fail to verify.
///
/// `#[non_exhaustive]` so v0.2 can add new variants (counter regression,
/// telemetry-flagged failures, etc.) without breaking downstream `match`
/// arms.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum VerifyError {
    /// One of the input byte buffers (`authenticator_data`,
    /// `client_data_json`, `signature`, `credential_id`) was malformed.
    /// The `&'static str` is a short tag identifying which buffer
    /// failed — intended for operator-facing logs, not end-user output.
    #[error("malformed assertion: {0}")]
    MalformedAssertion(&'static str),

    /// The resolver returned an error when looking up the
    /// verificationMethod URL.
    #[error("verification-method resolution failed: {0}")]
    VmResolution(#[from] ResolverError),

    /// The resolved VM advertises an algorithm this crate doesn't support
    /// (e.g. Ed25519 before v0.2 lands the feature).
    #[error("unsupported algorithm for this verifier")]
    UnsupportedAlgorithm,

    /// `clientData.type` was not `"webauthn.get"`.
    #[error("clientData.type is not \"webauthn.get\"")]
    WrongClientDataType,

    /// `clientData.origin` did not match the verifier's expected origin.
    #[error("clientData.origin does not match expected origin")]
    WrongOrigin,

    /// `clientData.challenge` did not match the expected challenge bytes.
    #[error("clientData.challenge does not match expected challenge")]
    ChallengeMismatch,

    /// `authenticatorData.rpIdHash` did not match `SHA-256(rp_id)`.
    #[error("authenticatorData.rpIdHash does not match expected rp_id")]
    WrongRpId,

    /// The User-Presence flag was not set on the assertion.
    #[error("user-presence (UP) flag not set on assertion")]
    UserPresenceMissing,

    /// User Verification was required by config but the UV flag was
    /// not set on the assertion.
    #[error("user-verification (UV) flag required but not set")]
    UserVerificationMissing,

    /// Cryptographic signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// The DID extracted from `verification_method` and the controller
    /// returned by the resolver disagree. Defence in depth — should be
    /// impossible if the resolver is correct.
    #[error("VM controller mismatch: expected {expected}, found {found}")]
    ControllerMismatch {
        /// DID derived from the `verification_method` URL.
        expected: String,
        /// Controller reported by the resolver.
        found: String,
    },
}
