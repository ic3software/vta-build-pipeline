//! Assertion payload (input) and verified-assertion (output) types.
//!
//! These types travel across the public API of [`crate::verify_assertion`].
//! Wire-format details (e.g. base64url field encoding when the assertion
//! arrives inside a trust-task JSON envelope) are the caller's
//! responsibility — this crate operates on already-decoded byte buffers.

use crate::resolver::VerificationAlgorithm;

/// A WebAuthn assertion the caller wants verified.
///
/// All byte fields hold raw bytes — the caller has already base64url-
/// decoded them from their wire-form.
#[derive(Debug, Clone)]
pub struct AssertionPayload {
    /// Credential ID identifying which credential produced the assertion.
    /// Sourced from the inbound assertion's `id` / `rawId` field.
    pub credential_id: Vec<u8>,
    /// Raw `authenticatorData` bytes from the assertion.
    pub authenticator_data: Vec<u8>,
    /// Raw `clientDataJSON` bytes from the assertion (UTF-8 JSON).
    pub client_data_json: Vec<u8>,
    /// Raw signature bytes (ECDSA, ASN.1 DER for ES256).
    pub signature: Vec<u8>,
    /// The verificationMethod URL the caller claims this assertion was
    /// produced against. The verifier resolves this URL and uses the VM's
    /// public key to check the signature.
    pub verification_method: String,
}

/// A successfully-verified assertion.
///
/// The caller takes this and decides what to do — issue a JWT, run an
/// operation, persist the sign-count for monotonicity tracking, etc.
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// The DID portion of `verification_method` (everything before the
    /// `#` fragment).
    pub did: String,
    /// The full verificationMethod URL that was used.
    pub verification_method: String,
    /// `true` if the authenticator reported User-Presence.
    pub user_present: bool,
    /// `true` if the authenticator reported User-Verified.
    pub user_verified: bool,
    /// `signCount` reported by the authenticator. Typically `0` for
    /// synced passkeys (iCloud Keychain, Google Password Manager) and
    /// strictly monotonic for hardware authenticators. Callers persist
    /// this if they want counter-regression detection.
    pub sign_count: u32,
    /// Algorithm of the VM that verified the assertion.
    pub algorithm: VerificationAlgorithm,
}
