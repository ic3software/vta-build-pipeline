//! End-to-end verification of AWS Nitro attestation quotes embedded in
//! sealed-bootstrap Mode B producer assertions.
//!
//! Delegates the heavy lifting (COSE_Sign1 parsing, AWS Nitro root-cert
//! chain validation, ECDSA signature verification) to the `nitro_attest`
//! crate. We layer the sealed-bootstrap-specific checks on top: the
//! quote's `user_data` must equal
//! `SHA256(client_ed25519_pub || nonce || producer_ed25519_pub)`, binding
//! the attestation to the exact did:keys the consumer saw (`client_did`
//! in the request, `producer_did` in the returned assertion) rather than
//! to the derived X25519 pubkeys HPKE internally consumed.
//!
//! Feature-gated behind `attest-verify` so clients that don't consume
//! Mode B bundles don't pull in the attestation crate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64STD;
use nitro_attest::UnparsedAttestationDoc;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::sealed_transfer::{AssertionProof, AttestationQuoteAssertion, ProducerAssertion};

/// Successfully verified attestation details, returned for callers that want
/// to log or display the enclave identity after a Mode B bootstrap.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub module_id: String,
    /// PCR0 — enclave image measurement — lowercase hex.
    pub pcr0_hex: String,
    /// PCR8 — signing certificate measurement — lowercase hex.
    pub pcr8_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationVerifyError {
    #[error("expected an Attested proof, got {0}")]
    WrongProofVariant(&'static str),
    #[error("unknown attestation format: {0}")]
    UnknownFormat(String),
    #[error("base64 decode: {0}")]
    Base64(String),
    #[error("quote parse/verify failed: {0}")]
    QuoteInvalid(String),
    #[error("attestation quote is missing user_data")]
    MissingUserData,
    #[error("user_data mismatch — quote does not commit to this bundle")]
    UserDataMismatch,
    #[error("invalid producer did:key: {0}")]
    BadProducerDid(String),
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

fn is_nitro_format(format: &str) -> bool {
    matches!(
        format.to_ascii_lowercase().as_str(),
        "nitro" | "aws-nitro" | "aws-nitro-v1"
    )
}

/// Verify an [`AttestationQuoteAssertion`] against the exact triple
/// `(client_ed25519_pub, nonce, producer_ed25519_pub)` that the
/// sealed-bootstrap handshake committed to. Returns the verified enclave
/// identity on success.
pub fn verify_nitro_assertion(
    producer: &ProducerAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let quote = match &producer.proof {
        AssertionProof::Attested(q) => q,
        AssertionProof::PinnedOnly => {
            return Err(AttestationVerifyError::WrongProofVariant("PinnedOnly"));
        }
        AssertionProof::DidSigned(_) => {
            return Err(AttestationVerifyError::WrongProofVariant("DidSigned"));
        }
    };

    verify_nitro_quote(quote, client_ed25519_pub, nonce, &producer.producer_did)
}

/// Variant that takes the quote + expected commitment components directly.
/// Useful for callers that already pulled the did:key out of the assertion.
pub fn verify_nitro_quote(
    quote: &AttestationQuoteAssertion,
    client_ed25519_pub: &[u8; 32],
    nonce: &[u8; 16],
    producer_did: &str,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    if !is_nitro_format(&quote.format) {
        return Err(AttestationVerifyError::UnknownFormat(quote.format.clone()));
    }

    let quote_bytes = B64STD
        .decode(&quote.quote_b64)
        .map_err(|e| AttestationVerifyError::Base64(e.to_string()))?;

    let parsed = UnparsedAttestationDoc::from(quote_bytes.as_slice())
        .parse_and_verify(OffsetDateTime::now_utc())
        .map_err(|e| AttestationVerifyError::QuoteInvalid(format!("{e:?}")))?;

    let producer_ed_pub = affinidi_crypto::did_key::did_key_to_ed25519_pub(producer_did)
        .map_err(|e| AttestationVerifyError::BadProducerDid(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(client_ed25519_pub);
    hasher.update(nonce);
    hasher.update(producer_ed_pub);
    let expected = hasher.finalize();

    let user_data_bytes: &[u8] = parsed
        .user_data
        .as_ref()
        .map(|b| b.as_ref())
        .ok_or(AttestationVerifyError::MissingUserData)?;
    if user_data_bytes != expected.as_slice() {
        return Err(AttestationVerifyError::UserDataMismatch);
    }

    let pcr0_hex = parsed
        .pcrs
        .get(&0)
        .map(|d| hex_lower(&d.value))
        .unwrap_or_default();
    let pcr8_hex = parsed
        .pcrs
        .get(&8)
        .map(|d| hex_lower(&d.value))
        .unwrap_or_default();

    Ok(VerifiedAttestation {
        module_id: parsed.module_id,
        pcr0_hex,
        pcr8_hex,
    })
}
