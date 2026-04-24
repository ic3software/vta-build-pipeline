//! Consumer-side verification of sealed-bundle producer assertions.
//!
//! The producer side constructs a `DidSigned` assertion over
//! `DID_SIGNED_DOMAIN_TAG || client_x25519_pub || bundle_id`
//! (see `vta-service/src/operations/provision_integration.rs::build_did_signed_assertion`).
//! Historically no consumer verified this signature — the bundle-id
//! digest OOB channel was the only in-band anchor. This module closes
//! that gap: given the producer's Ed25519 public-key bytes, confirm the
//! signature is genuine.
//!
//! The helper is deliberately pure — it does **not** resolve DIDs. The
//! caller is expected to resolve `producer_did` (or, for `did:key`,
//! decode it directly), extract the verification method matching the
//! assertion's `verification_method` field, and pass the raw 32-byte
//! Ed25519 public key in. Keeps the sealed-transfer crate free of DID
//! resolver dependencies and lets downstream consumers use whatever
//! resolver they already have.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::bundle::{AssertionProof, DidSignedAssertion, ProducerAssertion};
use super::error::SealedTransferError;

/// Domain tag bound into every `DidSigned` signature. Matches the
/// producer-side constant at
/// `vta-service/src/operations/provision_integration.rs` (look for the
/// `b"vta-sealed-transfer/v1\0"` literal in `build_did_signed_assertion`).
///
/// The tag isolates this signing context from every other use of the
/// VTA's `{vta_did}#key-0` key — a signature produced for a VC or a
/// DIDComm envelope can never be replayed as a producer assertion.
pub const DID_SIGNED_DOMAIN_TAG: &[u8] = b"vta-sealed-transfer/v1\0";

/// Verify a [`DidSignedAssertion`] given the producer's Ed25519
/// public-key bytes.
///
/// `expected_producer_did` is the `producer_did` embedded in chunk 0 —
/// we confirm the assertion's own `did` field agrees before spending
/// cycles on the signature check. This defends against a bundle where
/// the assertion was lifted from a different producer but chunk 0's
/// producer_did was swapped to match.
///
/// Returns `Ok(())` on verified signature, `SealedTransferError::AssertionVerification`
/// on any failure. Does **not** handle `PinnedOnly` or `Attested`
/// variants — call at the top of the consumer's verify path and fall
/// through to variant-specific checks for those.
pub fn verify_did_signed_assertion_with_pubkey(
    assertion: &DidSignedAssertion,
    expected_producer_did: &str,
    producer_ed25519_pubkey: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    bundle_id: &[u8; 16],
) -> Result<(), SealedTransferError> {
    if assertion.did != expected_producer_did {
        return Err(SealedTransferError::AssertionVerification(format!(
            "DidSigned assertion DID '{}' does not match bundle producer_did '{}'",
            assertion.did, expected_producer_did,
        )));
    }
    let sig_bytes = B64URL
        .decode(assertion.signature_b64.as_bytes())
        .map_err(|e| {
            SealedTransferError::AssertionVerification(format!("decode signature_b64: {e}"))
        })?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        SealedTransferError::AssertionVerification(format!(
            "signature shape (expected 64 bytes, got {}): {e}",
            sig_bytes.len()
        ))
    })?;
    let vk = VerifyingKey::from_bytes(producer_ed25519_pubkey)
        .map_err(|e| SealedTransferError::AssertionVerification(format!("pubkey shape: {e}")))?;

    let mut msg =
        Vec::with_capacity(DID_SIGNED_DOMAIN_TAG.len() + client_x25519_pub.len() + bundle_id.len());
    msg.extend_from_slice(DID_SIGNED_DOMAIN_TAG);
    msg.extend_from_slice(client_x25519_pub);
    msg.extend_from_slice(bundle_id);

    vk.verify(&msg, &signature).map_err(|e| {
        SealedTransferError::AssertionVerification(format!(
            "signature does not verify against producer pubkey: {e}"
        ))
    })
}

/// Classification of a producer assertion after dispatch. Callers
/// consume this to decide what integrity anchor they are relying on.
/// A value is only constructable via
/// [`verify_producer_assertion_with_pubkey`], so holding one is
/// evidence of (at least) a successful dispatch.
///
/// [`DidSignedVerified`] carries a fully-verified Ed25519 signature.
/// [`PinnedOnlyAcknowledged`] is a receipt that the caller accepted a
/// bundle whose only integrity anchor is the out-of-band digest —
/// they must have verified that digest separately; this type does not
/// prove it.
/// [`AttestedNeedsNitroCheck`] is an explicit demand on the caller to
/// invoke Nitro attestation verification (see
/// [`crate::attestation::verify_nitro_assertion`] under the
/// `attest-verify` feature). It is **not** a verification success.
#[derive(Debug)]
pub enum VerifiedAssertion<'a> {
    /// Ed25519 signature verified against the producer's resolved
    /// public key.
    DidSignedVerified(&'a ProducerAssertion),
    /// Dispatched as `PinnedOnly`. The caller is responsible for
    /// independently verifying the out-of-band digest; this variant
    /// does not prove integrity on its own.
    PinnedOnlyAcknowledged(&'a ProducerAssertion),
    /// Dispatched as `Attested`. The caller MUST call
    /// [`crate::attestation::verify_nitro_assertion`] to graduate
    /// this to a verified state. Discarding this variant without
    /// verification is a bug — downstream code should match
    /// exhaustively on this enum.
    AttestedNeedsNitroCheck(&'a ProducerAssertion),
}

/// Dispatch over [`AssertionProof`] variants, returning a
/// [`VerifiedAssertion`] typestate that tells the caller what (if any)
/// in-band integrity anchor was confirmed.
///
/// Previously this function returned `Result<(), _>` and quietly
/// returned `Ok(())` for `Attested` (deferring to
/// [`crate::attestation::verify_nitro_assertion`]) and `PinnedOnly`
/// (expecting the caller to verify the OOB digest separately). That
/// API let forgetful callers treat any non-error return as a full
/// verification success. The typestate return forces the caller to
/// branch on the variant and makes the remaining work explicit.
pub fn verify_producer_assertion_with_pubkey<'a>(
    producer: &'a ProducerAssertion,
    client_x25519_pub: &[u8; 32],
    bundle_id: &[u8; 16],
    producer_ed25519_pubkey: Option<&[u8; 32]>,
) -> Result<VerifiedAssertion<'a>, SealedTransferError> {
    match &producer.proof {
        AssertionProof::PinnedOnly => Ok(VerifiedAssertion::PinnedOnlyAcknowledged(producer)),
        AssertionProof::DidSigned(a) => {
            let pubkey = producer_ed25519_pubkey.ok_or_else(|| {
                SealedTransferError::AssertionVerification(
                    "DidSigned assertion requires the producer's Ed25519 pubkey; \
                     resolver returned None"
                        .into(),
                )
            })?;
            verify_did_signed_assertion_with_pubkey(
                a,
                &producer.producer_did,
                pubkey,
                client_x25519_pub,
                bundle_id,
            )?;
            Ok(VerifiedAssertion::DidSignedVerified(producer))
        }
        AssertionProof::Attested(_) => Ok(VerifiedAssertion::AttestedNeedsNitroCheck(producer)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::generate_ed25519_keypair;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_fixture(
        client_x25519_pub: &[u8; 32],
        bundle_id: &[u8; 16],
    ) -> (SigningKey, [u8; 32], DidSignedAssertion) {
        let (seed, pub_bytes) = generate_ed25519_keypair();
        let signing = SigningKey::from_bytes(&seed);
        let mut msg = Vec::new();
        msg.extend_from_slice(DID_SIGNED_DOMAIN_TAG);
        msg.extend_from_slice(client_x25519_pub);
        msg.extend_from_slice(bundle_id);
        let sig = signing.sign(&msg);
        let assertion = DidSignedAssertion {
            did: "did:key:zVtaTestProducer".into(),
            signature_b64: B64URL.encode(sig.to_bytes()),
            verification_method: "did:key:zVtaTestProducer#z6MkProducer".into(),
        };
        (signing, pub_bytes, assertion)
    }

    #[test]
    fn verify_passes_for_matching_signature() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        verify_did_signed_assertion_with_pubkey(
            &assertion,
            "did:key:zVtaTestProducer",
            &pubkey,
            &client_x,
            &bundle_id,
        )
        .expect("signature verifies under the genuine producer key");
    }

    #[test]
    fn verify_rejects_wrong_producer_did() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        let err = verify_did_signed_assertion_with_pubkey(
            &assertion,
            "did:key:zSomeoneElse",
            &pubkey,
            &client_x,
            &bundle_id,
        )
        .expect_err("DID mismatch must be rejected");
        assert!(
            matches!(err, SealedTransferError::AssertionVerification(_)),
            "got: {err:?}",
        );
    }

    #[test]
    fn verify_rejects_tampered_bundle_id() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        let tampered_bundle_id = [0x99u8; 16];
        let err = verify_did_signed_assertion_with_pubkey(
            &assertion,
            "did:key:zVtaTestProducer",
            &pubkey,
            &client_x,
            &tampered_bundle_id,
        )
        .expect_err("bundle_id swap must be rejected");
        assert!(
            matches!(err, SealedTransferError::AssertionVerification(_)),
            "got: {err:?}",
        );
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, _pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        // Generate a completely unrelated keypair.
        let (_, other_pub) = generate_ed25519_keypair();
        let err = verify_did_signed_assertion_with_pubkey(
            &assertion,
            "did:key:zVtaTestProducer",
            &other_pub,
            &client_x,
            &bundle_id,
        )
        .expect_err("attacker substituting their own pubkey must be rejected");
        assert!(
            matches!(err, SealedTransferError::AssertionVerification(_)),
            "got: {err:?}",
        );
    }

    #[test]
    fn verify_rejects_tampered_signature_bytes() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, pubkey, mut assertion) = sign_fixture(&client_x, &bundle_id);
        // Flip a bit in the signature payload by re-encoding a mutated copy.
        let mut sig_bytes = B64URL.decode(assertion.signature_b64.as_bytes()).unwrap();
        sig_bytes[0] ^= 0x01;
        assertion.signature_b64 = B64URL.encode(sig_bytes);
        let err = verify_did_signed_assertion_with_pubkey(
            &assertion,
            "did:key:zVtaTestProducer",
            &pubkey,
            &client_x,
            &bundle_id,
        )
        .expect_err("bit-flip in signature must be rejected");
        assert!(
            matches!(err, SealedTransferError::AssertionVerification(_)),
            "got: {err:?}",
        );
    }

    #[test]
    fn dispatch_pinned_only_yields_acknowledged_variant() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let producer = ProducerAssertion {
            producer_did: "did:key:zVtaTestProducer".into(),
            proof: AssertionProof::PinnedOnly,
        };
        let verified =
            verify_producer_assertion_with_pubkey(&producer, &client_x, &bundle_id, None)
                .expect("PinnedOnly dispatches successfully");
        assert!(
            matches!(verified, VerifiedAssertion::PinnedOnlyAcknowledged(_)),
            "PinnedOnly must yield PinnedOnlyAcknowledged so callers can't mistake it \
             for a real signature check — got {verified:?}",
        );
    }

    #[test]
    fn dispatch_attested_yields_needs_nitro_check_variant() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let producer = ProducerAssertion {
            producer_did: "did:key:zVtaTestProducer".into(),
            proof: AssertionProof::Attested(
                crate::sealed_transfer::bundle::AttestationQuoteAssertion {
                    format: "aws-nitro-v1".into(),
                    quote_b64: "AAAA".into(),
                },
            ),
        };
        let verified =
            verify_producer_assertion_with_pubkey(&producer, &client_x, &bundle_id, None)
                .expect("Attested dispatches successfully");
        assert!(
            matches!(verified, VerifiedAssertion::AttestedNeedsNitroCheck(_)),
            "Attested must yield AttestedNeedsNitroCheck so the caller is forced to \
             explicitly invoke nitro quote verification — got {verified:?}",
        );
    }

    #[test]
    fn dispatch_did_signed_yields_verified_variant() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        let producer = ProducerAssertion {
            producer_did: "did:key:zVtaTestProducer".into(),
            proof: AssertionProof::DidSigned(assertion),
        };
        let verified =
            verify_producer_assertion_with_pubkey(&producer, &client_x, &bundle_id, Some(&pubkey))
                .expect("DidSigned with valid pubkey verifies");
        assert!(
            matches!(verified, VerifiedAssertion::DidSignedVerified(_)),
            "got: {verified:?}",
        );
    }

    #[test]
    fn dispatch_did_signed_requires_pubkey() {
        let client_x = [0xAAu8; 32];
        let bundle_id = [0x55u8; 16];
        let (_signing, _pubkey, assertion) = sign_fixture(&client_x, &bundle_id);
        let producer = ProducerAssertion {
            producer_did: "did:key:zVtaTestProducer".into(),
            proof: AssertionProof::DidSigned(assertion),
        };
        let err = verify_producer_assertion_with_pubkey(&producer, &client_x, &bundle_id, None)
            .expect_err("DidSigned without a pubkey is an error");
        assert!(
            matches!(err, SealedTransferError::AssertionVerification(_)),
            "got: {err:?}",
        );
    }
}
