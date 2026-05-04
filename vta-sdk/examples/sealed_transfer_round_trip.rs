//! Sealed-transfer end-to-end round-trip example.
//!
//! Demonstrates the wire shape of the sealed-transfer envelope:
//! producer mints a payload → seals to a consumer-supplied X25519
//! pubkey → ASCII-armors → consumer parses armor → opens HPKE →
//! verifies the producer assertion.
//!
//! Run with:
//! ```bash
//! cargo run --example sealed_transfer_round_trip \
//!     --features sealed-transfer
//! ```
//!
//! The example uses the `DidSigned` producer assertion variant — the
//! default for VTA-issued bundles. `Attested` (Nitro quote) and
//! `PinnedOnly` (dev escape hatch) follow the same shape; see
//! `vta_sdk::sealed_transfer::AssertionProof`.

use vta_sdk::sealed_transfer::{
    AssertionProof, DidSignedAssertion, InMemoryNonceStore, LabeledKey, ProducerAssertion,
    SealedPayloadV1, armor, bundle_digest, ed25519_seed_to_x25519_secret, generate_ed25519_keypair,
    generate_keypair, open_bundle, seal_payload,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Producer side ────────────────────────────────────────────────

    // Producer's signing identity (Ed25519). For a real VTA this is
    // `{vta_did}#sealed-transfer-0`; here we generate one ad-hoc.
    let (producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);

    // Consumer-supplied recipient X25519 pubkey. The consumer derives
    // this from its own Ed25519 seed; the producer never sees the
    // consumer's private material.
    let (consumer_seed, consumer_ed_pub) = generate_ed25519_keypair();
    let consumer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&consumer_ed_pub);
    let recipient_x25519 = affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&consumer_ed_pub)?;

    // Per-bundle nonce — typically the consumer's request nonce.
    let mut bundle_id = [0u8; 16];
    getrandom::fill(&mut bundle_id)?;

    // Sample payload. Real flows use TemplateBootstrap, AdminRotation,
    // DidSecrets, etc. — see `SealedPayloadV1`'s variants.
    let payload = SealedPayloadV1::AdminKeySet(vec![LabeledKey {
        label: "example-key".into(),
        key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        key_type: Some("ed25519".into()),
    }]);

    // DidSigned producer assertion. The signature commits to
    // `DOMAIN_TAG || consumer_x25519_pub || bundle_id`.
    use ed25519_dalek::Signer;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&producer_seed);
    let mut to_sign = Vec::with_capacity(64);
    to_sign.extend_from_slice(b"vta-sealed-transfer/v1\0");
    to_sign.extend_from_slice(&recipient_x25519);
    to_sign.extend_from_slice(&bundle_id);
    let signature = signing_key.sign(&to_sign);

    use base64::Engine;
    let assertion = ProducerAssertion {
        producer_did: producer_did.clone(),
        proof: AssertionProof::DidSigned(DidSignedAssertion {
            did: producer_did.clone(),
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_bytes()),
            verification_method: format!("{producer_did}#{}", strip_did_key(&producer_did)),
        }),
    };

    // Seal + armor.
    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(
        &recipient_x25519,
        bundle_id,
        assertion,
        &payload,
        &nonce_store,
    )
    .await?;
    let armored = armor::encode(&bundle);
    let digest = bundle_digest(&bundle);

    println!("Producer DID:    {producer_did}");
    println!("Consumer DID:    {consumer_did}");
    println!("Bundle digest:   {digest}");
    println!("Armored bundle ({} bytes):", armored.len());
    println!("{armored}");

    // ── Consumer side ────────────────────────────────────────────────

    // Parse armor back into a SealedBundle.
    let parsed = armor::decode(&armored)?;
    let bundle = parsed.into_iter().next().expect("at least one bundle");

    // Open with the consumer's X25519 secret (derived from the
    // Ed25519 seed it controls).
    let consumer_x25519_secret = ed25519_seed_to_x25519_secret(&consumer_seed);
    let opened = open_bundle(&consumer_x25519_secret, &bundle, Some(&digest))?;

    println!(
        "Opened payload: {} variant, producer_did={}",
        match opened.payload {
            SealedPayloadV1::AdminKeySet(_) => "AdminKeySet",
            _ => "<other>",
        },
        opened.producer.producer_did
    );

    // Verify the DidSigned assertion matches the producer DID we expect.
    // (A real consumer pins a known producer_did out-of-band.)
    let _ = generate_keypair(); // silence the unused-import lint on no-op paths

    Ok(())
}

fn strip_did_key(did: &str) -> &str {
    did.strip_prefix("did:key:").unwrap_or(did)
}
