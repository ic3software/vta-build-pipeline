//! `vta bootstrap seal` — offline Mode C sealed-transfer producer.
//!
//! Reads a consumer's `BootstrapRequest` JSON and an arbitrary
//! `SealedPayloadV1` payload, seals the payload to the consumer's ephemeral
//! X25519 pubkey using HPKE, and writes an armored bundle plus prints the
//! canonical SHA-256 digest for out-of-band verification.
//!
//! Mode A (online token-gated bootstrap) was removed in favour of the
//! unified temp-did:key + ACL + rotation flow in `pnm setup`. This CLI is
//! retained for complex-client provisioning (mediator, webvh server) where
//! the consumer genuinely needs an offline-delivered pre-minted identity.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    generate_keypair, seal_payload,
};

use crate::config::AppConfig;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::store::Store;

/// Seal a payload to a consumer's BootstrapRequest (Mode C, offline).
pub async fn run_seal(
    config_path: Option<PathBuf>,
    request_path: PathBuf,
    payload_path: PathBuf,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
    if request.version != 1 {
        return Err(format!("unsupported request version: {}", request.version).into());
    }

    let recipient_pk = request.decode_client_x25519_pub()?;
    let bundle_id = request.decode_nonce()?;

    let payload_json = std::fs::read_to_string(&payload_path)
        .map_err(|e| format!("read {}: {e}", payload_path.display()))?;
    let payload: SealedPayloadV1 =
        serde_json::from_str(&payload_json).map_err(|e| format!("parse SealedPayloadV1: {e}"))?;

    // Fresh per-seal producer identity. In Mode C the consumer pins this
    // pubkey out-of-band — it is not tied to the VTA's long-lived DID.
    let (_producer_sk, producer_pk) = generate_keypair();
    let producer = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::PinnedOnly,
    };

    // Persistent nonce store — re-running `vta bootstrap seal` against the
    // same BootstrapRequest (e.g. after a network glitch) is rejected and
    // forces the consumer to regenerate their request.
    let config_store = AppConfig::load(config_path)?;
    let persistent_store = Store::open(&config_store.store)?;
    let nonce_ks = persistent_store.keyspace("sealed_nonces")?;
    let nonce_store = PersistentNonceStore::new(nonce_ks);
    let bundle = seal_payload(&recipient_pk, bundle_id, producer, &payload, &nonce_store).await?;
    persistent_store.persist().await?;

    let armored = armor::encode(&bundle);
    std::fs::write(&out_path, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    let digest = bundle_digest(&bundle);
    eprintln!("Sealed bundle written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:        {}", hex_lower(&bundle.bundle_id));
    eprintln!("  Chunks:           {}", bundle.chunks.len());
    eprintln!("  Producer pubkey:  {}", B64URL.encode(producer_pk));
    eprintln!("  SHA-256 digest:   {digest}");
    eprintln!();
    eprintln!(
        "Communicate the digest to the consumer out-of-band so they can run\n  \
         pnm bootstrap open --bundle <file> --expect-digest {digest}"
    );
    Ok(())
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
