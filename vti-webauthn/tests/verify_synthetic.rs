//! End-to-end integration test using cryptographically-valid synthetic
//! WebAuthn assertions.
//!
//! Why synthetic rather than browser-captured: the verifier's job is to
//! check that the assertion's signature, message construction, and field
//! validation are correct. Whether the bytes came from a real browser
//! or a Rust signer with a fresh P-256 keypair doesn't matter — what
//! matters is that every byte format and validation rule is exercised
//! with realistic inputs.
//!
//! Real-browser-captured fixtures can be added later by saving the
//! browser-emitted `authenticatorData`, `clientDataJSON`, and
//! `signature` bytes into JSON test data and consuming them via the
//! same `verify_assertion` call below.

use async_trait::async_trait;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose;
use sha2::{Digest, Sha256};

use vti_webauthn::{
    AssertionPayload, ResolvedVm, ResolverError, VerificationAlgorithm, VerifierConfig,
    VerifyError, VmResolver, verify_assertion,
};

/// FLAG_UP | FLAG_UV — both bits set.
const FLAGS_UP_AND_UV: u8 = (1 << 0) | (1 << 2);

/// Fixed test challenge.
const TEST_CHALLENGE: &[u8] = b"a-fresh-nonce-32-bytes-long-here";

const RP_ID: &str = "control.example.com";
const ORIGIN: &str = "https://control.example.com";
const HOLDER_DID: &str = "did:webvh:vta.example.com:alice";
const VM_URL: &str = "did:webvh:vta.example.com:alice#passkey-abc";

// ─── Helpers ─────────────────────────────────────────────────────────────────

struct TestKey {
    keypair: EcdsaKeyPair,
    /// Public key in compressed SEC1 form (33 bytes).
    pub_compressed: Vec<u8>,
    rng: SystemRandom,
}

impl TestKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("generate pkcs8");
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .expect("parse pkcs8");

        let uncompressed = keypair.public_key().as_ref();
        let pub_compressed = uncompressed_to_compressed(uncompressed);
        Self {
            keypair,
            pub_compressed,
            rng,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair
            .sign(&self.rng, message)
            .expect("sign")
            .as_ref()
            .to_vec()
    }
}

/// Convert an aws-lc-rs uncompressed P-256 point (0x04 || x || y, 65 B)
/// to compressed SEC1 form (0x02/0x03 || x, 33 B).
fn uncompressed_to_compressed(uncompressed: &[u8]) -> Vec<u8> {
    assert_eq!(uncompressed.len(), 65, "expected uncompressed SEC1");
    assert_eq!(uncompressed[0], 0x04, "expected uncompressed header");
    let x = &uncompressed[1..33];
    let y = &uncompressed[33..65];
    let header = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    let mut out = Vec::with_capacity(33);
    out.push(header);
    out.extend_from_slice(x);
    out
}

/// Build an `authenticatorData` byte string for a given rp_id + flags +
/// signCount. 37 bytes total — no attestedCredentialData, no extensions.
fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

/// Build a `clientDataJSON` byte string for given challenge + origin.
fn make_client_data(challenge: &[u8], origin: &str) -> Vec<u8> {
    let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    format!(r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"{origin}"}}"#)
        .into_bytes()
}

/// Build a complete `AssertionPayload` + matching `ResolvedVm` for a
/// given key, challenge, RP/origin. Caller can tweak the parts that
/// matter to their test.
fn make_assertion(
    key: &TestKey,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    flags: u8,
    sign_count: u32,
) -> (AssertionPayload, ResolvedVm) {
    let authenticator_data = make_auth_data(rp_id, flags, sign_count);
    let client_data_json = make_client_data(challenge, origin);

    // message = authenticatorData ‖ SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(&authenticator_data);
    message.extend_from_slice(&client_data_hash);

    let signature = key.sign(&message);

    let payload = AssertionPayload {
        credential_id: b"test-credential-abc".to_vec(),
        authenticator_data,
        client_data_json,
        signature,
        verification_method: VM_URL.to_string(),
    };

    let resolved = ResolvedVm {
        algorithm: VerificationAlgorithm::P256,
        public_key_bytes: key.pub_compressed.clone(),
        controller: HOLDER_DID.to_string(),
    };

    (payload, resolved)
}

/// Single-VM resolver returning whatever `ResolvedVm` we put in it.
struct FixedResolver(ResolvedVm);

#[async_trait]
impl VmResolver for FixedResolver {
    async fn resolve_vm(&self, _vm_url: &str) -> Result<ResolvedVm, ResolverError> {
        Ok(self.0.clone())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn happy_path_round_trip() {
    let key = TestKey::generate();
    let (payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, FLAGS_UP_AND_UV, 1);

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let verified = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .expect("valid assertion verifies");

    assert!(verified.user_present);
    assert!(verified.user_verified);
    assert_eq!(verified.sign_count, 1);
    assert_eq!(verified.did, HOLDER_DID);
    assert_eq!(verified.verification_method, VM_URL);
    assert_eq!(verified.algorithm, VerificationAlgorithm::P256);
}

#[tokio::test]
async fn rejects_tampered_signature() {
    let key = TestKey::generate();
    let (mut payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, FLAGS_UP_AND_UV, 1);

    // Flip the last byte of the signature.
    let last = payload.signature.len() - 1;
    payload.signature[last] ^= 0x01;

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid), "got {err:?}");
}

#[tokio::test]
async fn rejects_tampered_authenticator_data() {
    let key = TestKey::generate();
    let (mut payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, FLAGS_UP_AND_UV, 1);

    // Bump signCount — invalidates the signature (signed message changes).
    let len = payload.authenticator_data.len();
    payload.authenticator_data[len - 1] = payload.authenticator_data[len - 1].wrapping_add(1);

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid), "got {err:?}");
}

#[tokio::test]
async fn rejects_tampered_client_data() {
    let key = TestKey::generate();
    let (mut payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, FLAGS_UP_AND_UV, 1);

    // Insert extra whitespace into clientDataJSON — bytes change, hash
    // changes, signature no longer matches.
    let original = String::from_utf8(payload.client_data_json.clone()).unwrap();
    let tampered = original.replace(',', ", ");
    payload.client_data_json = tampered.into_bytes();

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid), "got {err:?}");
}

#[tokio::test]
async fn rejects_assertion_with_wrong_origin_first() {
    // Origin mismatch fires BEFORE signature check (it's cheaper),
    // so we get WrongOrigin not SignatureInvalid even with a valid sig.
    let key = TestKey::generate();
    let (payload, vm) = make_assertion(
        &key,
        TEST_CHALLENGE,
        RP_ID,
        "https://different.example.com",
        FLAGS_UP_AND_UV,
        1,
    );

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::WrongOrigin), "got {err:?}");
}

#[tokio::test]
async fn rejects_assertion_with_wrong_rp_id() {
    let key = TestKey::generate();
    let (payload, vm) = make_assertion(
        &key,
        TEST_CHALLENGE,
        "attacker.example",
        ORIGIN,
        FLAGS_UP_AND_UV,
        1,
    );

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::WrongRpId), "got {err:?}");
}

#[tokio::test]
async fn rejects_replay_with_different_challenge() {
    let key = TestKey::generate();
    let (payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, FLAGS_UP_AND_UV, 1);

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(
        &payload,
        b"different-challenge",
        &FixedResolver(vm),
        &config,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, VerifyError::ChallengeMismatch), "got {err:?}");
}

#[tokio::test]
async fn rejects_uv_missing_when_required() {
    let key = TestKey::generate();
    // FLAG_UP only — UV bit not set.
    let (payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, 1 << 0, 1);

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(
        matches!(err, VerifyError::UserVerificationMissing),
        "got {err:?}"
    );
}

#[tokio::test]
async fn allows_uv_missing_when_not_required() {
    let key = TestKey::generate();
    let (payload, vm) = make_assertion(&key, TEST_CHALLENGE, RP_ID, ORIGIN, 1 << 0, 1);

    let config = VerifierConfig::from_public_url(ORIGIN, false).unwrap();
    let verified = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .expect("UV is optional");
    assert!(verified.user_present);
    assert!(!verified.user_verified);
}

#[tokio::test]
async fn rejects_wrong_pubkey() {
    // Sign with one key, but resolver returns a different key's pubkey.
    let signing_key = TestKey::generate();
    let other_key = TestKey::generate();

    let (payload, mut vm) = make_assertion(
        &signing_key,
        TEST_CHALLENGE,
        RP_ID,
        ORIGIN,
        FLAGS_UP_AND_UV,
        1,
    );
    vm.public_key_bytes = other_key.pub_compressed.clone();

    let config = VerifierConfig::from_public_url(ORIGIN, true).unwrap();
    let err = verify_assertion(&payload, TEST_CHALLENGE, &FixedResolver(vm), &config)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid), "got {err:?}");
}
