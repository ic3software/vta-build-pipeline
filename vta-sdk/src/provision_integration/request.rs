//! Bootstrap request — W3C Verifiable Presentation signed by the
//! integration's ephemeral `client_did` (Ed25519).
//!
//! Wire shape is a VP with no embedded VCs. The VP's custom fields
//! (`nonce`, `validUntil`, `label`, `ask`) carry the operator's intent
//! and are covered by the VP's proof.
//!
//! Typestate: the deserialized [`BootstrapRequest`] is inert until
//! [`BootstrapRequest::verify`] produces a [`VerifiedBootstrapRequest`]
//! that downstream handlers consume.

use std::collections::BTreeMap;

use affinidi_crypto::did_key as did_key_helpers;
use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sealed_transfer::SealedTransferError;

use super::{BOOTSTRAP_CONTEXT_URL, ProvisionIntegrationError, VC_V2_CONTEXT_URL};

/// VP-framed bootstrap request. Wire shape conforms to VC Data Model 2.0
/// §6.1 (VPs MAY omit `verifiableCredential`; self-attested presentation
/// of arbitrary claims is permitted).
///
/// Standard VP fields (`@context`, `type`, `holder`, `id`, `proof`) are
/// at the top level; the custom bootstrap fields (`nonce`, `validUntil`,
/// `label`, `ask`) sit alongside as additional properties authenticated
/// by the same proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRequest {
    /// JSON-LD contexts. Must include `https://www.w3.org/ns/credentials/v2`
    /// and `https://openvtc.org/contexts/bootstrap-v1`.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// VP types. MUST include `VerifiablePresentation`; SHOULD include
    /// `BootstrapRequest` so verifiers can filter.
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// Unique id for this presentation. URN-shaped.
    pub id: String,

    /// Ephemeral `did:key` of the integration. Bundle is HPKE-sealed to
    /// this DID's X25519 derivation; proof verifies against this DID.
    pub holder: String,

    /// Random 16-byte nonce, base64url-no-pad. Becomes the sealed-bundle
    /// `bundle_id`.
    pub nonce: String,

    /// Freshness bound. ISO-8601 RFC 3339, UTC. Verifier allows ±5min
    /// skew.
    #[serde(rename = "validUntil")]
    pub valid_until: String,

    /// Optional human-readable tag for audit-log triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// What the holder is asking the VTA to do.
    pub ask: BootstrapAsk,

    /// Data Integrity proof. `eddsa-jcs-2022`, `proofPurpose =
    /// "authentication"`, signed by the holder's key.
    pub proof: Value,
}

/// Tagged enum of bootstrap intents. Extensible — add new variants as new
/// kinds of integration bootstrap emerge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BootstrapAsk {
    /// Template-driven integration bootstrap (phase 1 sole variant).
    TemplateBootstrap(TemplateBootstrapAsk),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBootstrapAsk {
    /// VTA context this integration will live in. The operator must
    /// confirm on the producer side (via CLI `--context`); this field
    /// is a hint for the common case where integration and admin agree
    /// up front.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contextHint")]
    pub context_hint: Option<String>,

    /// Template name + variables. Template must already be registered
    /// at the VTA; inline definitions are rejected.
    pub template: DidTemplateRef,

    /// Optional admin-DID template. When present, the VTA renders it,
    /// mints a fresh admin DID + keys, and binds the authorization VC
    /// + ACL row to that DID — rolling the holder over from the
    /// ephemeral `client_did` to a long-term VTA-minted admin identity
    /// in a single bootstrap round-trip.
    ///
    /// When absent, the authorization VC's subject is `client_did` and
    /// the ACL row is written for `client_did` (pre-rollover
    /// behaviour).
    ///
    /// The admin template must declare `kind: "admin"` at the VTA and
    /// be registered (built-in or operator-uploaded) just like the
    /// integration template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "adminTemplate")]
    pub admin_template: Option<DidTemplateRef>,

    /// Free-form operator note for audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Reference to a DID template registered at the VTA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidTemplateRef {
    /// Template name the VTA already knows (built-in or operator-
    /// uploaded via `pnm did-templates upload`).
    pub name: String,
    /// Variable bindings to pass to the template renderer. Must satisfy
    /// the template's `requiredVars`; `optionalVars` overrides accepted.
    #[serde(default)]
    pub vars: BTreeMap<String, Value>,
}

impl BootstrapRequest {
    /// Build + sign a bootstrap request with the holder's Ed25519 seed.
    ///
    /// `ed25519_seed` must be the private seed whose public derivation
    /// encodes to the `client_did` passed in — caller responsibility to
    /// keep them matched.
    pub async fn sign(
        ed25519_seed: &[u8; 32],
        client_did: &str,
        nonce: [u8; 16],
        validity: Duration,
        label: Option<String>,
        ask: BootstrapAsk,
    ) -> Result<Self, ProvisionIntegrationError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

        let now = Utc::now();
        let valid_until = now + validity;

        // Build a Secret whose `id` encodes the did:key-with-fragment
        // verification method shape the Data Integrity resolver
        // recognises (`did:key:zXxx#zXxx`).
        let vm_id = did_key_to_vm(client_did).ok_or_else(|| {
            ProvisionIntegrationError::Parse(format!("invalid client_did: {client_did}"))
        })?;
        let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(ed25519_seed));
        signer.id = vm_id.clone();

        // The unsigned VP body — all fields except `proof`. Data Integrity
        // signs this serialized structure (plus the signed proof config)
        // under JCS canonicalization.
        let unsigned = Self {
            context: vec![VC_V2_CONTEXT_URL.into(), BOOTSTRAP_CONTEXT_URL.into()],
            types: vec!["VerifiablePresentation".into(), "BootstrapRequest".into()],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            holder: client_did.to_string(),
            nonce: B64URL.encode(nonce),
            valid_until: rfc3339(valid_until),
            label,
            ask,
            proof: Value::Null, // placeholder — replaced after sign
        };

        let sign_options = SignOptions::new()
            .with_proof_purpose("authentication")
            .with_created(now);

        // Sign the document-with-null-proof. Verifiers must reconstruct
        // the same shape to re-derive the canonical bytes.
        let mut signing_doc = serde_json::to_value(&unsigned)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize VP: {e}")))?;
        // Strip `proof` before signing — JCS is sensitive to field
        // presence; the verifier sees the final VP with `proof`
        // populated, so sign-time must use the same shape after the
        // proof is removed.
        if let Some(obj) = signing_doc.as_object_mut() {
            obj.remove("proof");
        }

        let proof = DataIntegrityProof::sign(&signing_doc, &signer, sign_options)
            .await
            .map_err(|e| ProvisionIntegrationError::DataIntegrity(format!("sign VP: {e}")))?;

        let mut out = unsigned;
        out.proof = serde_json::to_value(&proof)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("serialize proof: {e}")))?;
        Ok(out)
    }

    /// Verify the proof + freshness + structure, returning the typestate
    /// form that downstream handlers consume.
    pub fn verify(self) -> Result<VerifiedBootstrapRequest, ProvisionIntegrationError> {
        // Structure checks first (cheap, deterministic).
        if !self.types.iter().any(|t| t == "VerifiablePresentation") {
            return Err(ProvisionIntegrationError::InvalidClaim(
                "type array must include 'VerifiablePresentation'".into(),
            ));
        }
        if !self.types.iter().any(|t| t == "BootstrapRequest") {
            return Err(ProvisionIntegrationError::InvalidClaim(
                "type array must include 'BootstrapRequest'".into(),
            ));
        }

        // Holder DID must be a decodable did:key (Ed25519).
        let holder_ed_pub = did_key_helpers::did_key_to_ed25519_pub(&self.holder)
            .map_err(|e| ProvisionIntegrationError::HolderMismatch(format!("holder: {e}")))?;

        // Parse the proof out.
        let proof: DataIntegrityProof = serde_json::from_value(self.proof.clone())
            .map_err(|e| ProvisionIntegrationError::BadProof(format!("parse proof: {e}")))?;

        // Cryptosuite check — only JCS is accepted here. If we add RDFC
        // later, widen this allowlist.
        if !matches!(proof.cryptosuite, CryptoSuite::EddsaJcs2022) {
            return Err(ProvisionIntegrationError::BadProof(format!(
                "unsupported cryptosuite {:?} (expected eddsa-jcs-2022)",
                proof.cryptosuite
            )));
        }

        // Proof's `verificationMethod` must live under the holder DID
        // (same DID, any fragment). Prevents a proof by someone else's
        // key being accepted via a forged `holder` field.
        let vm_did = proof
            .verification_method
            .split_once('#')
            .map(|(d, _)| d)
            .ok_or_else(|| {
                ProvisionIntegrationError::HolderMismatch("verificationMethod missing '#'".into())
            })?;
        if vm_did != self.holder {
            return Err(ProvisionIntegrationError::HolderMismatch(format!(
                "verificationMethod DID '{}' does not match holder '{}'",
                vm_did, self.holder
            )));
        }

        // Verify the proof against the document with `proof` stripped —
        // same shape that was signed.
        let mut signing_doc = serde_json::to_value(&self)
            .map_err(|e| ProvisionIntegrationError::Parse(format!("re-serialize VP: {e}")))?;
        if let Some(obj) = signing_doc.as_object_mut() {
            obj.remove("proof");
        }

        proof
            .verify_with_public_key(&signing_doc, &holder_ed_pub, VerifyOptions::new())
            .map_err(|e| ProvisionIntegrationError::BadProof(format!("verify VP: {e}")))?;

        // Freshness (±5min skew).
        let now = Utc::now();
        let skew = Duration::minutes(5);
        let vu = self
            .valid_until
            .parse::<DateTime<Utc>>()
            .map_err(|e| ProvisionIntegrationError::Parse(format!("validUntil: {e}")))?;
        if vu + skew < now {
            return Err(ProvisionIntegrationError::Expired(format!(
                "validUntil {vu} has passed"
            )));
        }

        Ok(VerifiedBootstrapRequest { inner: self })
    }
}

/// Post-verification form. Only constructable via
/// [`BootstrapRequest::verify`]. Any function that takes this is
/// guaranteed to be looking at a verified request whose `holder` actually
/// signed the bytes and whose `validUntil` has not passed.
#[derive(Debug, Clone)]
pub struct VerifiedBootstrapRequest {
    inner: BootstrapRequest,
}

impl VerifiedBootstrapRequest {
    /// The ephemeral `did:key` that signed this request.
    pub fn holder(&self) -> &str {
        &self.inner.holder
    }

    /// The 16-byte nonce (decoded). Becomes the sealed-bundle
    /// `bundle_id`.
    pub fn decode_nonce(&self) -> Result<[u8; 16], SealedTransferError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let raw = B64URL
            .decode(&self.inner.nonce)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
        raw.try_into()
            .map_err(|_| SealedTransferError::Wire("nonce must be 16 bytes".into()))
    }

    /// Raw 32-byte Ed25519 pubkey under `holder`'s did:key.
    pub fn decode_client_ed25519_pub(&self) -> Result<[u8; 32], ProvisionIntegrationError> {
        did_key_helpers::did_key_to_ed25519_pub(&self.inner.holder)
            .map_err(|e| ProvisionIntegrationError::HolderMismatch(format!("holder did:key: {e}")))
    }

    /// X25519 pubkey derived from the holder's Ed25519 pub, suitable for
    /// HPKE seal.
    pub fn decode_client_x25519_pub(&self) -> Result<[u8; 32], ProvisionIntegrationError> {
        let ed = self.decode_client_ed25519_pub()?;
        did_key_helpers::ed25519_pub_to_x25519_bytes(&ed).map_err(|e| {
            ProvisionIntegrationError::HolderMismatch(format!("holder X25519 derivation: {e}"))
        })
    }

    /// The operator's bootstrap intent. Phase 1: always `TemplateBootstrap`.
    pub fn ask(&self) -> &BootstrapAsk {
        &self.inner.ask
    }

    pub fn label(&self) -> Option<&str> {
        self.inner.label.as_deref()
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    pub fn valid_until(&self) -> &str {
        &self.inner.valid_until
    }

    /// Escape hatch for callers that need the raw VP JSON (e.g., to
    /// archive the request alongside the issued bundle for audit).
    pub fn as_wire(&self) -> &BootstrapRequest {
        &self.inner
    }

    /// Take ownership of the underlying wire form.
    pub fn into_wire(self) -> BootstrapRequest {
        self.inner
    }
}

// Helpers ---------------------------------------------------------------

/// Build the verificationMethod id for a `did:key:z6Mk...` string —
/// `did:key:z6Mk...#z6Mk...`.
fn did_key_to_vm(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:key:")?;
    Some(format!("{did}#{rest}"))
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_transfer::generate_ed25519_keypair;

    fn sample_ask() -> BootstrapAsk {
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "didcomm-mediator".into(),
                vars: BTreeMap::from([(
                    "URL".to_string(),
                    Value::String("https://mediator.example.com".into()),
                )]),
            },
            admin_template: None,
            note: None,
        })
    }

    fn sample_ask_with_admin_rollover() -> BootstrapAsk {
        BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "didcomm-mediator".into(),
                vars: BTreeMap::from([(
                    "URL".to_string(),
                    Value::String("https://mediator.example.com".into()),
                )]),
            },
            admin_template: Some(DidTemplateRef {
                name: "vta-admin".into(),
                vars: BTreeMap::new(),
            }),
            note: None,
        })
    }

    fn sample_client_did(seed_byte: u8) -> ([u8; 32], String) {
        let (seed, pub_bytes) = {
            let (s, p) = generate_ed25519_keypair();
            (*s, p)
        };
        let _ = seed_byte;
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        (seed, did)
    }

    #[tokio::test]
    async fn sign_and_verify_round_trip() {
        let (seed, client_did) = sample_client_did(1);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [7u8; 16],
            Duration::hours(1),
            Some("smoke test".into()),
            sample_ask(),
        )
        .await
        .unwrap();

        assert_eq!(vp.holder, client_did);
        assert!(vp.types.iter().any(|t| t == "VerifiablePresentation"));
        assert!(vp.types.iter().any(|t| t == "BootstrapRequest"));

        let verified = vp.verify().expect("verify signed VP");
        assert_eq!(verified.holder(), client_did);
        assert_eq!(verified.decode_nonce().unwrap(), [7u8; 16]);
        assert!(matches!(verified.ask(), BootstrapAsk::TemplateBootstrap(_)));
        assert_eq!(verified.label(), Some("smoke test"));
    }

    #[tokio::test]
    async fn roundtrip_via_json() {
        let (seed, client_did) = sample_client_did(2);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [9u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let json = serde_json::to_string(&vp).unwrap();
        let parsed: BootstrapRequest = serde_json::from_str(&json).unwrap();
        parsed.verify().expect("verify deserialized VP");
    }

    #[tokio::test]
    async fn tampered_nonce_rejected() {
        let (seed, client_did) = sample_client_did(3);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [1u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker flips the nonce to a different value while keeping the
        // proof unchanged — must fail.
        vp.nonce = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 16])
        };

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn tampered_ask_rejected() {
        let (seed, client_did) = sample_client_did(4);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [5u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker swaps the requested template to a different one.
        vp.ask = BootstrapAsk::TemplateBootstrap(TemplateBootstrapAsk {
            context_hint: Some("prod-mediator".into()),
            template: DidTemplateRef {
                name: "attacker-template".into(),
                vars: BTreeMap::new(),
            },
            admin_template: None,
            note: None,
        });

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn expired_request_rejected() {
        let (seed, client_did) = sample_client_did(5);
        // Sign with negative validity — validUntil is already in the past.
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [8u8; 16],
            Duration::hours(-2),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::Expired(_)),
            "expected Expired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn admin_template_round_trips_through_sign_verify() {
        let (seed, client_did) = sample_client_did(11);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [12u8; 16],
            Duration::hours(1),
            Some("rollover".into()),
            sample_ask_with_admin_rollover(),
        )
        .await
        .unwrap();

        // VP must serialize the new field with its `adminTemplate` JSON
        // name, not the snake_case Rust name.
        let json = serde_json::to_value(&vp).unwrap();
        let admin_tpl = &json["ask"]["adminTemplate"];
        assert!(!admin_tpl.is_null(), "adminTemplate must serialize");
        assert_eq!(admin_tpl["name"], "vta-admin");

        // Round-trip through deserialize + verify; field must survive.
        let parsed: BootstrapRequest = serde_json::from_value(json).unwrap();
        let verified = parsed.verify().expect("verify");
        let BootstrapAsk::TemplateBootstrap(ask) = verified.ask();
        let admin = ask
            .admin_template
            .as_ref()
            .expect("admin_template preserved");
        assert_eq!(admin.name, "vta-admin");
    }

    #[tokio::test]
    async fn admin_template_omitted_is_backward_compatible() {
        // Older callers built `TemplateBootstrapAsk` without the new
        // field; their on-the-wire JSON has no `adminTemplate` key. That
        // shape must still deserialize and verify.
        let (seed, client_did) = sample_client_did(13);
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [14u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        let json = serde_json::to_value(&vp).unwrap();
        // Confirm the field really is absent on the wire — `skip_serializing_if`
        // keeps the legacy shape stable when callers don't set it.
        assert!(
            json["ask"].get("adminTemplate").is_none(),
            "absent field must be omitted from wire JSON, got: {}",
            json["ask"]
        );

        let parsed: BootstrapRequest = serde_json::from_value(json).unwrap();
        let verified = parsed.verify().expect("verify legacy-shape VP");
        let BootstrapAsk::TemplateBootstrap(ask) = verified.ask();
        assert!(ask.admin_template.is_none());
    }

    #[tokio::test]
    async fn tampered_admin_template_rejected() {
        // Same threat model as `tampered_ask_rejected` but for the new
        // field: an attacker editing the admin template name after
        // signing must fail proof verification.
        let (seed, client_did) = sample_client_did(15);
        let mut vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [16u8; 16],
            Duration::hours(1),
            None,
            sample_ask_with_admin_rollover(),
        )
        .await
        .unwrap();

        let BootstrapAsk::TemplateBootstrap(ref mut ask) = vp.ask;
        ask.admin_template = Some(DidTemplateRef {
            name: "attacker-admin-template".into(),
            vars: BTreeMap::new(),
        });

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::BadProof(_)),
            "expected BadProof, got {err:?}"
        );
    }

    #[tokio::test]
    async fn holder_swap_rejected() {
        let (seed_a, did_a) = sample_client_did(6);
        let (_, did_b) = sample_client_did(7);

        let mut vp = BootstrapRequest::sign(
            &seed_a,
            &did_a,
            [4u8; 16],
            Duration::hours(1),
            None,
            sample_ask(),
        )
        .await
        .unwrap();

        // Attacker rewrites the holder field to point at did_b, hoping the
        // verifier will resolve did_b's pubkey. Proof still signed by did_a.
        vp.holder = did_b;

        let err = vp.verify().unwrap_err();
        assert!(
            matches!(err, ProvisionIntegrationError::HolderMismatch(_)),
            "expected HolderMismatch, got {err:?}"
        );
    }

    #[test]
    fn client_x25519_derivation_matches_sealed_transfer() {
        // A verified request's decode_client_x25519_pub() must agree with
        // deriving X25519 directly from the Ed25519 seed through the
        // sealed-transfer helper.
        use crate::sealed_transfer::ed25519_seed_to_x25519_secret;
        use crate::sealed_transfer::hpke::{open, seal};

        let (seed, ed_pub) = {
            let (s, p) = generate_ed25519_keypair();
            (*s, p)
        };
        let did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&ed_pub);

        // Simulate a VerifiedBootstrapRequest by directly constructing it
        // (tests need not sign/verify to exercise the derivation path).
        let wire = BootstrapRequest {
            context: vec![VC_V2_CONTEXT_URL.into(), BOOTSTRAP_CONTEXT_URL.into()],
            types: vec!["VerifiablePresentation".into(), "BootstrapRequest".into()],
            id: "urn:uuid:test".into(),
            holder: did.clone(),
            nonce: {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16])
            },
            valid_until: "2099-01-01T00:00:00Z".into(),
            label: None,
            ask: sample_ask(),
            proof: Value::Null,
        };
        let verified = VerifiedBootstrapRequest { inner: wire };

        let recipient_x_pub = verified.decode_client_x25519_pub().unwrap();
        let sealed = seal(&recipient_x_pub, b"hello", b"aad").unwrap();

        let x_secret = ed25519_seed_to_x25519_secret(&seed);
        let opened = open(&x_secret, &sealed, b"aad").unwrap();
        assert_eq!(opened, b"hello");
    }
}
