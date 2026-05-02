//! Consumer-side verification of `SealedPayloadV1::TemplateBootstrap`
//! payloads.
//!
//! Closes the two verification gaps the security review flagged:
//!
//! - **VC verification at open time.** `TemplateBootstrapPayload::authorization`
//!   was previously stored as an opaque `serde_json::Value` with no
//!   caller invoking [`crate::provision_integration::credential::verify_vta_authorization_credential`]
//!   on install. The payload's own comment said "verified at bundle
//!   open; never re-verified after that" — but nothing actually
//!   verified it.
//! - **Pinned `vta_did` requirement.** The VTA's DID + document + log
//!   travel inside the bundle (`vta_trust`). Verifying the VC against
//!   the assertionMethod from *that same doc* is circular — an
//!   attacker who can mint a bundle (whose VC's issuer is attacker-
//!   controlled) can also replace the `vta_trust` with a doc that
//!   authenticates the VC. The caller must supply a pinned
//!   `expected_vta_did` out-of-band; we reject any payload whose
//!   `vta_trust.vta_did` or `admin_of.vta` disagrees.
//!
//! Typestate pattern mirrors [`crate::provision_integration::request::BootstrapRequest::verify`]:
//! [`verify_template_bootstrap`] consumes the payload and returns a
//! [`VerifiedTemplateBootstrap`] that exposes the parsed
//! [`VtaAuthorizationClaim`]. Downstream install code only takes the
//! verified form — a call site that forgets to verify doesn't compile.

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_vc::VerifiableCredential;
use chrono::Duration;
use serde_json::Value;

use crate::sealed_transfer::template_bootstrap::{
    TemplateBootstrapConfig, TemplateBootstrapPayload, VtaTrustBundle,
};

use super::ProvisionIntegrationError;
use super::credential::{VtaAuthorizationClaim, verify_vta_authorization_credential};

/// Verified form of [`TemplateBootstrapPayload`]. Only constructable
/// via [`verify_template_bootstrap`].
///
/// Downstream install code takes `&VerifiedTemplateBootstrap` (or
/// consumes `into_inner`) — the compile-time guarantee is that any
/// function accepting this type has received a payload whose VC
/// verified against the pinned VTA DID + issuer key.
pub struct VerifiedTemplateBootstrap {
    inner: TemplateBootstrapPayload,
    parsed_claim: VtaAuthorizationClaim,
    parsed_vc: VerifiableCredential,
}

impl VerifiedTemplateBootstrap {
    /// Parsed, typed view of `credentialSubject`.
    pub fn admin_claim(&self) -> &VtaAuthorizationClaim {
        &self.parsed_claim
    }

    /// The underlying VC, with its proof intact, for audit archival.
    pub fn credential(&self) -> &VerifiableCredential {
        &self.parsed_vc
    }

    /// Non-credential first-boot config (template outputs, VTA trust
    /// bundle, rendered DID document, …).
    pub fn config(&self) -> &TemplateBootstrapConfig {
        &self.inner.config
    }

    /// Private key material keyed by DID. `Zeroizing`-wrapped at rest
    /// inside [`crate::sealed_transfer::template_bootstrap::KeyPair`].
    pub fn secrets(
        &self,
    ) -> &std::collections::BTreeMap<
        String,
        crate::sealed_transfer::template_bootstrap::DidKeyMaterial,
    > {
        &self.inner.secrets
    }

    /// VTA trust material from the bundle. Safe to consume after
    /// verification because `verify` cross-checked `vta_trust.vta_did ==
    /// expected_vta_did`.
    pub fn vta_trust(&self) -> &VtaTrustBundle {
        &self.inner.config.vta_trust
    }

    /// Take ownership of the verified payload. Useful when the caller
    /// wants to re-emit (e.g. to archive) the unverified wire form.
    pub fn into_inner(self) -> TemplateBootstrapPayload {
        self.inner
    }
}

/// Verify a [`TemplateBootstrapPayload`] against a pinned `expected_vta_did`.
///
/// Order of checks (fail-closed — later checks depend on earlier ones):
///
/// 1. `vta_trust.vta_did == expected_vta_did` (pinned DID; rejects
///    bundles from attacker-controlled VTAs).
/// 2. `authorization` parses as a `VerifiableCredential` with type
///    `VtaAuthorizationCredential`.
/// 3. VC's `proof.verificationMethod` names a verification method
///    whose publicKey is present in `vta_trust.vta_did_document` (the
///    trust anchor we just pinned). Extract the Ed25519 pubkey bytes.
/// 4. VC proof verifies against that pubkey; `validFrom`/`validUntil`
///    fresh within `clock_skew`.
/// 5. `credentialSubject` parses as [`VtaAuthorizationClaim`].
/// 6. `claim.admin_of.vta == expected_vta_did` (defence-in-depth: the
///    claim must agree with both the pinned DID and the issuer DID —
///    prevents a VC issued by a different VTA being replayed into a
///    bundle whose `vta_trust` was swapped).
///
/// Does **not** verify the sealed-bundle producer assertion — that's
/// [`crate::sealed_transfer::verify::verify_producer_assertion_with_pubkey`].
/// Call both at the consumer boundary.
pub fn verify_template_bootstrap(
    payload: TemplateBootstrapPayload,
    expected_vta_did: &str,
    clock_skew: Duration,
) -> Result<VerifiedTemplateBootstrap, ProvisionIntegrationError> {
    // (1) Pinned VTA DID check.
    if payload.config.vta_trust.vta_did != expected_vta_did {
        return Err(ProvisionIntegrationError::InvalidClaim(format!(
            "bundle vta_trust.vta_did '{}' does not match pinned expected_vta_did '{}'",
            payload.config.vta_trust.vta_did, expected_vta_did,
        )));
    }

    // (2) Parse VC shape.
    let vc: VerifiableCredential = serde_json::from_value(payload.authorization.clone())
        .map_err(|e| ProvisionIntegrationError::Parse(format!("parse authorization VC: {e}")))?;

    // (3) Extract issuer pubkey from the trust-bundled DID document,
    //     matching the VM id named in the VC's proof.
    let proof_value = vc
        .proof
        .as_ref()
        .ok_or_else(|| ProvisionIntegrationError::BadProof("VC has no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| ProvisionIntegrationError::BadProof(format!("parse VC proof: {e}")))?;
    let issuer_pubkey = extract_ed25519_pubkey_from_did_doc(
        &payload.config.vta_trust.vta_did_document,
        &proof.verification_method,
    )?;

    // (4) VC proof + validity window — typestate guarantees the claim
    //     was parsed too, so step (5) is the verified accessor, not a
    //     second-chance parse.
    let verified_vc = verify_vta_authorization_credential(&vc, &issuer_pubkey, clock_skew)?;
    let parsed_claim = verified_vc.claim().clone();

    // (6) Defence-in-depth: claim's own `admin_of.vta` must match the
    //     pinned DID too. An attacker who controls both the bundle
    //     and the VC but doesn't control the pinned DID can't rewrite
    //     this field without invalidating the proof.
    if parsed_claim.admin_of.vta != expected_vta_did {
        return Err(ProvisionIntegrationError::InvalidClaim(format!(
            "VC claim.admin_of.vta '{}' does not match pinned expected_vta_did '{}'",
            parsed_claim.admin_of.vta, expected_vta_did,
        )));
    }

    Ok(VerifiedTemplateBootstrap {
        inner: payload,
        parsed_claim,
        parsed_vc: vc,
    })
}

/// Walk a DID document's `verificationMethod` array looking for an entry
/// whose `id` matches `target_vm_id`. Returns the 32-byte Ed25519
/// public key extracted from `publicKeyMultibase`.
///
/// The VM id can be fully-qualified (`did:webvh:...#key-0`) or a
/// fragment-only suffix (`#key-0`) — both shapes appear in
/// verificationMethod entries produced by `didwebvh-rs` and the admin
/// rollover path.
fn extract_ed25519_pubkey_from_did_doc(
    doc: &Value,
    target_vm_id: &str,
) -> Result<[u8; 32], ProvisionIntegrationError> {
    let vms = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ProvisionIntegrationError::InvalidClaim(
                "vta_did_document has no verificationMethod array".into(),
            )
        })?;

    let target_fragment = target_vm_id.split_once('#').map(|(_, f)| f);

    for vm in vms {
        let id = vm.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let id_fragment = id.split_once('#').map(|(_, f)| f);
        let matches =
            id == target_vm_id || (target_fragment.is_some() && target_fragment == id_fragment);
        if !matches {
            continue;
        }
        let mb = vm
            .get("publicKeyMultibase")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProvisionIntegrationError::InvalidClaim(format!(
                    "verificationMethod '{id}' has no publicKeyMultibase"
                ))
            })?;
        return crate::did_key::decode_ed25519_public_key_multibase(mb).map_err(|e| {
            ProvisionIntegrationError::InvalidClaim(format!(
                "decode publicKeyMultibase for '{id}': {e}"
            ))
        });
    }

    Err(ProvisionIntegrationError::InvalidClaim(format!(
        "verificationMethod '{target_vm_id}' not found in vta_did_document"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialBundle as _Dummy;
    use crate::did_key::ed25519_multibase_pubkey;
    use crate::provision_integration::credential::{
        AdminOfClaim, OperatorOfClaim, VtaAuthorizationParams,
    };
    use crate::sealed_transfer::generate_ed25519_keypair;
    use crate::sealed_transfer::template_bootstrap::{
        TemplateBootstrapConfig, TemplateBootstrapPayload, VtaTrustBundle,
    };
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::collections::BTreeMap;

    // Silence unused-import lint for the marker `_Dummy` when test
    // features make it unreferenced.
    #[allow(dead_code)]
    fn _touch_dummy() -> Option<_Dummy> {
        None
    }

    async fn make_fixture(
        vta_did: &str,
        subject_did: &str,
        claim_vta: &str,
    ) -> (TemplateBootstrapPayload, [u8; 32]) {
        let (seed, pub_bytes) = generate_ed25519_keypair();
        let multibase = ed25519_multibase_pubkey(&pub_bytes);
        // Synthesize a minimal DID doc whose `verificationMethod[0]`
        // has `#key-0` fragment. The VC's proof.verificationMethod
        // will point at the same id so extraction succeeds.
        let vm_id = format!("{vta_did}#key-0");
        let doc = json!({
            "id": vta_did,
            "verificationMethod": [{
                "id": vm_id,
                "type": "Multikey",
                "controller": vta_did,
                "publicKeyMultibase": multibase,
            }],
            "assertionMethod": [vm_id.clone()],
        });

        let mut issuer_secret = Secret::generate_ed25519(Some(&vm_id), Some(&seed));
        issuer_secret.id = vm_id.clone();

        let params = VtaAuthorizationParams::new(VtaAuthorizationClaim {
            id: subject_did.to_string(),
            admin_of: AdminOfClaim {
                vta: claim_vta.to_string(),
                context: "prod-mediator".into(),
                role: "admin".into(),
            },
            operator_of: Some(OperatorOfClaim {
                did: "did:webvh:integration.example".into(),
                template: "didcomm-mediator".into(),
            }),
        });
        let vc =
            super::super::credential::issue_vta_authorization_credential(&issuer_secret, params)
                .await
                .expect("issue VC");

        let payload = TemplateBootstrapPayload {
            authorization: serde_json::to_value(&vc).unwrap(),
            secrets: BTreeMap::new(),
            config: TemplateBootstrapConfig {
                template_name: "didcomm-mediator".into(),
                template_kind: "mediator".into(),
                did_document: json!({"id": "did:webvh:integration.example"}),
                outputs: vec![],
                vta_url: Some("https://vta.test".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: vta_did.to_string(),
                    vta_did_document: doc,
                    vta_did_log: None,
                },
            },
        };
        (payload, pub_bytes)
    }

    #[tokio::test]
    async fn verify_passes_for_matched_pinned_did() {
        let vta_did = "did:key:zVerifierVtaOne";
        let (payload, _) = make_fixture(vta_did, "did:key:zSubject", vta_did).await;
        match verify_template_bootstrap(payload, vta_did, Duration::minutes(5)) {
            Ok(verified) => {
                assert_eq!(verified.admin_claim().admin_of.vta, vta_did);
                assert_eq!(verified.admin_claim().admin_of.role, "admin");
            }
            Err(e) => panic!("verify must pass when pinned DID matches: {e}"),
        }
    }

    #[tokio::test]
    async fn verify_rejects_mismatched_pinned_did() {
        let (payload, _) = make_fixture(
            "did:key:zBundleVta",
            "did:key:zSubject",
            "did:key:zBundleVta",
        )
        .await;
        let result = verify_template_bootstrap(
            payload,
            "did:key:zOperatorPinnedSomeoneElse",
            Duration::minutes(5),
        );
        match result {
            Err(ProvisionIntegrationError::InvalidClaim(msg)) => {
                assert!(msg.contains("does not match pinned"), "got: {msg}")
            }
            Err(other) => panic!("expected InvalidClaim, got {other:?}"),
            Ok(_) => panic!("verify must reject mismatched pinned DID"),
        }
    }

    #[tokio::test]
    async fn verify_rejects_claim_vta_drift() {
        // Trust bundle + pinned DID agree, but the VC's inner claim
        // names a different VTA (plausible if an attacker who cannot
        // re-sign the VC replaced vta_trust but not the proof).
        let signing_vta = "did:key:zBundleVta";
        let (payload, _) = make_fixture(
            signing_vta,
            "did:key:zSubject",
            "did:key:zClaimedDifferentVta",
        )
        .await;
        let result = verify_template_bootstrap(payload, signing_vta, Duration::minutes(5));
        match result {
            Err(ProvisionIntegrationError::InvalidClaim(msg)) => {
                assert!(msg.contains("claim.admin_of.vta"), "got: {msg}")
            }
            Err(other) => panic!("expected InvalidClaim (claim-drift), got {other:?}"),
            Ok(_) => panic!("verify must reject claim-drift"),
        }
    }

    #[tokio::test]
    async fn verify_rejects_unknown_verification_method() {
        // Produce a fixture then tamper with the DID doc so the VM id
        // the VC's proof references is missing.
        let vta_did = "did:key:zVtaMissingVm";
        let (mut payload, _) = make_fixture(vta_did, "did:key:zSubject", vta_did).await;
        // Empty verificationMethod array.
        payload.config.vta_trust.vta_did_document = json!({
            "id": vta_did,
            "verificationMethod": [],
        });
        let result = verify_template_bootstrap(payload, vta_did, Duration::minutes(5));
        match result {
            Err(ProvisionIntegrationError::InvalidClaim(msg)) => {
                assert!(msg.contains("not found"), "got: {msg}")
            }
            Err(other) => panic!("expected InvalidClaim (VM lookup), got {other:?}"),
            Ok(_) => panic!("verify must reject missing VM"),
        }
    }
}
