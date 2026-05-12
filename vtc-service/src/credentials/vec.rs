//! Verifiable Endorsement Credential builder — spec §6.1 / M2.9.
//!
//! Used for role grants ("admin", "moderator", …) and — in
//! Phase 3+ — community-defined endorsement values. The role
//! VEC's `endorsement` field follows spec §6.1's shape:
//!
//! ```json
//! {
//!   "endorsement": {
//!     "type": "CommunityRole",
//!     "role": "admin",
//!     "communityDid": "did:webvh:vtc.example.com:abc"
//!   }
//! }
//! ```
//!
//! The credential is re-issued on every role change (spec §6.1)
//! and on every renewal (spec §6.3 step 2) so the external chain
//! stays consistent.

use affinidi_vc::{CredentialBuilder, VerifiableCredential};
use chrono::{Duration, Utc};
use serde_json::{Map, Value as JsonValue, json};
use vti_common::error::AppError;

use crate::acl::VtcRole;

use super::LocalSigner;
use super::VEC_CONTEXT_URL;

/// Type the VEC's `type` array carries alongside
/// `VerifiableCredential`. Spec §6.1 names this credential the
/// "Verifiable Endorsement Credential"; role grants are one
/// canonical shape.
pub const VEC_TYPE: &str = "VerifiableEndorsementCredential";

/// `endorsement.type` value for a role-grant VEC. Custom
/// endorsements (Phase 3+) use community-defined types.
pub const COMMUNITY_ROLE_ENDORSEMENT_TYPE: &str = "CommunityRole";

/// Default validity for a freshly-minted role VEC. Mirrors the
/// VMC default (30d). Operators tighten via configuration.
pub const DEFAULT_ROLE_VEC_VALIDITY: Duration = Duration::days(30);

/// Parameters for [`build_role_vec`].
#[derive(Debug, Clone)]
pub struct RoleVecParams {
    /// Subject DID — the member receiving the role grant.
    pub member_did: String,
    /// Optional top-level `id` URI for the VC (typically
    /// `urn:uuid:<server-allocated>`). Mirrors
    /// [`super::vmc::VmcParams::id`].
    pub id: Option<String>,
    /// The role being granted. Spec §5.3 names four standard
    /// roles + `Custom(String)`; all five surface here via
    /// [`VtcRole::to_string`].
    pub role: VtcRole,
    /// `validUntil = now + validity`. Same default as VMC.
    pub validity: Duration,
}

impl RoleVecParams {
    pub fn new(member_did: impl Into<String>, role: VtcRole) -> Self {
        Self {
            member_did: member_did.into(),
            id: None,
            role,
            validity: DEFAULT_ROLE_VEC_VALIDITY,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_validity(mut self, validity: Duration) -> Self {
        self.validity = validity;
        self
    }
}

/// Build + sign a role VEC. `issuer = signer.issuer_did()`.
pub async fn build_role_vec(
    signer: &LocalSigner,
    params: RoleVecParams,
) -> Result<VerifiableCredential, AppError> {
    let now = Utc::now();
    let valid_until = now + params.validity;

    let endorsement = json!({
        "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
        "role": params.role.to_string(),
        "communityDid": signer.issuer_did(),
    });

    let mut subject = Map::new();
    subject.insert("id".into(), JsonValue::String(params.member_did.clone()));
    subject.insert("endorsement".into(), endorsement);

    let mut vc = CredentialBuilder::v2()
        .context(VEC_CONTEXT_URL)
        .issuer_uri(signer.issuer_did().to_string())
        .add_type(VEC_TYPE)
        .valid_from(rfc3339(now))
        .valid_until(rfc3339(valid_until))
        .subject(subject)
        .build()
        .map_err(|e| AppError::Internal(format!("VEC build: {e}")))?;

    if let Some(id) = &params.id {
        attach_top_level_id(&mut vc, id)?;
    }

    signer.sign(&mut vc).await?;
    Ok(vc)
}

/// Splice a top-level `id` onto the VC. Same JSON-round-trip
/// trick the VMC builder uses for `credentialStatus`.
fn attach_top_level_id(vc: &mut VerifiableCredential, id: &str) -> Result<(), AppError> {
    let mut as_value =
        serde_json::to_value(&*vc).map_err(|e| AppError::Internal(format!("VEC -> value: {e}")))?;
    as_value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("VEC not an object".into()))?
        .insert("id".into(), JsonValue::String(id.into()));
    *vc = serde_json::from_value(as_value)
        .map_err(|e| AppError::Internal(format!("value -> VEC: {e}")))?;
    Ok(())
}

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_vc::SubjectValue;

    const TEST_VTC_DID: &str = "did:webvh:vtc.example.com:abc";
    const MEMBER_DID: &str = "did:key:zMember1";

    fn signer() -> LocalSigner {
        LocalSigner::from_ed25519_seed(TEST_VTC_DID.into(), &[0xBB; 32])
    }

    fn subject_map(vc: &VerifiableCredential) -> Map<String, JsonValue> {
        match &vc.credential_subject {
            SubjectValue::Single(m) => m.clone(),
            SubjectValue::Multiple(v) => v[0].clone(),
        }
    }

    /// Build + verify a VEC for each standard role. Spec §5.3's
    /// matrix covers Admin/Moderator/Issuer/Member; Custom is
    /// the open-ended fifth variant.
    #[tokio::test]
    async fn role_vec_round_trips_for_each_standard_role() {
        let signer = signer();
        let cases = [
            (VtcRole::Admin, "admin"),
            (VtcRole::Moderator, "moderator"),
            (VtcRole::Issuer, "issuer"),
            (VtcRole::Member, "member"),
            (VtcRole::Custom("editor".into()), "custom:editor"),
        ];
        for (role, expected_wire) in cases {
            let vc = build_role_vec(&signer, RoleVecParams::new(MEMBER_DID, role.clone()))
                .await
                .unwrap_or_else(|e| panic!("build VEC for {role:?}: {e:?}"));

            // Type array carries VEC type.
            assert!(vc.types.iter().any(|t| t == VEC_TYPE));

            // endorsement payload.
            let subj = subject_map(&vc);
            let endorsement = &subj["endorsement"];
            assert_eq!(endorsement["type"], COMMUNITY_ROLE_ENDORSEMENT_TYPE);
            assert_eq!(endorsement["role"], expected_wire);
            assert_eq!(endorsement["communityDid"], TEST_VTC_DID);
            assert_eq!(subj["id"], MEMBER_DID);

            // Proof verifies.
            signer
                .verify(&vc)
                .unwrap_or_else(|e| panic!("VEC proof must verify for {role:?}: {e:?}"));
        }
    }

    /// Tampering with the endorsement role invalidates the
    /// proof.
    #[tokio::test]
    async fn role_vec_tampered_role_invalidates_proof() {
        let signer = signer();
        let mut vc = build_role_vec(&signer, RoleVecParams::new(MEMBER_DID, VtcRole::Member))
            .await
            .unwrap();
        let mut as_value = serde_json::to_value(&vc).unwrap();
        // Promote member to admin without re-signing.
        as_value["credentialSubject"]["endorsement"]["role"] = JsonValue::String("admin".into());
        vc = serde_json::from_value(as_value).unwrap();

        let err = signer.verify(&vc).expect_err("tampered VEC must fail");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }
}
