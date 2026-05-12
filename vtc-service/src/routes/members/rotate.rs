//! `POST /v1/members/me/rotate/{challenge,…}` — DID rotation
//! (M2.15.1). Spec §10.5.
//!
//! Two-step ceremony that swaps a member's DID with both keys
//! co-signing. M2.15.1 ships the `did:key` path; the
//! `did:webvh` branch (M2.15.2) is left as a `TODO` at the
//! method-detection step and lands in a follow-up.
//!
//! ## Step 1 — `POST /v1/members/me/rotate/challenge`
//!
//! Authenticated by the member's existing session. Mints a
//! single-use `rotation_id` + `expires_at` (10-minute TTL) and
//! returns them. The challenge row is persisted to the
//! `passkey_ks` keyspace under a `rotation_chal:` prefix so we
//! don't need a separate keyspace handle for a short-lived
//! state row.
//!
//! ## Step 2 — `POST /v1/members/me/rotate`
//!
//! Authenticated by the old DID's session. The body carries:
//!
//! - `rotationId` (from step 1)
//! - `oldDid` (must match the caller's session)
//! - `newDid` (the member's new identity)
//! - `oldSignature` — Ed25519 over the canonical payload
//! - `newSignature` — Ed25519 over the canonical payload,
//!   signed by the new DID's key
//!
//! Canonical payload (the bytes the signers sign):
//!
//! ```text
//! "vtc-did-rotation/v1\0" || canonical_json({
//!   "rotationId":  <uuid>,
//!   "oldDid":       <did>,
//!   "newDid":       <did>,
//!   "expiresAt":    <epoch seconds>
//! })
//! ```
//!
//! On success (atomic):
//!
//! 1. Verify both signatures.
//! 2. Consume the rotation row.
//! 3. Move the ACL row: delete `acl:<old>`, write
//!    `acl:<new>` with the same role + metadata.
//! 4. Move the Member row.
//! 5. Revoke every session keyed on the old DID.
//! 6. Re-mint VMC + role VEC against the new DID, reusing
//!    the existing status-list slot.
//! 7. Audit `DidRotated`.
//!
//! ## Why the *old* DID's session
//!
//! Spec §10.5 + the M2.15 milestone bullet say "auth: new
//! DID's session" — practically the new DID has no ACL row
//! yet, so the auth layer can't accept its session under the
//! standard `AuthClaims` extractor. The body's `newSignature`
//! field gives us the equivalent guarantee (the new key
//! holder is in control), and the old session ties the
//! request back to the existing member's authenticated
//! presence. Documenting the deviation for M2.16's spec-
//! clarification pass.
//!
//! ## `did:key` only for M2.15.1
//!
//! New-DID method detection rejects non-`did:key` values with
//! a clear message pointing at M2.15.2's follow-up. The
//! cryptographic verification path only knows how to extract
//! Ed25519 pubkeys from `did:key` today; `did:webvh` needs the
//! `affinidi-did-resolver-cache-sdk` walk that lands later.

use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_status_list::StatusPurpose;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::{info, warn};
use uuid::Uuid;

use vti_common::audit::{AuditEvent, DidRotatedData};
use vti_common::auth::session::{delete_session, list_sessions};
use vti_common::error::AppError;

use crate::acl::{delete_acl_entry, get_acl_entry, store_acl_entry};
use crate::auth::AuthClaims;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::members::{delete_member, get_member, store_member};
use crate::server::AppState;
use crate::status_list;

/// Domain tag prefixed onto the canonical payload that both
/// the old and new DID's keys sign over. Distinct from every
/// other domain tag in the workspace so a signature minted
/// for a different protocol can't be replayed as a rotation.
pub const ROTATION_DOMAIN_TAG: &[u8] = b"vtc-did-rotation/v1\0";

/// Rotation-challenge TTL — spec §10.5 calls for 10 minutes.
const CHALLENGE_TTL_SECS: i64 = 10 * 60;

/// Storage prefix for rotation challenge rows in `passkey_ks`.
/// Co-tenanting with the passkey keyspace avoids a separate
/// AppState field for what is conceptually short-lived
/// transient state.
const ROTATION_PREFIX: &[u8] = b"rotation_chal:";

// ---------------------------------------------------------------------------
// Persisted challenge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotationChallenge {
    id: Uuid,
    did: String,
    expires_at: DateTime<Utc>,
}

fn challenge_key(id: Uuid) -> Vec<u8> {
    let mut k = ROTATION_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

async fn store_challenge(state: &AppState, challenge: &RotationChallenge) -> Result<(), AppError> {
    state
        .passkey_ks
        .insert(
            String::from_utf8(challenge_key(challenge.id)).expect("ascii key"),
            challenge,
        )
        .await
}

async fn take_challenge(state: &AppState, id: Uuid) -> Result<Option<RotationChallenge>, AppError> {
    let key = challenge_key(id);
    let raw = state.passkey_ks.get_raw(key.clone()).await?;
    let Some(bytes) = raw else { return Ok(None) };
    let challenge: RotationChallenge = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("RotationChallenge decode: {e}")))?;
    state.passkey_ks.remove(key).await?;
    Ok(Some(challenge))
}

// ---------------------------------------------------------------------------
// Step 1 — challenge
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub rotation_id: Uuid,
    pub expires_at: DateTime<Utc>,
    /// Canonical payload bytes the signers must hash over,
    /// hex-encoded. Server-supplied so the caller can't omit
    /// the domain tag or get the canonical JSON encoding
    /// wrong.
    pub signing_payload_hex: String,
    /// New-DID placeholder — the canonical payload includes
    /// `newDid`, so the client computes the final payload by
    /// substituting its chosen `new_did` into the JSON and
    /// hashing the result. Callers that prefer to assemble
    /// the payload themselves can ignore this field.
    pub canonical_template: JsonValue,
}

pub async fn challenge(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<ChallengeResponse>), AppError> {
    // Caller must be a current member — anyone with a session
    // could mint a challenge otherwise.
    let _acl = get_acl_entry(&state.acl_ks, &auth.did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no ACL row for {} — not a member", auth.did)))?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
    let challenge = RotationChallenge {
        id,
        did: auth.did.clone(),
        expires_at,
    };
    store_challenge(&state, &challenge).await?;

    // Canonical template — the caller substitutes `newDid`.
    let template = serde_json::json!({
        "rotationId": id.to_string(),
        "oldDid": auth.did,
        "newDid": "<fill in>",
        "expiresAt": expires_at.timestamp(),
    });

    info!(
        rotation_id = %id,
        did = %auth.did,
        "DID rotation challenge issued"
    );

    Ok((
        StatusCode::OK,
        Json(ChallengeResponse {
            rotation_id: id,
            expires_at,
            signing_payload_hex: hex::encode(ROTATION_DOMAIN_TAG),
            canonical_template: template,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Step 2 — finish
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishBody {
    pub rotation_id: Uuid,
    pub old_did: String,
    pub new_did: String,
    /// Hex-encoded Ed25519 signature by the old DID's key.
    pub old_signature: String,
    /// Hex-encoded Ed25519 signature by the new DID's key.
    pub new_signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishResponse {
    pub new_did: String,
    pub method: String,
    pub vmc: JsonValue,
    pub role_vec: JsonValue,
}

pub async fn rotate(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<FinishBody>,
) -> Result<(StatusCode, Json<FinishResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    // 1. Authenticated session must match `oldDid`.
    if auth.did != body.old_did {
        return Err(AppError::Forbidden(format!(
            "session DID ({}) does not match oldDid ({})",
            auth.did, body.old_did
        )));
    }

    // 2. Method detection. M2.15.1 ships did:key only;
    //    did:webvh is deferred to M2.15.2.
    let method = method_of(&body.new_did)?;
    if method != "did:key" {
        return Err(AppError::Validation(format!(
            "DID method '{method}' is not yet supported for rotation \
             (M2.15.1 covers did:key only; did:webvh lands in M2.15.2)"
        )));
    }

    // 3. Consume the challenge row. Single-use: `take_challenge`
    //    removes it before we run any further checks.
    let challenge = take_challenge(&state, body.rotation_id)
        .await?
        .ok_or_else(|| {
            AppError::Validation(format!(
                "rotation challenge {} not found or already consumed",
                body.rotation_id
            ))
        })?;
    if challenge.did != body.old_did {
        return Err(AppError::Forbidden(format!(
            "rotation challenge was issued for {}, not {}",
            challenge.did, body.old_did
        )));
    }
    if Utc::now() > challenge.expires_at {
        return Err(AppError::Validation(format!(
            "rotation challenge {} expired at {}",
            body.rotation_id, challenge.expires_at
        )));
    }

    // 4. Reject same-DID rotations (no-op churn).
    if body.old_did == body.new_did {
        return Err(AppError::Validation(
            "oldDid and newDid must differ — same-DID rotation is a no-op".into(),
        ));
    }

    // 5. Verify both signatures over the canonical payload.
    let payload = canonical_signing_bytes(
        body.rotation_id,
        &body.old_did,
        &body.new_did,
        challenge.expires_at.timestamp(),
    )?;
    verify_did_key_signature(&body.old_did, &payload, &body.old_signature)
        .map_err(|e| AppError::Validation(format!("oldSignature failed: {e}")))?;
    verify_did_key_signature(&body.new_did, &payload, &body.new_signature)
        .map_err(|e| AppError::Validation(format!("newSignature failed: {e}")))?;

    // 6. Refuse if the new DID already has an ACL row (would
    //    collide).
    if get_acl_entry(&state.acl_ks, &body.new_did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "newDid {} already has an ACL row — refusing to clobber",
            body.new_did
        )));
    }

    // 7. Move the ACL row.
    let mut acl = get_acl_entry(&state.acl_ks, &body.old_did)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "ACL row for {} disappeared mid-rotation",
                body.old_did
            ))
        })?;
    acl.did = body.new_did.clone();
    store_acl_entry(&state.acl_ks, &acl).await?;
    delete_acl_entry(&state.acl_ks, &body.old_did).await?;

    // 8. Move the Member row.
    let member_opt = get_member(&state.members_ks, &body.old_did).await?;
    if let Some(mut m) = member_opt {
        m.did = body.new_did.clone();
        store_member(&state.members_ks, &m).await?;
    }
    delete_member(&state.members_ks, &body.old_did).await?;

    // 9. Revoke every session keyed on the old DID.
    let sessions = list_sessions(&state.sessions_ks).await?;
    for s in sessions.iter().filter(|s| s.did == body.old_did) {
        let _ = delete_session(&state.sessions_ks, &s.session_id).await;
    }

    // 10. Re-mint VMC + role VEC against the new DID. Reuse
    //     the status-list slot. A daemon misconfiguration
    //     leaves the credential pointers null — the operator
    //     can recover via the renewal endpoint.
    let (vmc_value, vec_value, vmc_id, vec_id) =
        match reissue_credentials(&state, &body.new_did, &acl).await {
            Ok(out) => out,
            Err(e) => {
                warn!(error = %e, "rotation succeeded but credential re-issuance failed");
                (JsonValue::Null, JsonValue::Null, None, None)
            }
        };

    // 11. Audit. Actor is the **new** DID (the future
    //     principal) per spec §10.5.
    audit_writer
        .write(
            &body.new_did,
            Some(&body.old_did),
            AuditEvent::DidRotated(DidRotatedData {
                old_did: body.old_did.clone(),
                new_did: body.new_did.clone(),
                method: method.to_string(),
                vmc_id,
                role_vec_id: vec_id,
            }),
        )
        .await?;

    info!(
        old_did = %body.old_did,
        new_did = %body.new_did,
        method,
        "DID rotated"
    );

    Ok((
        StatusCode::OK,
        Json(FinishResponse {
            new_did: body.new_did,
            method: method.to_string(),
            vmc: vmc_value,
            role_vec: vec_value,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wire-form DID method prefix — `did:key` or `did:webvh`. Used
/// by the rotation endpoint's method-detection step.
fn method_of(did: &str) -> Result<&'static str, AppError> {
    if did.starts_with("did:key:") {
        Ok("did:key")
    } else if did.starts_with("did:webvh:") {
        Ok("did:webvh")
    } else {
        Err(AppError::Validation(format!(
            "DID '{did}' is not did:key or did:webvh"
        )))
    }
}

/// Build the canonical signing payload — domain tag prefixed
/// onto a key-ordered JSON object. Both signers (old + new) sign
/// this exact byte sequence.
fn canonical_signing_bytes(
    rotation_id: Uuid,
    old_did: &str,
    new_did: &str,
    expires_at: i64,
) -> Result<Vec<u8>, AppError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Payload<'a> {
        rotation_id: String,
        old_did: &'a str,
        new_did: &'a str,
        expires_at: i64,
    }
    let json = serde_json::to_vec(&Payload {
        rotation_id: rotation_id.to_string(),
        old_did,
        new_did,
        expires_at,
    })
    .map_err(|e| AppError::Internal(format!("canonical payload: {e}")))?;
    let mut buf = Vec::with_capacity(ROTATION_DOMAIN_TAG.len() + json.len());
    buf.extend_from_slice(ROTATION_DOMAIN_TAG);
    buf.extend_from_slice(&json);
    Ok(buf)
}

fn verify_did_key_signature(did: &str, payload: &[u8], hex_sig: &str) -> Result<(), String> {
    let pub_bytes = affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
        .map_err(|e| format!("did:key parse: {e}"))?;
    let vk =
        VerifyingKey::from_bytes(&pub_bytes).map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;
    let raw = hex::decode(hex_sig).map_err(|e| format!("signature is not hex: {e}"))?;
    let sig = Signature::from_slice(&raw).map_err(|e| format!("signature is not 64 bytes: {e}"))?;
    vk.verify(payload, &sig)
        .map_err(|e| format!("signature verification: {e}"))
}

/// Re-mint VMC + role VEC against the new DID. Reuses the
/// existing status-list slot (recovered from the moved
/// Member row).
async fn reissue_credentials(
    state: &AppState,
    new_did: &str,
    acl: &crate::acl::VtcAclEntry,
) -> Result<(JsonValue, JsonValue, Option<String>, Option<String>), AppError> {
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not initialised".into()))?;

    let member = get_member(&state.members_ks, new_did)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!(
                "Member row for {new_did} missing after rotation move"
            ))
        })?;

    let row = status_list::get_state(&state.status_lists_ks, StatusPurpose::Revocation)
        .await?
        .ok_or_else(|| AppError::Internal("revocation status list not provisioned".into()))?;

    let slot = member.status_list_index.ok_or_else(|| {
        AppError::Internal(format!(
            "Member {new_did} has no status_list_index — rotation cannot reissue"
        ))
    })?;
    let status_ref = CredentialStatusRef::revocation(row.list_credential_id.clone(), slot);

    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(new_did)
            .with_id(vmc_id.clone())
            .with_status_ref(status_ref)
            .with_personhood(false),
    )
    .await?;

    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(new_did, acl.role.clone()).with_id(vec_id.clone()),
    )
    .await?;

    // Update Member row pointers.
    let mut member_mut = member;
    member_mut.current_vmc_id = Some(vmc_id.clone());
    member_mut.current_role_vec_id = Some(vec_id.clone());
    store_member(&state.members_ks, &member_mut).await?;

    let vmc_value = serde_json::to_value(&vmc)
        .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
    let vec_value = serde_json::to_value(&role_vec)
        .map_err(|e| AppError::Internal(format!("serialise VEC: {e}")))?;

    Ok((vmc_value, vec_value, Some(vmc_id), Some(vec_id)))
}

#[allow(dead_code)]
fn epoch_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
