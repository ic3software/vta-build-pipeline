//! `POST /v1/join-requests/{id}/approve` + `/reject` — admin
//! decision endpoints (M1.10.1).
//!
//! Approve atomically writes the ACL row (`VtcRole::Member`),
//! the Member record, and the audit envelopes
//! (`JoinRequestApproved` + `MemberAdded`). The applicant_did is
//! already validated at submit time so the only failure modes
//! here are auth + duplicate-membership.

use affinidi_status_list::StatusPurpose;
use affinidi_vc::VerifiableCredential;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::info;
use uuid::Uuid;

use vti_common::audit::{
    AuditEvent, CredentialIssuedData, JoinRequestData, JoinRequestRejectedData, MemberAddedData,
};
use vti_common::error::AppError;

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::credentials::vec::VEC_TYPE;
use crate::credentials::vmc::VMC_TYPE;
use crate::credentials::{
    CredentialStatusRef, RoleVecParams, VmcParams, build_role_vec, build_vmc,
};
use crate::join::{JoinStatus, get_join_request, store_join_request};
use crate::members::{Member, store_member};
use crate::server::AppState;
use crate::status_list;

const REJECT_REASON_MAX: usize = 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideResponse {
    pub request_id: Uuid,
    pub status: String,
    /// Issued VMC (M2.12). Inline so the admin caller can hand
    /// it to the applicant out-of-band; sealed-transfer to the
    /// applicant's DID lands in a follow-up milestone. `None` on
    /// the reject path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    /// Issued role VEC. Same delivery story as `vmc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
}

// ---------------------------------------------------------------------------
// Approve
// ---------------------------------------------------------------------------

pub async fn approve(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }
    if get_acl_entry(&state.acl_ks, &req.applicant_did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "{} already has an ACL row; refusing to approve a duplicate membership",
            req.applicant_did
        )));
    }

    // Write ACL first (auth-gating truth), then Member, then flip
    // the JoinRequest status. A crash between ACL + Member would
    // leave the auth path working but the metadata missing — the
    // safer direction (Phase 2 reconcile / next admin action can
    // patch the gap).
    let now = now_epoch();
    let acl = VtcAclEntry {
        did: req.applicant_did.clone(),
        role: VtcRole::Member,
        label: None,
        allowed_contexts: vec![],
        created_at: now,
        created_by: admin.0.did.clone(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &acl).await?;

    let mut member = Member::fresh(&req.applicant_did);
    store_member(&state.members_ks, &member).await?;

    // M2.12: issue VMC + role VEC + flip status-list slot. Done
    // after the ACL + Member rows are persisted so the credential
    // pointers reference a row that exists. A failure here
    // surfaces as 500 — the ACL + Member rows remain, so the
    // operator can retry via the M2.13 renewal endpoint once the
    // underlying issue is fixed.
    let (vmc, role_vec, status_list_index) =
        issue_join_credentials(&state, &req.applicant_did).await?;
    member.status_list_index = Some(status_list_index);
    member.current_vmc_id = top_level_id(&vmc);
    member.current_role_vec_id = top_level_id(&role_vec);
    store_member(&state.members_ks, &member).await?;

    req.status = JoinStatus::Approved;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestApproved(JoinRequestData {
                request_id: id.to_string(),
                transport: "rest".to_string(),
            }),
        )
        .await?;
    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::MemberAdded(MemberAddedData {
                role: VtcRole::Member.to_string(),
                via_join_request_id: Some(id.to_string()),
            }),
        )
        .await?;
    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::VmcIssued(credential_issued_data(&vmc, Some(status_list_index))?),
        )
        .await?;
    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::VecIssued(credential_issued_data(&role_vec, None)?),
        )
        .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        status_list_index,
        "join request approved"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
            vmc: Some(serde_json::to_value(&vmc).map_err(|e| {
                AppError::Internal(format!("serialise VMC for response: {e}"))
            })?),
            role_vec: Some(serde_json::to_value(&role_vec).map_err(|e| {
                AppError::Internal(format!("serialise VEC for response: {e}"))
            })?),
        }),
    ))
}

/// Allocate a revocation-list slot, mint the VMC + role VEC,
/// persist the updated status-list state. Returns the signed
/// VCs + the allocated index for the audit trail.
///
/// Sealed-transfer to the applicant's DID is deferred — for
/// M2.12 the credentials are returned inline in the approve
/// response and the admin caller hands them off out-of-band.
async fn issue_join_credentials(
    state: &AppState,
    applicant_did: &str,
) -> Result<(VerifiableCredential, VerifiableCredential, u32), AppError> {
    let signer = state.credential_signer.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credential signer not initialised — cannot mint VMC (run setup first)".into(),
        )
    })?;

    let mut row = status_list::get_state(&state.status_lists_ks, StatusPurpose::Revocation)
        .await?
        .ok_or_else(|| {
            AppError::Internal(
                "revocation status list not provisioned — set `public_url` + restart".into(),
            )
        })?;

    let slot = status_list::allocate(&mut row).ok_or_else(|| {
        AppError::Internal(format!(
            "revocation status list exhausted (capacity = {})",
            row.capacity
        ))
    })?;

    let status_ref =
        CredentialStatusRef::revocation(row.list_credential_id.clone(), slot);

    let vmc_id = format!("urn:uuid:{}", Uuid::new_v4());
    let vmc = build_vmc(
        signer,
        VmcParams::new(applicant_did)
            .with_id(vmc_id)
            .with_status_ref(status_ref)
            .with_personhood(false),
    )
    .await?;

    let vec_id = format!("urn:uuid:{}", Uuid::new_v4());
    let role_vec = build_role_vec(
        signer,
        RoleVecParams::new(applicant_did, VtcRole::Member).with_id(vec_id),
    )
    .await?;

    // Persist the status-list state *after* both VCs build
    // successfully — if either build fails we don't permanently
    // burn a slot. (The state lives only in this function's
    // local copy until the store_state call.)
    status_list::store_state(&state.status_lists_ks, &row).await?;
    status_list::maybe_emit_occupancy_warning(&row);

    Ok((vmc, role_vec, slot))
}

/// Pull the top-level `id` field off a signed VC. The
/// upstream `VerifiableCredential` type doesn't expose it
/// directly — we splice it onto the wire form via JSON, so
/// reading it back requires a JSON round-trip.
fn top_level_id(vc: &VerifiableCredential) -> Option<String> {
    serde_json::to_value(vc)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str().map(str::to_string)))
}

/// Build a [`CredentialIssuedData`] payload from a signed VC.
fn credential_issued_data(
    vc: &VerifiableCredential,
    status_list_index: Option<u32>,
) -> Result<CredentialIssuedData, AppError> {
    let id = top_level_id(vc).ok_or_else(|| {
        AppError::Internal("credential is missing top-level `id` — issuance dropped it".into())
    })?;
    let credential_type = vc
        .types
        .iter()
        .find(|t| *t == VMC_TYPE || *t == VEC_TYPE)
        .cloned()
        .ok_or_else(|| AppError::Internal("credential carries neither VMC nor VEC type".into()))?;
    let valid_from = vc
        .valid_from
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validFrom".into()))?;
    let valid_until = vc
        .valid_until
        .clone()
        .ok_or_else(|| AppError::Internal("credential missing validUntil".into()))?;
    Ok(CredentialIssuedData {
        credential_id: id,
        credential_type,
        valid_from,
        valid_until,
        status_list_index,
    })
}

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RejectBody {
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn reject(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<(StatusCode, Json<DecideResponse>), AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let reason = body.reason.unwrap_or_default();
    if reason.len() > REJECT_REASON_MAX {
        return Err(AppError::Validation(format!(
            "reject reason exceeds {REJECT_REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }

    let mut req = get_join_request(&state.join_requests_ks, id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("join request not found: {id}")))?;
    if req.status != JoinStatus::Pending {
        return Err(AppError::Conflict(format!(
            "join request {id} is {:?}, not Pending",
            req.status
        )));
    }

    req.status = JoinStatus::Rejected;
    store_join_request(&state.join_requests_ks, &req).await?;

    audit_writer
        .write(
            &admin.0.did,
            Some(&req.applicant_did),
            AuditEvent::JoinRequestRejected(JoinRequestRejectedData {
                request_id: id.to_string(),
                reason: reason.clone(),
            }),
        )
        .await?;

    info!(
        request_id = %id,
        applicant = %req.applicant_did,
        admin = %admin.0.did,
        reason_present = !reason.is_empty(),
        "join request rejected"
    );

    Ok((
        StatusCode::OK,
        Json(DecideResponse {
            request_id: id,
            status: req.status.to_string(),
            vmc: None,
            role_vec: None,
        }),
    ))
}
