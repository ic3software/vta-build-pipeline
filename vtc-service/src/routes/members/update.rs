//! `PATCH /v1/members/{did}` — M1.5.1.

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use vti_common::audit::{AuditEvent, MemberUpdatedData, RoleChangedData};

use crate::acl::{VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::members::{Disposition, get_member, store_member};
use crate::routes::members::read::MemberResponse;
use crate::server::AppState;

/// Body of the PATCH request. Every field is optional; a request
/// with no fields is a no-op (200 with the current row).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemberRequest {
    pub role: Option<VtcRole>,
    pub publish_consent: Option<bool>,
    pub departure_preference: Option<Disposition>,
    pub extensions: Option<JsonValue>,
}

pub async fn update_member(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, AppError> {
    // Role=Admin is forbidden on this surface — it routes to the
    // separate promote-to-admin endpoint (spec §10.4). Catch it
    // early so the response carries an operator-friendly hint.
    if matches!(req.role, Some(VtcRole::Admin)) {
        return Err(AppError::Validation(format!(
            "role=admin is not assignable via PATCH /v1/members/{{did}}; \
             use POST /v1/members/{did}/promote-to-admin (spec §10.4) \
             so the step-up UV ceremony fires."
        )));
    }

    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let mut acl = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;
    let mut member = get_member(&state.members_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {did}")))?;

    let previous_role = acl.role.clone();
    let mut fields_changed: Vec<String> = Vec::new();
    let mut role_changed = false;

    if let Some(new_role) = req.role.clone()
        && new_role != acl.role
    {
        acl.role = new_role;
        role_changed = true;
    }

    if let Some(consent) = req.publish_consent
        && consent != member.publish_consent
    {
        member.publish_consent = consent;
        fields_changed.push("publishConsent".into());
    }
    if let Some(pref) = req.departure_preference
        && pref != member.departure_preference
    {
        member.departure_preference = pref;
        fields_changed.push("departurePreference".into());
    }
    if let Some(extensions) = req.extensions
        && extensions != member.extensions
    {
        member.extensions = extensions;
        fields_changed.push("extensions".into());
    }

    // Persist in canonical order: ACL row first (auth-gating
    // truth), then Member row. A crash between the two leaves the
    // ACL slightly ahead of the metadata, which is the safer
    // direction (the auth path keeps working).
    if role_changed {
        store_acl_entry(&state.acl_ks, &acl).await?;
    }
    if !fields_changed.is_empty() {
        store_member(&state.members_ks, &member).await?;
    }

    // Audit. Role changes are a separate variant from
    // non-role updates (spec §10.4 keeps the SIEM filter
    // simple).
    if role_changed {
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::RoleChanged(RoleChangedData {
                    previous_role: previous_role.to_string(),
                    new_role: acl.role.to_string(),
                }),
            )
            .await?;
    }
    if !fields_changed.is_empty() {
        audit_writer
            .write(
                &auth.0.did,
                Some(&did),
                AuditEvent::MemberUpdated(MemberUpdatedData {
                    fields_changed: fields_changed.clone(),
                }),
            )
            .await?;
    }

    Ok(Json(MemberResponse::from_pair_for_route(acl, member)))
}

// Re-export `from_pair` under a route-only alias so this module
// doesn't have to make the constructor public on `MemberResponse`.
impl MemberResponse {
    pub(crate) fn from_pair_for_route(acl: VtcAclEntry, member: crate::members::Member) -> Self {
        // Inline the same join the read endpoints do — duplicating
        // the body (~10 lines) is cheaper than exposing a public
        // constructor that's only used by route handlers.
        Self {
            did: member.did,
            role: acl.role,
            label: acl.label,
            joined_at: member.joined_at,
            publish_consent: member.publish_consent,
            departure_preference: member.departure_preference,
            status_list_index: member.status_list_index,
            current_vmc_id: member.current_vmc_id,
            current_role_vec_id: member.current_role_vec_id,
            extensions: member.extensions,
            personhood: member.personhood,
            personhood_asserted_at: member.personhood_asserted_at,
        }
    }
}
