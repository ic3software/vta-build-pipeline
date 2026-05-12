//! `DELETE /v1/members/me` (M1.11.1) + `DELETE /v1/members/{did}`
//! (M1.12.1).
//!
//! Both paths converge on `remove_inner` so the no-last-admin
//! invariant + disposition resolution + audit emission live in
//! exactly one place.
//!
//! ## No-last-admin invariant
//!
//! Spec §10.2: a removal that would leave the community with
//! zero admins is refused with 409 `LastAdminProtected`. The
//! check + ACL delete run inside the same critical section
//! guarded by [`LAST_ADMIN_LOCK`] so concurrent removals can't
//! race past each other.
//!
//! Phase 1 implementation: snapshot every ACL row inside the
//! lock, count Admin rows after removing the target, refuse if
//! the count would hit zero. Fjall walks are O(n) but
//! Phase-1 communities are small; Phase 2+ can swap in an
//! admin-count index.

use std::sync::LazyLock;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tokio::sync::Mutex;
use tracing::{info, warn};

use vti_common::audit::{AuditEvent, MemberRemovedData, StatusListFlippedData};
use vti_common::error::AppError;

use crate::acl::{VtcRole, delete_acl_entry, get_acl_entry, list_acl_entries};
use crate::auth::{AdminAuth, AuthClaims};
use crate::members::{Disposition, delete_member, get_member, store_member};
use crate::policy::{
    PolicyPurpose, compile as compile_policy, evaluate as evaluate_policy, get_active_policy_id,
    get_policy,
};
use crate::server::AppState;

/// Process-wide mutex that serialises every removal, self- and
/// admin- alike, so the "would this leave zero admins?" check is
/// not racy. Cannot defend against multi-process — fjall isn't
/// multi-process safe to begin with (project memory).
static LAST_ADMIN_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoveBody {
    #[serde(default)]
    pub disposition: Option<Disposition>,
    /// Optional admin-only reason. Self-remove ignores this (the
    /// member doesn't need to justify their own departure). Capped
    /// at 1024 chars at the route layer.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResponse {
    pub did: String,
    pub disposition: String,
    pub removed: bool,
}

const REASON_MAX: usize = 1024;

// ---------------------------------------------------------------------------
// DELETE /v1/members/me — M1.11.1
// ---------------------------------------------------------------------------

pub async fn self_remove(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let target_did = auth.did.clone();
    let outcome = remove_inner(
        &state,
        &auth.did,
        &target_did,
        body.disposition,
        // Self-remove ignores any caller-supplied reason — the
        // departure is the member's own decision and doesn't carry
        // an externally-meaningful justification field.
        String::new(),
        // Self-remove is unconditional (spec §10.2) — bypasses
        // the `removal.rego` allow gate. Disposition still
        // routes through the policy when the member's preference
        // is `PolicyDefault`.
        false,
    )
    .await?;
    Ok((StatusCode::OK, Json(outcome)))
}

// ---------------------------------------------------------------------------
// DELETE /v1/members/{did} — M1.12.1 (REST only)
// ---------------------------------------------------------------------------

pub async fn admin_remove(
    admin: AdminAuth,
    State(state): State<AppState>,
    Path(target_did): Path<String>,
    body: Option<Json<RemoveBody>>,
) -> Result<(StatusCode, Json<RemoveResponse>), AppError> {
    if admin.0.did == target_did {
        return Err(AppError::Validation(
            "use DELETE /v1/members/me to remove yourself — \
             DELETE /v1/members/{did} is for admins removing other members"
                .to_string(),
        ));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let reason = body.reason.unwrap_or_default();
    if reason.len() > REASON_MAX {
        return Err(AppError::Validation(format!(
            "reason exceeds {REASON_MAX} chars (got {})",
            reason.len(),
        )));
    }
    let outcome = remove_inner(
        &state,
        &admin.0.did,
        &target_did,
        body.disposition,
        reason,
        true,
    )
    .await?;
    Ok((StatusCode::OK, Json(outcome)))
}

// ---------------------------------------------------------------------------
// Shared inner removal
// ---------------------------------------------------------------------------

/// Returns `Ok(RemoveResponse)` on success or
/// `Err(AppError::Conflict)` for the no-last-admin invariant.
///
/// `actor_did` is the audit actor (self for self-remove, admin
/// for admin-remove). `target_did` is the row being removed.
/// `is_admin_remove` gates the `removal.rego` allow check —
/// self-remove is unconditional per spec §10.2.
pub async fn remove_inner(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
    disposition: Option<Disposition>,
    reason: String,
    is_admin_remove: bool,
) -> Result<RemoveResponse, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let _guard = LAST_ADMIN_LOCK.lock().await;

    let target_acl = get_acl_entry(&state.acl_ks, target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;

    let target_member = get_member(&state.members_ks, target_did).await?;
    // Capture the status-list slot **before** the disposition
    // path mutates the Member row (purge deletes it; tombstone
    // clears extensions but leaves status_list_index intact —
    // we still want to read it from the pre-mutation snapshot).
    let status_list_index = target_member.as_ref().and_then(|m| m.status_list_index);

    // Phase 2 policy step (M2.7). Admin-remove evaluates the
    // active `removal.rego` against the canonical input from
    // spec §7.3. Self-remove bypasses (spec §10.2 makes it
    // unconditional). The no-last-admin invariant + the route-
    // layer AdminAuth gate run in addition to the policy check.
    if is_admin_remove {
        let input = json!({
            "actor_did": actor_did,
            "target_did": target_did,
            "target_role": target_acl.role.to_string(),
            "reason": reason,
            "action": "remove",
            "now": Utc::now().to_rfc3339(),
        });
        if !evaluate_removal_allow(state, &input).await? {
            return Err(AppError::Forbidden(
                "removal denied by policy (removal.rego.allow returned false)".into(),
            ));
        }
    }

    // Resolve disposition. Caller's request wins; member's
    // departure_preference is the fallback; `PolicyDefault`
    // consults the active `removal.rego`'s `min_disposition`
    // output (Phase 1 plan §D6 placeholder). A non-decodable
    // policy output falls back to `Tombstone` — the boring
    // middle ground Phase 1 already used.
    let initial = disposition
        .or_else(|| target_member.as_ref().map(|m| m.departure_preference))
        .unwrap_or(Disposition::PolicyDefault);
    let resolved = match initial {
        Disposition::PolicyDefault => resolve_min_disposition(state)
            .await
            .unwrap_or(Disposition::Tombstone),
        other => other,
    };

    // No-last-admin invariant.
    if matches!(target_acl.role, VtcRole::Admin) {
        let acl_rows = list_acl_entries(&state.acl_ks).await?;
        let other_admins = acl_rows
            .iter()
            .filter(|e| e.did != target_did && matches!(e.role, VtcRole::Admin))
            .count();
        if other_admins == 0 {
            return Err(AppError::Conflict(format!(
                "refusing to remove the last admin ({target_did}) — promote another \
                 member to admin first"
            )));
        }
    }

    // Apply the disposition.
    delete_acl_entry(&state.acl_ks, target_did).await?;
    match (resolved, target_member) {
        (Disposition::Purge, _) => {
            delete_member(&state.members_ks, target_did).await?;
        }
        (Disposition::Tombstone, Some(mut m)) => {
            m.tombstone();
            store_member(&state.members_ks, &m).await?;
        }
        (Disposition::Historical, Some(mut m)) => {
            m.mark_historical();
            store_member(&state.members_ks, &m).await?;
        }
        // No Member row to operate on — Tombstone/Historical
        // semantics are trivially satisfied (nothing to keep).
        (Disposition::Tombstone | Disposition::Historical, None) => {}
        (Disposition::PolicyDefault, _) => {
            // resolve() collapsed this to Tombstone above; this
            // arm is unreachable but stays here so the match
            // remains total.
            unreachable!("PolicyDefault must resolve before dispatch");
        }
    }

    let disposition_str = match resolved {
        Disposition::Purge => "purge",
        Disposition::Tombstone => "tombstone",
        Disposition::Historical => "historical",
        Disposition::PolicyDefault => "policydefault",
    };

    audit_writer
        .write(
            actor_did,
            Some(target_did),
            AuditEvent::MemberRemoved(MemberRemovedData {
                disposition: disposition_str.into(),
                reason: reason.clone(),
            }),
        )
        .await?;

    // M2.14: flip the revocation bit + emit StatusListFlipped.
    // Best-effort — a failure here doesn't unwind the ACL +
    // Member removal (those are already persisted), but it
    // surfaces in audit + logs so an operator can re-flip
    // manually if needed.
    if let Some(slot) = status_list_index
        && let Err(e) =
            flip_revocation_for_member(state, slot, audit_writer, actor_did, target_did).await
    {
        warn!(
            error = %e,
            slot,
            target = target_did,
            "failed to flip revocation status-list bit on removal — \
             ACL/Member already removed; operator must reflip manually"
        );
    }

    info!(
        actor = actor_did,
        target = target_did,
        disposition = disposition_str,
        reason_present = !reason.is_empty(),
        "member removed"
    );

    Ok(RemoveResponse {
        did: target_did.to_string(),
        disposition: disposition_str.into(),
        removed: true,
    })
}

// ---------------------------------------------------------------------------
// Status-list helpers (M2.14)
// ---------------------------------------------------------------------------

/// Flip the revocation bit at `slot` + emit `StatusListFlipped`.
/// Used by [`remove_inner`] after the ACL + Member rows have
/// already been mutated.
async fn flip_revocation_for_member(
    state: &AppState,
    slot: u32,
    audit_writer: &vti_common::audit::AuditWriter,
    actor_did: &str,
    target_did: &str,
) -> Result<(), AppError> {
    let mut row = crate::status_list::get_state(
        &state.status_lists_ks,
        affinidi_status_list::StatusPurpose::Revocation,
    )
    .await?
    .ok_or_else(|| {
        AppError::Internal(
            "revocation status list not provisioned — set `public_url` + restart".into(),
        )
    })?;
    crate::status_list::flip(&mut row, slot, true)
        .map_err(|e| AppError::Internal(format!("flip revocation slot {slot}: {e}")))?;
    crate::status_list::store_state(&state.status_lists_ks, &row).await?;
    crate::status_list::maybe_emit_occupancy_warning(&row);

    audit_writer
        .write(
            actor_did,
            Some(target_did),
            AuditEvent::StatusListFlipped(StatusListFlippedData {
                purpose: affinidi_status_list::StatusPurpose::Revocation.to_string(),
                index: slot,
                revoked: true,
            }),
        )
        .await?;

    info!(
        actor = actor_did,
        target = target_did,
        slot,
        "revocation bit flipped"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy helpers (M2.7)
// ---------------------------------------------------------------------------

/// Evaluate the active `removal.rego`'s `allow` rule. Fails closed
/// on every error path — a daemon misconfiguration must not let
/// removals through that the operator hasn't authored a policy
/// for.
async fn evaluate_removal_allow(state: &AppState, input: &JsonValue) -> Result<bool, AppError> {
    let active_id = get_active_policy_id(&state.active_policies_ks, PolicyPurpose::Removal).await?;
    let id = match active_id {
        Some(id) => id,
        None => {
            warn!("no active removal policy — refusing admin-remove");
            return Ok(false);
        }
    };
    let policy = get_policy(&state.policies_ks, id)
        .await?
        .ok_or_else(|| AppError::Internal(format!("active removal policy {id} not found")))?;
    let compiled = compile_policy(&policy.rego_source, policy.id)?;
    let result = evaluate_policy(&compiled, "data.vtc.removal.allow", input.clone())?;
    Ok(result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Read `data.vtc.removal.min_disposition` and convert to a
/// concrete `Disposition`. Returns `None` when no policy is active
/// or the policy emits a non-string / unknown value — callers
/// fall back to `Tombstone`.
async fn resolve_min_disposition(state: &AppState) -> Option<Disposition> {
    let active_id = get_active_policy_id(&state.active_policies_ks, PolicyPurpose::Removal)
        .await
        .ok()
        .flatten()?;
    let policy = get_policy(&state.policies_ks, active_id)
        .await
        .ok()
        .flatten()?;
    let compiled = compile_policy(&policy.rego_source, policy.id).ok()?;
    let result = evaluate_policy(
        &compiled,
        "data.vtc.removal.min_disposition",
        JsonValue::Object(Default::default()),
    )
    .ok()?;
    let s = result
        .pointer("/result/0/expressions/0/value")
        .and_then(|v| v.as_str())?;
    match s {
        "purge" => Some(Disposition::Purge),
        "tombstone" => Some(Disposition::Tombstone),
        "historical" => Some(Disposition::Historical),
        other => {
            warn!(
                value = other,
                "removal.rego min_disposition emitted an unknown disposition — using Tombstone"
            );
            None
        }
    }
}
