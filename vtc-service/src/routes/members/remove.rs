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
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;

use vti_common::audit::{AuditEvent, MemberRemovedData};
use vti_common::error::AppError;

use crate::acl::{VtcRole, delete_acl_entry, get_acl_entry, list_acl_entries};
use crate::auth::{AdminAuth, AuthClaims};
use crate::members::{Disposition, delete_member, get_member, store_member};
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
    let outcome = remove_inner(&state, &admin.0.did, &target_did, body.disposition, reason).await?;
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
pub async fn remove_inner(
    state: &AppState,
    actor_did: &str,
    target_did: &str,
    disposition: Option<Disposition>,
    reason: String,
) -> Result<RemoveResponse, AppError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;

    let _guard = LAST_ADMIN_LOCK.lock().await;

    let target_acl = get_acl_entry(&state.acl_ks, target_did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("member not found: {target_did}")))?;

    // Resolve disposition. Caller can override the member's
    // departure_preference; if neither is set we fall through
    // to PolicyDefault → Tombstone.
    let target_member = get_member(&state.members_ks, target_did).await?;
    let resolved = disposition
        .or_else(|| target_member.as_ref().map(|m| m.departure_preference))
        .unwrap_or_default_disposition()
        .resolve();

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

// `Option<Disposition>::unwrap_or_default_disposition()` — small
// extension that returns `PolicyDefault` when the option is
// `None`. Hand-rolled so the call site reads linearly without an
// `unwrap_or(Disposition::PolicyDefault)` literal everywhere.
trait DispositionOption {
    fn unwrap_or_default_disposition(self) -> Disposition;
}

impl DispositionOption for Option<Disposition> {
    fn unwrap_or_default_disposition(self) -> Disposition {
        self.unwrap_or(Disposition::PolicyDefault)
    }
}
