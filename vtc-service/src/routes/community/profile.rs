//! `GET / PUT /v1/community/profile` handlers.
//!
//! Per spec §5.1:
//!
//! - **GET**: any authenticated session may read. Returns 404
//!   `community_not_initialised` when no profile has been written
//!   yet (pre-bootstrap state).
//! - **PUT**: requires `Admin` role. Rejects changes to
//!   `community_did` (immutable). Emits a `CommunityProfileUpdated`
//!   audit event listing only the field names that actually changed.
//!
//! The trust-task validation happens in
//! [`crate::routes::router`]'s `route_with_task` layer; reaching a
//! handler implies the header matched.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tracing::info;
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::community::{CommunityProfile, CommunityProfileUpdate, load_profile, store_profile};
use crate::server::AppState;

/// GET handler. Returns the singleton profile.
pub async fn get_profile(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<CommunityProfile>, AppError> {
    let profile = load_profile(&state.community_ks)
        .await?
        .ok_or_else(|| AppError::NotFound("community profile not initialised".into()))?;
    Ok(Json(profile))
}

/// PUT response shape — echoes the updated profile + the list of
/// fields that actually changed (operator-friendly + powers the
/// audit event emitter that lands alongside this in a follow-up).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileResponse {
    pub profile: CommunityProfile,
    pub fields_changed: Vec<String>,
}

/// PUT handler. Admin-only. Refuses changes to `community_did`.
pub async fn put_profile(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Json(update): Json<CommunityProfileUpdate>,
) -> Result<(StatusCode, Json<UpdateProfileResponse>), AppError> {
    let mut profile = load_profile(&state.community_ks).await?.ok_or_else(|| {
        AppError::NotFound("community profile not initialised — cannot PUT before bootstrap".into())
    })?;

    let fields_changed = update.apply(&mut profile)?;

    if fields_changed.is_empty() {
        // Nothing changed — return 200 with the existing profile.
        // PUT semantics tolerate idempotent no-ops.
        return Ok((
            StatusCode::OK,
            Json(UpdateProfileResponse {
                profile,
                fields_changed,
            }),
        ));
    }

    store_profile(&state.community_ks, &profile).await?;
    info!(
        community_did = %profile.community_did,
        fields_changed = ?fields_changed,
        "community profile updated"
    );

    // Audit emission (`CommunityProfileUpdated` per M0.1.5) is wired
    // in once an `AuditWriter` lands in `AppState` (post-M0.9). The
    // `fields_changed` list returned here is the same shape the
    // event will carry.

    Ok((
        StatusCode::OK,
        Json(UpdateProfileResponse {
            profile,
            fields_changed,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Behavioural coverage lives in `tests/community_profile.rs` — those
    // exercise the full router stack (Trust-Task header, AdminAuth
    // extractor, JSON body) via `Router::oneshot`. Unit tests for the
    // underlying storage + patch semantics live in
    // `crate::community::profile::tests`.
}
