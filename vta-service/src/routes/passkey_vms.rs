//! REST routes for passkey-as-verificationMethod enrolment.
//!
//! Mounted at:
//!
//! - `POST /did/verification-methods/passkey/challenge`
//! - `POST /did/verification-methods/passkey`
//! - `GET  /did/verification-methods/passkey?did=…`
//! - `DELETE /did/verification-methods/passkey/{fragment}?did=…`
//!
//! All gated by [`AdminAuth`]. Per-DID context membership is asserted
//! inside the operations layer.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use vta_sdk::protocols::did_management::passkey_vms::{
    EnrollPasskeyChallengeResponse, EnrollPasskeySubmitBody, EnrollPasskeySubmitResponse,
    ListPasskeyVmsResponse,
};

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct PasskeyVmDidQuery {
    pub did: String,
}

#[derive(Debug, Deserialize)]
pub struct EnrollPasskeyChallengeBody {
    pub did: String,
    #[serde(default)]
    pub label: Option<String>,
}

pub async fn enroll_challenge_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<EnrollPasskeyChallengeBody>,
) -> Result<Json<EnrollPasskeyChallengeResponse>, AppError> {
    let config = state.config.read().await;
    let result = operations::passkey_vms::start_enrollment(
        &state.webvh_ks,
        &state.passkey_vms_ks,
        &config,
        &auth.0,
        &body.did,
        body.label,
    )
    .await?;
    Ok(Json(result))
}

pub async fn enroll_submit_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<EnrollPasskeySubmitBody>,
) -> Result<Json<EnrollPasskeySubmitResponse>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    let config = state.config.read().await.clone();
    let result = operations::passkey_vms::finish_enrollment(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.passkey_vms_ks,
        &*state.seed_store,
        &auth.0,
        body,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        &config,
        "rest",
    )
    .await?;
    Ok(Json(result))
}

pub async fn list_passkeys_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<PasskeyVmDidQuery>,
) -> Result<Json<ListPasskeyVmsResponse>, AppError> {
    let result = operations::passkey_vms::list_passkeys(&state.webvh_ks, &auth.0, &q.did).await?;
    Ok(Json(result))
}

pub async fn revoke_passkey_handler(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(fragment): Path<String>,
    Query(q): Query<PasskeyVmDidQuery>,
) -> Result<StatusCode, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Internal("DID resolver not available".into()))?;
    let vta_did = state.config.read().await.vta_did.clone();
    operations::passkey_vms::revoke_passkey(
        &state.keys_ks,
        &state.imported_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &*state.seed_store,
        &auth.0,
        &q.did,
        &fragment,
        did_resolver,
        &state.didcomm_bridge,
        vta_did.as_deref(),
        &state.webvh_auth_locks,
        "rest",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
