//! `GET / PATCH /v1/admin/config` handlers.
//!
//! Implements **M0.8.2** of the VTC MVP Phase 0 plan.
//!
//! - **GET**: returns the four-layer-merged [`EffectiveConfig`].
//! - **PATCH**: writes overrides to the db-layer (`config` keyspace),
//!   returning `{ applied, pending_restart, rejected }` so the
//!   caller can tell which keys took effect immediately, which
//!   require a daemon restart (M0.8.3), and which were rejected
//!   (and why).
//!
//! Sensitive values are run through
//! `vti_common::audit::ConfigChange::redact_if` before the
//! `ConfigChanged` audit event is emitted (audit emission is
//! deferred until `AuditWriter` lands on `AppState` post-M0.9 —
//! same pattern as `community/profile`).

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::config_store::{
    ConfigStore, EffectiveConfig, compute_effective_config, lookup, validate_value,
};
use crate::server::AppState;

/// PATCH request body: arbitrary `key → value` map. Keys not in
/// [`crate::config_store::REGISTRY`] are reported back under
/// `rejected` rather than silently dropped.
#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    #[serde(flatten)]
    pub overrides: HashMap<String, Value>,
}

/// PATCH response body. Lists which keys took effect immediately,
/// which await restart, and which were rejected.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchResponse {
    pub applied: Vec<String>,
    pub pending_restart: Vec<String>,
    pub rejected: Vec<RejectedKey>,
}

/// One rejected key + the reason. Surfaced to the caller so the
/// admin UX can present a meaningful error inline.
#[derive(Debug, Serialize)]
pub struct RejectedKey {
    pub key: String,
    pub reason: String,
}

/// GET handler.
pub async fn get_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<EffectiveConfig>, AppError> {
    let cfg = state.config.read().await;
    let store = ConfigStore::new(state.config_ks.clone());
    let eff = compute_effective_config(&cfg, &store).await?;
    Ok(Json(eff))
}

/// PATCH handler.
pub async fn patch_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<PatchRequest>,
) -> Result<(StatusCode, Json<PatchResponse>), AppError> {
    let store = ConfigStore::new(state.config_ks.clone());
    let mut applied = Vec::new();
    let mut pending_restart = Vec::new();
    let mut rejected = Vec::new();

    for (key, value) in req.overrides {
        let Some(def) = lookup(&key) else {
            rejected.push(RejectedKey {
                key,
                reason: "unknown config key (not in registry)".into(),
            });
            continue;
        };

        if let Err(e) = validate_value(def, &value) {
            rejected.push(RejectedKey {
                key,
                reason: format!("validation failed: {e}"),
            });
            continue;
        }

        if let Err(e) = store.put(&key, &value).await {
            rejected.push(RejectedKey {
                key,
                reason: format!("persistence failed: {e}"),
            });
            continue;
        }

        info!(
            key = %key,
            requires_restart = def.requires_restart,
            sensitive = def.sensitive,
            "admin config PATCH applied"
        );

        if def.requires_restart {
            pending_restart.push(key);
        } else {
            applied.push(key);
        }
    }

    // `ConfigChanged` audit emission lands when AuditWriter is wired
    // into AppState post-M0.9. The audit event's sensitive-value
    // redaction will use `ConfigChange::redact_if` from M0.1.5.

    Ok((
        StatusCode::OK,
        Json(PatchResponse {
            applied,
            pending_restart,
            rejected,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Behavioural coverage lives in `tests/admin_config.rs` — those
    // exercise the full router stack (Trust-Task header, AdminAuth
    // extractor, JSON body, three-layer effective view) via
    // `Router::oneshot`. Unit tests for the overlay + validation
    // semantics live in `crate::config_store::tests`.
}
