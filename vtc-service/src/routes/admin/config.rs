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
#[allow(unused_imports)]
use crate::supervisor::SupervisorKind;
use vti_common::audit::{AuditEvent, AuditWriter, ConfigReloadedData, RestartRequestedData};

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
// Reload
// ---------------------------------------------------------------------------

/// `restart.drain_timeout` default (seconds). Hardcoded for Phase 0
/// — surfaces in the `RestartRequested` audit event and bounds the
/// graceful-shutdown wait in `run_rest_thread`. A future
/// `restart.drain_timeout` config key plugs in here.
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 30;

/// `POST /v1/admin/config/reload` response. Lists the keys whose
/// **db-layer** values were applied in-memory by this call. Keys
/// flagged `requires_restart` never appear here — they re-apply on
/// the next restart.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReloadResponse {
    pub keys_reloaded: Vec<String>,
}

/// `POST /v1/admin/config/reload` handler. Re-reads the
/// `EffectiveConfig` and diffs against the live in-memory config;
/// for each hot-reloadable key whose effective value differs, the
/// in-memory `AppConfig` is updated. Emits `ConfigReloaded` listing
/// the keys that actually changed.
///
/// **Phase 0 limitation**: only the Phase-0 registry's
/// hot-reloadable keys (`log.level` today) are propagated. Future
/// runtime-state subscribers (tracing subscriber filter handle,
/// session-cleanup interval, etc.) will plug into the same diff
/// loop.
pub async fn reload_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ReloadResponse>, AppError> {
    let audit_writer = require_audit_writer(&state)?;

    let store = ConfigStore::new(state.config_ks.clone());

    // Snapshot the live in-memory config so we can diff against what
    // the four-layer overlay currently says. Read the latest
    // effective view first, then mutate the in-memory copy under a
    // write lock so concurrent reads see a single atomic flip per
    // key.
    let new_effective = {
        let cfg = state.config.read().await;
        compute_effective_config(&cfg, &store).await?
    };

    // Compare per-key effective values against `EffectiveConfig`'s
    // serialised snapshot of the same `AppConfig` shape. For Phase 0
    // the registry has three keys (`server.host`, `server.port`,
    // `log.level`). Server keys are `requires_restart` so they
    // never re-apply here.
    let mut keys_reloaded = Vec::new();
    {
        let mut cfg = state.config.write().await;
        for def in crate::config_store::REGISTRY {
            if def.requires_restart {
                continue;
            }
            let new_value = new_effective
                .fields
                .iter()
                .find(|f| f.key == def.key)
                .map(|f| f.value.clone())
                .unwrap_or(Value::Null);
            let live_value = lookup_live(&cfg, def.key);
            if new_value != live_value && apply_to_live(&mut cfg, def.key, &new_value) {
                keys_reloaded.push(def.key.to_string());
            }
        }
    }

    audit_writer
        .write(
            "did:key:vtc-admin", // M0.6.2 will swap this for the real admin DID once
            // the audit-actor plumbing wires `AdminAuth` through.
            None,
            AuditEvent::ConfigReloaded(ConfigReloadedData {
                keys_reloaded: keys_reloaded.clone(),
            }),
        )
        .await?;

    info!(?keys_reloaded, "config reloaded");

    Ok(Json(ReloadResponse { keys_reloaded }))
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

/// `POST /v1/admin/config/restart` response when the supervisor
/// check passes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartResponse {
    /// Which supervisor the daemon detected (so the operator's
    /// admin UX can echo it back).
    pub supervisor: SupervisorKind,
    /// `drain_timeout` (seconds) the daemon will use for graceful
    /// shutdown. Mirrors `RestartRequestedData.drain_timeout_seconds`.
    pub drain_timeout_seconds: u64,
}

/// `POST /v1/admin/config/restart` handler.
///
/// Refuses (`412 Precondition Failed`,
/// `SupervisorRequired`) unless a supervisor is detected — restart
/// without an external supervisor is just "kill the process" and a
/// caller asking for `restart` likely means "have the daemon come
/// back up afterwards". Detection lives in
/// [`crate::supervisor::detect_supervisor`].
///
/// On success the handler emits `RestartRequested` to the audit
/// log *before* signalling shutdown — so the row survives even if
/// the drain wedges.
pub async fn restart_config(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RestartResponse>, AppError> {
    let audit_writer = require_audit_writer(&state)?;

    let supervisor = state.supervisor.ok_or_else(|| AppError::ServiceError {
        status: StatusCode::PRECONDITION_FAILED,
        message: "SupervisorRequired: refusing to restart without a process supervisor \
            (set VTC_SUPERVISED=1 or run under systemd / kubernetes)"
            .into(),
    })?;

    audit_writer
        .write(
            "did:key:vtc-admin",
            None,
            AuditEvent::RestartRequested(RestartRequestedData {
                drain_timeout_seconds: DEFAULT_DRAIN_TIMEOUT_SECS,
            }),
        )
        .await?;

    info!(?supervisor, "restart requested");

    // Flip the shared graceful-shutdown channel. The REST thread
    // observes this via `with_graceful_shutdown` and stops accepting
    // new connections; the storage thread flushes; supervisor
    // restarts the process. We send AFTER audit emission so a wedged
    // drain still leaves the row behind.
    let _ = state.shutdown_tx.send(true);

    Ok(Json(RestartResponse {
        supervisor,
        drain_timeout_seconds: DEFAULT_DRAIN_TIMEOUT_SECS,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_audit_writer(state: &AppState) -> Result<&AuditWriter, AppError> {
    state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })
}

/// Read the live in-memory value for `key` out of an `AppConfig`.
/// Phase-0 keys only; unknown keys return `Value::Null`.
fn lookup_live(cfg: &crate::config::AppConfig, key: &str) -> Value {
    match key {
        "server.host" => Value::String(cfg.server.host.clone()),
        "server.port" => Value::Number(cfg.server.port.into()),
        "log.level" => Value::String(cfg.log.level.clone()),
        _ => Value::Null,
    }
}

/// Apply `value` to the live in-memory `AppConfig` for `key`.
/// Returns `true` if the field changed (it should; the caller has
/// already diffed). Phase-0 keys only; unknown keys are a no-op.
///
/// **Phase 0 limitation**: this updates the field but does NOT
/// notify downstream subscribers (e.g., `tracing-subscriber`'s
/// reload Handle for `log.level`). Plumbing those subscribers is
/// a Phase-1 follow-up; for now the new value sticks for any
/// future reads of `state.config`, and `requires_restart`-flagged
/// keys (`server.*`) keep behaving correctly because they're never
/// touched here.
fn apply_to_live(cfg: &mut crate::config::AppConfig, key: &str, value: &Value) -> bool {
    // server.host / server.port are requires_restart and never reach
    // this function. Future hot-reloadable keys plug in alongside
    // `log.level` with their own arms.
    if key == "log.level"
        && let Some(s) = value.as_str()
    {
        cfg.log.level = s.to_string();
        return true;
    }
    false
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
