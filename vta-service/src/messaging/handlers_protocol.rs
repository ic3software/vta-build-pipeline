//! DIDComm handlers for protocol-management operations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Each handler is a thin adapter: parse the body, call the
//! existing operation function with `DisableTransport::Didcomm`
//! when applicable so the spec's 1h-min-TTL guard fires (criterion
//! #12), and return a typed response.
//!
//! `enable` is intentionally NOT exposed over DIDComm — DIDComm
//! isn't running yet at first-enable time, so the request couldn't
//! arrive over this transport in the first place.

#![cfg(feature = "webvh")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use vta_sdk::protocols::protocol_management;

use super::router::VtaState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::handshake::AlwaysOkProver;
use crate::operations::protocol::OpContext;
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::disable_rest::{DisableRestParams, disable_rest};
use crate::operations::protocol::drain_cancel::{DrainCancelParams, drain_cancel};
use crate::operations::protocol::enable_rest::{EnableRestParams, enable_rest};
use crate::operations::protocol::report::{ReportParams, mediator_report};
use crate::operations::protocol::rollback_didcomm::{RollbackDidcommParams, rollback_didcomm};
use crate::operations::protocol::rollback_rest::{RollbackRestParams, rollback_rest};
use crate::operations::protocol::update_didcomm::{
    MigrateAuditKind, UpdateDidcommParams, update_didcomm,
};
use crate::operations::protocol::update_rest::{UpdateRestParams, update_rest};

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

fn response<T: serde::Serialize>(msg_type: &str, result: &T) -> HandlerResult {
    let body = serde_json::to_value(result).map_err(handler_err)?;
    Ok(Some(DIDCommResponse::new(msg_type, body)))
}

fn problem_report_unauthorized(msg: impl Into<String>) -> DIDCommResponse {
    DIDCommResponse::problem_report(ProblemReport::unauthorized(msg.into()))
}

fn problem_report_conflict(msg: impl Into<String>) -> DIDCommResponse {
    DIDCommResponse::problem_report(ProblemReport::conflict(msg.into()))
}

fn problem_report_bad_request(msg: impl Into<String>) -> DIDCommResponse {
    DIDCommResponse::problem_report(ProblemReport::bad_request(msg.into()))
}

fn problem_report_internal(msg: impl Into<String>) -> DIDCommResponse {
    DIDCommResponse::problem_report(ProblemReport::internal_error(msg.into()))
}

// ── disable_didcomm over DIDComm ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DisableDidcommBody {
    #[serde(default)]
    drain_ttl_secs: u64,
}

pub async fn handle_disable_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let body: DisableDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let result = disable_didcomm(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        &auth,
        DisableDidcommParams {
            drain_ttl: Duration::from_secs(body.drain_ttl_secs),
            // Critical: this is the DIDComm transport, so the
            // 1h-min-TTL guard fires (spec criterion #12).
            transport: DisableTransport::Didcomm,
        },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::disable_didcomm::DisableDidcommError;
    match result {
        Ok(r) => response(
            protocol_management::DISABLE_DIDCOMM_RESULT,
            &serde_json::json!({
                "new_version_id": r.new_version_id,
                "prior_mediator_did": r.prior_mediator_did,
                "drains_until": r.drains_until.map(|t| t.to_rfc3339()),
            }),
        ),
        Err(DisableDidcommError::DidcommNotEnabled) => Ok(Some(problem_report_conflict(
            "DIDComm is not currently enabled",
        ))),
        Err(DisableDidcommError::NoProtocolRemaining) => Ok(Some(problem_report_conflict(
            "cannot disable DIDComm — REST is also disabled",
        ))),
        Err(DisableDidcommError::DrainTtlTooShortForDidcomm) => {
            Ok(Some(problem_report_bad_request(
                "drain-ttl 0s over DIDComm transport is not permitted (1h minimum)",
            )))
        }
        Err(DisableDidcommError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── update_didcomm over DIDComm ───────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateDidcommBody {
    new_mediator_did: String,
    drain_ttl_secs: u64,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    handshake_timeout_secs: Option<u64>,
    #[serde(default)]
    rollback: bool,
}

pub async fn handle_update_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let body: UpdateDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;

    // For DIDComm transport we use AlwaysOkProver — see comment in
    // routes/protocol.rs::build_live_prover. Same fallback rationale
    // applies: building a live prover from a DIDComm handler context
    // requires plumbing secrets/vm_ids through VtaState in the same
    // way the route layer does it. Tracked as a follow-up.
    let prover = AlwaysOkProver;
    let timeout = Duration::from_secs(body.handshake_timeout_secs.unwrap_or(10));
    let audit_kind = if body.rollback {
        MigrateAuditKind::Rollback
    } else {
        MigrateAuditKind::Forward
    };

    let result = update_didcomm(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        &prover,
        &auth,
        UpdateDidcommParams {
            new_mediator_did: body.new_mediator_did,
            drain_ttl: Duration::from_secs(body.drain_ttl_secs),
            force: body.force,
            handshake_timeout: timeout,
            audit_kind,
        },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::update_didcomm::UpdateDidcommError;
    match result {
        Ok(r) => response(
            protocol_management::UPDATE_DIDCOMM_RESULT,
            &serde_json::json!({
                "new_version_id": r.new_version_id,
                "prior_mediator_did": r.prior_mediator_did,
                "active_mediator_did": r.active_mediator_did,
                "active_mediator_endpoint": r.active_mediator_endpoint,
                "drains_until": r.drains_until.to_rfc3339(),
            }),
        ),
        Err(UpdateDidcommError::DidcommNotEnabled) => Ok(Some(problem_report_conflict(
            "DIDComm is not currently enabled",
        ))),
        Err(UpdateDidcommError::SameAsActive(did)) => Ok(Some(problem_report_conflict(format!(
            "{did} is already the active mediator"
        )))),
        Err(UpdateDidcommError::AlreadyDraining(did)) => Ok(Some(problem_report_conflict(
            format!("{did} is currently in drain state — cancel or rollback first"),
        ))),
        Err(UpdateDidcommError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── drain_cancel over DIDComm ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DrainCancelBody {
    mediator_did: String,
}

pub async fn handle_drain_cancel(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };
    let body: DrainCancelBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let result = drain_cancel(
        &state.config,
        &state.drains_ks,
        &state.mediator_registry,
        &state.telemetry,
        &auth,
        DrainCancelParams {
            mediator_did: body.mediator_did,
        },
        "didcomm",
    )
    .await;

    use crate::messaging::registry::RegistryError;
    use crate::operations::protocol::drain_cancel::DrainCancelError;
    match result {
        Ok(r) => response(
            protocol_management::DRAIN_CANCEL_RESULT,
            &serde_json::json!({ "mediator_did": r.mediator_did }),
        ),
        Err(DrainCancelError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(DrainCancelError::Registry(RegistryError::CannotCancelActive(did))) => {
            Ok(Some(problem_report_conflict(format!(
                "{did} is the active mediator — use disable instead",
            ))))
        }
        Err(DrainCancelError::Registry(RegistryError::NotRegistered(did))) => Ok(Some(
            problem_report_conflict(format!("{did} is not registered (no drain entry)",)),
        )),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── mediator_report over DIDComm ────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MediatorReportBody {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
}

pub async fn handle_mediator_report(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };
    let body: MediatorReportBody = serde_json::from_value(message.body).map_err(handler_err)?;

    let parse_ts = |s: Option<String>| -> Result<Option<DateTime<Utc>>, DIDCommServiceError> {
        match s {
            None => Ok(None),
            Some(s) => DateTime::parse_from_rfc3339(&s)
                .map(|d| Some(d.with_timezone(&Utc)))
                .map_err(handler_err),
        }
    };
    let since = parse_ts(body.since)?;
    let until = parse_ts(body.until)?;

    let result = mediator_report(&state.telemetry, &auth, ReportParams { since, until }).await;
    use crate::operations::protocol::report::ReportError;
    match result {
        Ok(r) => response(protocol_management::MEDIATOR_REPORT_RESULT, &r),
        Err(ReportError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── REST service-management handlers (T1.5) ─────────────────────────
//
// Each handler is a thin adapter mirroring `handle_disable_didcomm`:
// authenticate the message, parse the body, call the existing
// operation function, and emit either a typed result or a problem-
// report. All three REST ops are reachable over DIDComm — REST is
// always running per spec §3.2, so unlike `enable_didcomm` (which
// can't arrive over a transport that isn't running yet) there's no
// chicken-and-egg constraint here.

fn body_str_field(message: &Message, key: &str) -> Result<String, DIDCommServiceError> {
    message
        .body
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| handler_err(format!("missing or non-string `{key}` in body")))
}

pub async fn handle_enable_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let url = body_str_field(&message, "url")?;

    let result = enable_rest(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.telemetry,
        &auth,
        EnableRestParams { url },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::enable_rest::EnableRestError;
    match result {
        Ok(r) => response(
            protocol_management::ENABLE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "url": r.url,
            }),
        ),
        Err(EnableRestError::ServiceAlreadyEnabled) => {
            Ok(Some(problem_report_conflict("REST is already enabled")))
        }
        Err(EnableRestError::Validation(e)) => Ok(Some(problem_report_bad_request(e))),
        Err(EnableRestError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

pub async fn handle_update_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let url = body_str_field(&message, "url")?;

    let result = update_rest(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.telemetry,
        &auth,
        UpdateRestParams { url },
        OpContext::Direct,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::update_rest::UpdateRestError;
    match result {
        Ok(r) => response(
            protocol_management::UPDATE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_url": r.prior_url,
                "url": r.url,
            }),
        ),
        Err(UpdateRestError::ServiceNotPresent) => Ok(Some(problem_report_conflict(
            "REST is not currently enabled",
        ))),
        Err(UpdateRestError::Validation(e)) => Ok(Some(problem_report_bad_request(e))),
        Err(UpdateRestError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

pub async fn handle_disable_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let result = disable_rest(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.telemetry,
        &auth,
        DisableRestParams,
        OpContext::Direct,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::disable_rest::DisableRestError;
    match result {
        Ok(r) => response(
            protocol_management::DISABLE_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id,
                "effective_at": Utc::now().to_rfc3339(),
                "prior_url": r.prior_url,
            }),
        ),
        Err(DisableRestError::ServiceNotPresent) => Ok(Some(problem_report_conflict(
            "REST is not currently enabled — nothing to disable",
        ))),
        Err(DisableRestError::LastServiceRefused) => Ok(Some(problem_report_conflict(
            "refusing operation: would leave the VTA with no advertised services",
        ))),
        Err(DisableRestError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── Fail-forward rollback over DIDComm (T3.4) ──────────────────────

pub async fn handle_rollback_rest(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let result = rollback_rest(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.telemetry,
        &auth,
        RollbackRestParams,
        "didcomm",
    )
    .await;

    use crate::operations::protocol::rollback_rest::RollbackRestError;
    match result {
        Ok(r) => response(
            protocol_management::ROLLBACK_REST_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id.unwrap_or_default(),
                "effective_at": Utc::now().to_rfc3339(),
                "kind": match r.kind {
                    crate::operations::protocol::rollback_rest::RollbackKind::Disabled => "disabled",
                    crate::operations::protocol::rollback_rest::RollbackKind::Enabled => "enabled",
                    crate::operations::protocol::rollback_rest::RollbackKind::Updated => "updated",
                    crate::operations::protocol::rollback_rest::RollbackKind::NoOp => "no_op",
                },
            }),
        ),
        Err(RollbackRestError::NoPriorMutation) => Ok(Some(problem_report_conflict(
            "no prior REST mutation to roll back from",
        ))),
        Err(RollbackRestError::DisableForward(
            crate::operations::protocol::disable_rest::DisableRestError::LastServiceRefused,
        )) => Ok(Some(problem_report_conflict(
            "rolling back this REST mutation would leave the VTA with no advertised services",
        ))),
        Err(RollbackRestError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

#[derive(Debug, Deserialize)]
struct RollbackDidcommBody {
    #[serde(default)]
    drain_ttl_secs: Option<u64>,
}

pub async fn handle_rollback_didcomm(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let body: RollbackDidcommBody = serde_json::from_value(message.body).map_err(handler_err)?;
    let drain_ttl = std::time::Duration::from_secs(body.drain_ttl_secs.unwrap_or(86_400));

    let prover = AlwaysOkProver;

    let result = rollback_didcomm(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &state.snapshot_ks,
        &*state.seed_store,
        state
            .did_resolver
            .as_ref()
            .ok_or_else(|| handler_err("did_resolver unavailable"))?,
        &state.didcomm_bridge,
        &state.mediator_registry,
        &state.drain_sweeper,
        &state.telemetry,
        &prover,
        &auth,
        RollbackDidcommParams {
            drain_ttl,
            // The rollback request arrived over DIDComm transport,
            // so the MIN_DRAIN_TTL_OVER_DIDCOMM floor applies if
            // the dispatch ends up in disable_didcomm.
            transport: DisableTransport::Didcomm,
        },
        "didcomm",
    )
    .await;

    use crate::operations::protocol::rollback_didcomm::RollbackDidcommError;
    match result {
        Ok(r) => response(
            protocol_management::ROLLBACK_DIDCOMM_RESULT,
            &serde_json::json!({
                "log_entry_version_id": r.new_version_id.unwrap_or_default(),
                "effective_at": Utc::now().to_rfc3339(),
                "kind": match r.kind {
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Disabled => "disabled",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Enabled => "enabled",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::Updated => "updated",
                    crate::operations::protocol::rollback_didcomm::RollbackKind::NoOp => "no_op",
                },
                "draining_mediator": r.draining_mediator,
            }),
        ),
        Err(RollbackDidcommError::NoPriorMutation) => Ok(Some(problem_report_conflict(
            "no prior DIDComm mutation to roll back from",
        ))),
        Err(RollbackDidcommError::DisableForward(
            crate::operations::protocol::disable_didcomm::DisableDidcommError::NoProtocolRemaining,
        )) => Ok(Some(problem_report_conflict(
            "rolling back this DIDComm mutation would leave the VTA with no advertised services",
        ))),
        Err(RollbackDidcommError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}

// ── List services over DIDComm (T4.2) ─────────────────────────────

pub async fn handle_list_services(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = match auth_from_message(&message, &state.acl_ks).await {
        Ok(a) => a,
        Err(e) => return Ok(Some(problem_report_unauthorized(e.to_string()))),
    };

    let result =
        crate::operations::protocol::list::list_services(&state.config, &state.webvh_ks, &auth)
            .await;

    use crate::operations::protocol::list::ListServicesError;
    match result {
        Ok(r) => response(protocol_management::LIST_SERVICES_RESULT, &r),
        Err(ListServicesError::Auth(e)) => Ok(Some(problem_report_unauthorized(e))),
        Err(ListServicesError::VtaDidNotConfigured) => {
            Ok(Some(problem_report_conflict("VTA DID is not configured")))
        }
        Err(other) => Ok(Some(problem_report_internal(other.to_string()))),
    }
}
