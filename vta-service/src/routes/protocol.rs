//! REST routes for DIDComm protocol management.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `POST /services/didcomm/enable`. The remaining
//! routes (`/services/didcomm/disable`, `/services`, `/mediators/*`)
//! are added by Phase 4 verticals.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth::SuperAdminAuth;
use crate::messaging::handshake::{AlwaysOkProver, HandshakeError, HandshakeStage};
use crate::operations::protocol::disable_didcomm::{
    DisableDidcommError, DisableDidcommParams, DisableTransport, disable_didcomm,
};
use crate::operations::protocol::enable_didcomm::{
    EnableDidcommError, EnableDidcommParams, enable_didcomm,
};
use crate::server::AppState;

/// Default trust-ping round-trip timeout for first-enable when the
/// caller doesn't specify `handshake_timeout_secs`. Spec default 10s.
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Deserialize)]
pub struct EnableDidcommRequest {
    pub mediator_did: String,
    /// Optional: skip steps 2-5 of the handshake (DID resolution
    /// always runs). The route emits a `MediatorHandshakeBypassed`
    /// telemetry event when this is set.
    #[serde(default)]
    pub force: bool,
    /// Optional: trust-ping round-trip timeout in seconds. Spec
    /// default: 10s.
    #[serde(default)]
    pub handshake_timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EnableDidcommResponse {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
}

/// `POST /services/didcomm/enable` — enable DIDComm on a REST-only
/// VTA. Auth: super-admin only. Refuses if DIDComm is already
/// enabled (operator should use `migrate` instead).
///
/// **Phase 3 limitation (tracked):** the live mediator handshake
/// (steps 2-5) requires a running `DIDCommService`, which doesn't
/// exist yet at first-enable time. For Phase 3 this route uses
/// [`AlwaysOkProver`], so steps 2-5 are bypassed; the connection is
/// validated implicitly when the DIDComm runtime starts up after
/// the next service restart. Phase 4 introduces a real
/// `ListenerProver` impl wired to a live `DIDCommService` — that
/// impl is naturally exercised by `pnm mediator migrate` (where
/// DIDComm is already running). Operators who need pre-publish
/// validation today should run `pnm mediator migrate` once DIDComm
/// is enabled.
pub async fn enable_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<EnableDidcommRequest>,
) -> Result<Json<EnableDidcommResponse>, EnableDidcommHttpError> {
    let bridge = Arc::clone(&state.didcomm_bridge);
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(EnableDidcommHttpError::DidResolverUnavailable)?
        .clone();

    let prover = AlwaysOkProver;
    let timeout = Duration::from_secs(
        req.handshake_timeout_secs
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
    );

    let result = enable_didcomm(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.telemetry,
        &prover,
        &auth.0,
        EnableDidcommParams {
            mediator_did: req.mediator_did,
            force: req.force,
            handshake_timeout: timeout,
        },
        "rest",
    )
    .await?;

    Ok(Json(EnableDidcommResponse {
        new_version_id: result.new_version_id,
        mediator_did: result.mediator_did,
        mediator_endpoint: result.mediator_endpoint,
    }))
}

/// HTTP error wrapper for `EnableDidcommError` that maps each typed
/// variant to an appropriate status code + suggested-fix body.
#[derive(Debug)]
pub enum EnableDidcommHttpError {
    Op(EnableDidcommError),
    DidResolverUnavailable,
}

impl From<EnableDidcommError> for EnableDidcommHttpError {
    fn from(value: EnableDidcommError) -> Self {
        Self::Op(value)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
    /// Operator-facing suggested fix. Per CLAUDE.md, we surface the
    /// corrected command rather than just the HTTP status.
    #[serde(skip_serializing_if = "Option::is_none")]
    suggested_fix: Option<String>,
    /// Failing handshake stage when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'static str>,
}

impl IntoResponse for EnableDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(EnableDidcommError::DidcommAlreadyEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_already_enabled",
                    message: "DIDComm is already enabled.".into(),
                    suggested_fix: Some(
                        "Use `pnm mediator migrate --to <did>` to change the active mediator."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidRecordMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_record_missing",
                    message: format!("VTA DID `{did}` has no webvh record on disk."),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::VtaDidLogMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_missing",
                    message: format!("VTA DID `{did}` has no published log."),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::EmptyLog) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_empty",
                    message: "VTA DID log is empty.".into(),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Handshake(HandshakeError::Failed { stage, cause })) => (
                StatusCode::BAD_GATEWAY,
                ErrorBody {
                    error: "mediator_handshake_failed",
                    message: format!("mediator handshake failed: {cause}"),
                    suggested_fix: Some(match stage {
                        HandshakeStage::Resolve =>
                            "Check the mediator DID is correct and reachable from this VTA.".into(),
                        _ =>
                            "Inspect the mediator's logs; or retry with `--force` if you've validated reachability out-of-band."
                                .into(),
                    }),
                    stage: Some(stage_str(stage)),
                },
            ),
            Self::Op(EnableDidcommError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::ConfigPersistence(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "config_persistence_failed",
                    message: e,
                    suggested_fix: Some(
                        "Check the VTA's config file is writable; the LogEntry was published \
                         but config persistence failed — fix permissions and retry."
                            .into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Registry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "registry_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(EnableDidcommError::Storage(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_failed",
                    message: e,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver is not initialised on this VTA.".into(),
                    suggested_fix: Some(
                        "Configure `resolver_url` or run with the local resolver.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}

fn stage_str(stage: HandshakeStage) -> &'static str {
    match stage {
        HandshakeStage::Resolve => "resolve",
        HandshakeStage::Connect => "connect",
        HandshakeStage::Authenticate => "authenticate",
        HandshakeStage::Register => "register",
        HandshakeStage::TrustPing => "trust-ping",
    }
}

// ────────────────────────────────────────────────────────────────────
// disable_didcomm
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DisableDidcommRequest {
    /// Drain TTL in seconds. 0 = immediate teardown (REST only;
    /// over DIDComm transport, minimum 1h is enforced).
    #[serde(default)]
    pub drain_ttl_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct DisableDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(rfc3339)` when the listener entered drain state;
    /// `None` when it was torn down immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drains_until: Option<String>,
}

/// `POST /services/didcomm/disable` — disable DIDComm. Auth:
/// super-admin. The route uses `DisableTransport::Rest` since this
/// handler IS the REST transport. The 1h-min-TTL guard applies only
/// when called over the DIDComm transport (Phase 4.2 and beyond).
pub async fn disable_didcomm_handler(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(req): Json<DisableDidcommRequest>,
) -> Result<Json<DisableDidcommResponse>, DisableDidcommHttpError> {
    let bridge = Arc::clone(&state.didcomm_bridge);
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or(DisableDidcommHttpError::DidResolverUnavailable)?
        .clone();

    let result = disable_didcomm(
        &state.config,
        &state.keys_ks,
        &state.contexts_ks,
        &state.webvh_ks,
        &state.audit_ks,
        &state.drains_ks,
        &*state.seed_store,
        &did_resolver,
        &bridge,
        &state.mediator_registry,
        &state.telemetry,
        &auth.0,
        DisableDidcommParams {
            drain_ttl: Duration::from_secs(req.drain_ttl_secs),
            transport: DisableTransport::Rest,
        },
        "rest",
    )
    .await?;

    Ok(Json(DisableDidcommResponse {
        new_version_id: result.new_version_id,
        prior_mediator_did: result.prior_mediator_did,
        drains_until: result.drains_until.map(|t| t.to_rfc3339()),
    }))
}

#[derive(Debug)]
pub enum DisableDidcommHttpError {
    Op(DisableDidcommError),
    DidResolverUnavailable,
}

impl From<DisableDidcommError> for DisableDidcommHttpError {
    fn from(value: DisableDidcommError) -> Self {
        Self::Op(value)
    }
}

impl IntoResponse for DisableDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Op(DisableDidcommError::DidcommNotEnabled) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "didcomm_not_enabled",
                    message: "DIDComm is not currently enabled.".into(),
                    suggested_fix: Some(
                        "Use `pnm services enable didcomm --mediator-did <did>` first.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::NoProtocolRemaining) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "no_protocol_remaining",
                    message: "Cannot disable DIDComm — REST is also disabled. The VTA would have no protocol surface left.".into(),
                    suggested_fix: Some(
                        "Run `pnm services enable rest` first, then retry.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::DrainTtlTooShortForDidcomm) => (
                StatusCode::BAD_REQUEST,
                ErrorBody {
                    error: "drain_ttl_too_short_for_didcomm",
                    message: "drain-ttl 0s over DIDComm transport is not permitted (minimum 1h).".into(),
                    suggested_fix: Some(
                        "Either retry over REST transport (`--transport rest`) or use a TTL >= 1h.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidNotConfigured) => (
                StatusCode::CONFLICT,
                ErrorBody {
                    error: "vta_did_not_configured",
                    message: "VTA DID is not configured.".into(),
                    suggested_fix: Some("Run `vta setup` to configure the VTA's DID first.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidRecordMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_record_missing",
                    message: format!("VTA DID `{did}` has no webvh record on disk."),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::VtaDidLogMissing(did)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_missing",
                    message: format!("VTA DID `{did}` has no published log."),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::EmptyLog) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "vta_did_log_empty",
                    message: "VTA DID log is empty.".into(),
                    suggested_fix: Some("Re-run `vta setup` — local state appears corrupted.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::NoActiveMediator) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "no_active_mediator",
                    message: "DIDComm is enabled but the DID document has no `#vta-didcomm` service entry.".into(),
                    suggested_fix: Some("On-disk state is inconsistent — re-run `vta setup`.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::DocumentPatch(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "document_patch_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::WebVHUpdate(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "webvh_update_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::ConfigPersistence(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "config_persistence_failed",
                    message: e,
                    suggested_fix: Some(
                        "Check the VTA's config file is writable and retry.".into(),
                    ),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Registry(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "registry_failed",
                    message: e.to_string(),
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Auth(e)) => (
                StatusCode::FORBIDDEN,
                ErrorBody {
                    error: "forbidden",
                    message: e,
                    suggested_fix: Some("This operation requires super-admin privileges.".into()),
                    stage: None,
                },
            ),
            Self::Op(DisableDidcommError::Storage(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "storage_failed",
                    message: e,
                    suggested_fix: None,
                    stage: None,
                },
            ),
            Self::DidResolverUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorBody {
                    error: "did_resolver_unavailable",
                    message: "DID resolver is not initialised on this VTA.".into(),
                    suggested_fix: Some(
                        "Configure `resolver_url` or run with the local resolver.".into(),
                    ),
                    stage: None,
                },
            ),
        };
        (status, Json(body)).into_response()
    }
}
