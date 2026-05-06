//! Client surface for DIDComm protocol management.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! Phase 3 lands `enable_didcomm` (REST-only by nature — DIDComm is
//! not yet running at first-enable time). The disable / migrate /
//! drain-cancel / report calls — and their DIDComm transport
//! handlers — arrive in Phase 4 verticals.
//!
//! Runtime REST service-management wire types (the symmetric
//! REST-side of the spec §4 surface — `EnableRestRequest`,
//! `UpdateRestRequest`, `DisableRestRequest`, `RollbackRestRequest`,
//! `ServiceMutationResponse`) live in [`services`].

pub mod services;

use serde::{Deserialize, Serialize};

use crate::client::VtaClient;
use crate::error::VtaError;
use crate::protocols::protocol_management;

/// Request body for `POST /services/didcomm/enable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct EnableDidcommRequest {
    pub mediator_did: String,
    /// Skip handshake steps 2-5 (DID resolution always runs).
    /// Emits a `MediatorHandshakeBypassed` telemetry event when set.
    #[serde(default)]
    pub force: bool,
    /// Trust-ping round-trip timeout (default: 10 seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
}

impl EnableDidcommRequest {
    pub fn new(mediator_did: impl Into<String>) -> Self {
        Self {
            mediator_did: mediator_did.into(),
            force: false,
            handshake_timeout_secs: None,
        }
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn handshake_timeout_secs(mut self, secs: u64) -> Self {
        self.handshake_timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableDidcommResponse {
    pub new_version_id: String,
    pub mediator_did: String,
    pub mediator_endpoint: String,
}

/// Request body for `POST /services/didcomm/disable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableDidcommRequest {
    /// Drain TTL in seconds. 0 = immediate teardown (REST only;
    /// over DIDComm transport, minimum 1h is enforced server-side).
    pub drain_ttl_secs: u64,
}

impl DisableDidcommRequest {
    pub fn new(drain_ttl_secs: u64) -> Self {
        Self { drain_ttl_secs }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableDidcommResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(rfc3339)` when the listener entered drain state;
    /// `None` when it was torn down immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drains_until: Option<String>,
}

impl VtaClient {
    /// Enable DIDComm on a REST-only VTA. Spec: success criterion #1.
    ///
    /// The VTA must be configured with a vta_did, must currently
    /// have `services.didcomm = false`, and the caller must have
    /// super-admin role. On success, the VTA publishes a new WebVH
    /// LogEntry advertising the mediator and registers it as
    /// active.
    ///
    /// **Phase 3 limitation:** the live mediator handshake (steps
    /// 2-5) requires a running `DIDCommService`, which doesn't
    /// exist yet at first-enable. This call therefore bypasses
    /// steps 2-5; the connection is validated implicitly when the
    /// DIDComm runtime starts up after the next service restart.
    /// To validate a mediator pre-publish today, run
    /// `pnm services enable didcomm` followed by
    /// `pnm mediator migrate --to <same>` — the migrate path runs
    /// the full handshake.
    pub async fn enable_didcomm(
        &self,
        req: EnableDidcommRequest,
    ) -> Result<EnableDidcommResponse, VtaError> {
        // REST-only by nature. Calling this over DIDComm transport
        // will surface as a 404 from the upstream message router,
        // which the rpc() layer turns into a `VtaError::Protocol`.
        // That's the right behaviour — the operation is logically
        // not available over DIDComm transport.
        self.rpc(
            "services-management/1.0/enable-not-available-via-didcomm",
            serde_json::to_value(&req)?,
            "services-management/1.0/enable-not-available-via-didcomm-result",
            30,
            |c, url| c.post(format!("{url}/services/didcomm/enable")).json(&req),
        )
        .await
    }

    /// Disable DIDComm. Refuses if REST is also disabled
    /// (`NoProtocolRemaining`). Drain TTL semantics:
    /// - `0` = immediate teardown (REST transport only).
    /// - `>= 3600` = drain window over DIDComm transport (server
    ///   enforces 1h minimum).
    pub async fn disable_didcomm(
        &self,
        req: DisableDidcommRequest,
    ) -> Result<DisableDidcommResponse, VtaError> {
        self.rpc(
            protocol_management::DISABLE_DIDCOMM,
            serde_json::to_value(&req)?,
            protocol_management::DISABLE_DIDCOMM_RESULT,
            30,
            |c, url| c.post(format!("{url}/services/didcomm/disable")).json(&req),
        )
        .await
    }

    /// Migrate the active mediator. Runs the pre-promotion
    /// handshake against the new mediator and places the prior
    /// mediator in drain state for the requested TTL.
    pub async fn migrate_mediator(
        &self,
        req: MigrateMediatorRequest,
    ) -> Result<MigrateMediatorResponse, VtaError> {
        self.rpc(
            protocol_management::MIGRATE_MEDIATOR,
            serde_json::to_value(&req)?,
            protocol_management::MIGRATE_MEDIATOR_RESULT,
            120,
            |c, url| c.post(format!("{url}/mediators/migrate")).json(&req),
        )
        .await
    }
}

/// Request body for `POST /mediators/migrate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct MigrateMediatorRequest {
    pub new_mediator_did: String,
    pub drain_ttl_secs: u64,
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_secs: Option<u64>,
    /// Tag the operation as a rollback in telemetry.
    #[serde(default)]
    pub rollback: bool,
}

impl MigrateMediatorRequest {
    pub fn new(new_mediator_did: impl Into<String>, drain_ttl_secs: u64) -> Self {
        Self {
            new_mediator_did: new_mediator_did.into(),
            drain_ttl_secs,
            force: false,
            handshake_timeout_secs: None,
            rollback: false,
        }
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn rollback(mut self, rollback: bool) -> Self {
        self.rollback = rollback;
        self
    }

    pub fn handshake_timeout_secs(mut self, secs: u64) -> Self {
        self.handshake_timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateMediatorResponse {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    pub active_mediator_did: String,
    pub active_mediator_endpoint: String,
    pub drains_until: String,
}

/// Request body for `POST /mediators/drain/cancel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainCancelRequest {
    pub mediator_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainCancelResponse {
    pub mediator_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediatorStats {
    pub mediator_did: String,
    pub inbound_count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderLastSeen {
    pub sender_did: String,
    pub last_seen_mediator: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediatorReport {
    #[serde(default)]
    pub since: Option<String>,
    pub until: String,
    pub mediators: Vec<MediatorStats>,
    pub senders: Vec<SenderLastSeen>,
}

impl VtaClient {
    /// Cancel a drain entry early, dropping the listener for that
    /// mediator immediately. Refuses if the named DID is the
    /// active mediator (use `services disable didcomm` instead) or
    /// not registered at all.
    pub async fn drain_cancel(
        &self,
        req: DrainCancelRequest,
    ) -> Result<DrainCancelResponse, VtaError> {
        self.rpc(
            protocol_management::DRAIN_CANCEL,
            serde_json::to_value(&req)?,
            protocol_management::DRAIN_CANCEL_RESULT,
            30,
            |c, url| c.post(format!("{url}/mediators/drain/cancel")).json(&req),
        )
        .await
    }

    /// Query the mediator-attribution report. `since`/`until` are
    /// optional RFC 3339 timestamps. Returns per-mediator inbound
    /// counts and per-sender last-seen mediator (so operators can
    /// spot senders still using the prior mediator after a
    /// migrate).
    pub async fn mediator_report(
        &self,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<MediatorReport, VtaError> {
        let since_owned = since.map(str::to_string);
        let until_owned = until.map(str::to_string);
        let qs = build_report_query(since_owned.as_deref(), until_owned.as_deref());
        self.rpc(
            protocol_management::MEDIATOR_REPORT,
            serde_json::json!({
                "since": since_owned,
                "until": until_owned,
            }),
            protocol_management::MEDIATOR_REPORT_RESULT,
            30,
            move |c, url| {
                let url = if qs.is_empty() {
                    format!("{url}/mediators/report")
                } else {
                    format!("{url}/mediators/report?{qs}")
                };
                c.get(url)
            },
        )
        .await
    }
}

fn build_report_query(since: Option<&str>, until: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = since {
        parts.push(format!("since={}", url_encode(s)));
    }
    if let Some(u) = until {
        parts.push(format!("until={}", url_encode(u)));
    }
    parts.join("&")
}

fn url_encode(s: &str) -> String {
    // RFC 3339 timestamps contain `:` and `+`; the latter is the
    // form-urlencoded representation of a space and would mangle
    // the timestamp on the server side. Encode the unsafe chars
    // explicitly.
    s.chars()
        .flat_map(|c| match c {
            ':' => "%3A".chars().collect::<Vec<_>>(),
            '+' => "%2B".chars().collect::<Vec<_>>(),
            _ => vec![c],
        })
        .collect()
}
