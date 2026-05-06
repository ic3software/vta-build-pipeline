//! Wire types for the runtime REST service-management surface.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §4.
//!
//! These cover the four REST operations exposed under
//! `pnm services rest {enable,update,disable,rollback}` plus the
//! shared response shape (`ServiceMutationResponse`) used by every
//! mutation across both REST and DIDComm kinds.
//!
//! DIDComm-side wire types live in [`super`] — `EnableDidcommRequest`,
//! `DisableDidcommRequest`, and (renamed in T2.3) `UpdateDidcommRequest`.
//! Keep the two surfaces in sync as they evolve.
//!
//! ## URL field convention
//!
//! `url: String` is intentional — the field stays a string here so
//! the SDK matches the existing protocol-management types
//! (`mediator_did: String`, etc.) and the operation layer applies a
//! single validation pass via [`crate::protocol::validate_service_url`]
//! (T1.2). Operators see one consistent error shape regardless of
//! whether validation runs client-side, server-side, or both.

use serde::{Deserialize, Serialize};

/// Request body for `POST /services/rest/enable`.
///
/// Adds a `#vta-rest` service entry to the VTA's DID document
/// pointing at `url`. Refused with `ServiceAlreadyEnabled` if REST
/// is already advertised. The wire shape rendered into the DID
/// document — `id: "{DID}#vta-rest"`, `type: "VTARest"` — is
/// preserved by the operation layer (P1.3) for SDK-resolution
/// compatibility (`vta-sdk/src/session.rs:1100`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[must_use]
pub struct EnableRestRequest {
    pub url: String,
}

impl EnableRestRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/rest/update`.
///
/// Replaces the URL on the existing `#vta-rest` entry. Refused
/// with `ServiceNotPresent` if REST is not currently advertised.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[must_use]
pub struct UpdateRestRequest {
    pub url: String,
}

impl UpdateRestRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// Request body for `POST /services/rest/disable`.
///
/// Removes the `#vta-rest` entry. Refused with
/// `LastServiceRefused` when DIDComm is also disabled (spec §3.2)
/// and with `ServiceNotPresent` if REST isn't currently advertised.
///
/// No fields today — the body exists so the wire surface stays
/// uniform (every mutation is a `POST` with a JSON body) and so
/// the type can grow optional fields later without a breaking
/// change. Serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[must_use]
pub struct DisableRestRequest {}

/// Request body for `POST /services/rest/rollback`.
///
/// Fail-forwards the most recent REST mutation (spec §3.5a) by
/// reading the snapshot store and dispatching to the equivalent
/// forward operation. Refused with `NoPriorMutation` when no
/// snapshot is recorded, and with `LastServiceRefused` if the
/// rollback would brick the VTA. Like [`DisableRestRequest`],
/// no fields today — serializes as `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[must_use]
pub struct RollbackRestRequest {}

/// Shared response body for every successful service-mutation
/// operation (REST + DIDComm enable/update/disable/rollback).
///
/// `drain_until` is `Some(rfc3339)` only for DIDComm operations
/// that scheduled a drain (`update_didcomm`, `disable_didcomm`,
/// or a `rollback_didcomm` whose fail-forward target was a drain
/// transition). REST mutations always set it to `None`.
///
/// All timestamps are RFC 3339 strings to match the existing wire
/// convention from `DisableDidcommResponse::drains_until`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceMutationResponse {
    /// Version-id of the new WebVH LogEntry produced by the
    /// mutation. Joins telemetry events to chain history.
    pub log_entry_version_id: String,
    /// RFC 3339 timestamp when the mutation took effect — the
    /// same instant stamped on the new LogEntry.
    pub effective_at: String,
    /// `Some(rfc3339)` when the mutation scheduled a DIDComm
    /// drain; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip every request type — both directions, across the
    /// wire forms used by REST handlers (raw JSON body) and DIDComm
    /// transport (JSON-tagged in the message attachment).
    #[test]
    fn rest_request_types_round_trip_through_json() {
        let req = EnableRestRequest::new("https://vta.example.com");
        let json = serde_json::to_string(&req).unwrap();
        let restored: EnableRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = UpdateRestRequest::new("https://vta-new.example.com");
        let json = serde_json::to_string(&req).unwrap();
        let restored: UpdateRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = DisableRestRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: DisableRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);

        let req = RollbackRestRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let restored: RollbackRestRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, req);
    }

    /// The empty request bodies must serialize as `{}`, not `null`,
    /// `[]`, or a string. REST clients that send `null` would
    /// fail strict-deserialize servers; pin the wire form.
    #[test]
    fn empty_request_bodies_serialize_as_empty_object() {
        assert_eq!(
            serde_json::to_string(&DisableRestRequest::default()).unwrap(),
            "{}"
        );
        assert_eq!(
            serde_json::to_string(&RollbackRestRequest::default()).unwrap(),
            "{}"
        );
    }

    /// The empty request bodies must also accept an empty object
    /// `{}` (and `null`, via `Default`) on the deserialize side, so
    /// callers that send no body don't trip up the server.
    #[test]
    fn empty_request_bodies_accept_empty_object() {
        let _: DisableRestRequest = serde_json::from_str("{}").unwrap();
        let _: RollbackRestRequest = serde_json::from_str("{}").unwrap();
    }

    /// `url` field name must stay literal `url` on the wire —
    /// renaming it would break every caller. Pin via JSON shape
    /// rather than relying solely on the `#[derive(Serialize)]`
    /// default.
    #[test]
    fn rest_url_field_is_literal_url_on_wire() {
        let json = serde_json::to_value(EnableRestRequest::new("https://x.example")).unwrap();
        assert_eq!(json["url"], "https://x.example");
        assert!(json.get("uri").is_none(), "must not rename url to uri");

        let json = serde_json::to_value(UpdateRestRequest::new("https://y.example")).unwrap();
        assert_eq!(json["url"], "https://y.example");
    }

    /// `ServiceMutationResponse` round-trips with and without
    /// `drain_until`. The `None` case omits the field on the wire
    /// (per `skip_serializing_if`); the `Some` case includes the
    /// RFC 3339 timestamp.
    #[test]
    fn service_mutation_response_round_trips_both_drain_states() {
        let rest_response = ServiceMutationResponse {
            log_entry_version_id: "1-zQm...A".into(),
            effective_at: "2026-05-06T13:00:00Z".into(),
            drain_until: None,
        };
        let json = serde_json::to_value(&rest_response).unwrap();
        assert_eq!(json["log_entry_version_id"], "1-zQm...A");
        assert_eq!(json["effective_at"], "2026-05-06T13:00:00Z");
        assert!(
            json.get("drain_until").is_none(),
            "drain_until must be omitted when None — wire bandwidth + reader convention",
        );
        let restored: ServiceMutationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(restored, rest_response);

        let didcomm_response = ServiceMutationResponse {
            log_entry_version_id: "2-zQm...B".into(),
            effective_at: "2026-05-06T13:00:00Z".into(),
            drain_until: Some("2026-05-07T13:00:00Z".into()),
        };
        let json = serde_json::to_value(&didcomm_response).unwrap();
        assert_eq!(json["drain_until"], "2026-05-07T13:00:00Z");
        let restored: ServiceMutationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(restored, didcomm_response);
    }

    /// `ServiceMutationResponse` deserializes both forms — explicit
    /// `null` for drain_until (some encoders emit it) and the
    /// elided form (preferred).
    #[test]
    fn service_mutation_response_accepts_explicit_null_drain_until() {
        let with_null = r#"{
            "log_entry_version_id": "1-zQm...A",
            "effective_at": "2026-05-06T13:00:00Z",
            "drain_until": null
        }"#;
        let r: ServiceMutationResponse = serde_json::from_str(with_null).unwrap();
        assert_eq!(r.drain_until, None);

        let elided = r#"{
            "log_entry_version_id": "1-zQm...A",
            "effective_at": "2026-05-06T13:00:00Z"
        }"#;
        let r: ServiceMutationResponse = serde_json::from_str(elided).unwrap();
        assert_eq!(r.drain_until, None);
    }
}
