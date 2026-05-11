//! [`AuditEvent`] — the tagged enum of every audit-log variant.
//!
//! Currently a single `Generic` placeholder. Phase-0 variants
//! (`CommunityInstalled`, `EmergencyBootstrapInvoked`,
//! `AdminPasskeyRegistered`, `AdminPasskeyRevoked`, `ConfigChanged`,
//! `ConfigReloaded`, `RestartRequested`, `CommunityProfileUpdated`,
//! `AuditKeyRotated`) land in M0.1.5 once the corresponding
//! lifecycle code arrives. Phase-1+ variants land alongside their
//! features.
//!
//! The tagged enum form (`#[serde(tag = "type", content = "data")]`)
//! is workspace doctrine — see spec §11.4. External consumers (SIEM,
//! later webhooks) discriminate by the `type` field, so the variant
//! identifiers are part of the wire contract: don't rename.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Audit-event payload. Tagged on the `type` field with the variant
/// name and the variant's data under `data`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum AuditEvent {
    /// Placeholder for arbitrary structured payloads. Used by
    /// pre-Phase-1 emitters that need to record an event before its
    /// dedicated variant lands. New emitters should add a concrete
    /// variant rather than reaching for `Generic`.
    Generic {
        /// Short identifier (e.g. `"ConfigBootstrap"`). Free-form for
        /// now; will tighten when the full vocabulary lands.
        kind: String,
        /// Variant-specific structured data.
        payload: Value,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generic_round_trips_through_serde() {
        let e = AuditEvent::Generic {
            kind: "TestEvent".into(),
            payload: json!({ "answer": 42 }),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn generic_wire_shape_is_tagged() {
        let e = AuditEvent::Generic {
            kind: "X".into(),
            payload: json!(null),
        };
        let v: Value = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "Generic");
        assert_eq!(v["data"]["kind"], "X");
    }
}
