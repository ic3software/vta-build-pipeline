//! [`AuditEvent`] — the tagged enum of every audit-log variant.
//!
//! Ships the **Phase-0 vocabulary** matching spec §11.4. Phase-1+
//! variants land alongside their owning features (join requests,
//! members, policies, registry, VRC, etc.) and follow the same
//! pattern: one variant per semantically distinct event, with a
//! purpose-built data struct.
//!
//! ## Wire contract
//!
//! - Tagged form `#[serde(tag = "type", content = "data")]` so
//!   external consumers (SIEM, later webhooks) discriminate on the
//!   `type` field. **Variant identifiers are part of the wire
//!   contract — don't rename them without bumping
//!   `EVENT_VERSION`.**
//! - Data structs use `#[serde(rename_all = "camelCase")]` for
//!   downstream tooling friendliness. Field names are also wire
//!   contract.
//!
//! ## Sensitive-field redaction
//!
//! [`ConfigChange::redact_if`] walks a [`ConfigChangedData`] and
//! masks `old_value` / `new_value` for any key matched by the caller-
//! supplied sensitivity predicate. The emitter (config endpoint
//! handlers, M0.8) calls this **before** persisting the event so
//! sensitive values never reach the audit keyspace in cleartext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::key_store::RotationReason;

/// Marker used in place of redacted config values. Distinguishable
/// from a JSON null / empty string by callers introspecting an
/// archived audit row.
pub const REDACTED_MARKER: &str = "<redacted>";

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// Audit-event payload. Tagged on `type` with the variant name and
/// the variant's data under `data`. Phase-0 vocabulary only;
/// Phase-1+ adds variants alongside the features that emit them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum AuditEvent {
    /// Bootstrap completed — the first admin DID was written into the
    /// ACL and the install carve-out was permanently closed.
    CommunityInstalled(CommunityInstalledData),

    /// `vtc admin emergency-bootstrap` was invoked with a valid
    /// master-seed mnemonic, re-opening the install carve-out exactly
    /// once. Loud event — surfaced prominently in diagnostics on next
    /// daemon start so a forgotten emergency action is impossible to
    /// miss.
    EmergencyBootstrapInvoked(EmergencyBootstrapData),

    /// A passkey was registered against an admin DID (initial enrol
    /// at install **or** a subsequent additional-device enrolment).
    AdminPasskeyRegistered(AdminPasskeyData),

    /// A passkey was revoked from an admin DID. The CAS check that
    /// refuses to leave zero passkeys runs *before* the event is
    /// emitted, so any persisted `AdminPasskeyRevoked` leaves at
    /// least one passkey behind.
    AdminPasskeyRevoked(AdminPasskeyData),

    /// One or more runtime configuration keys were modified via
    /// `PATCH /v1/admin/config`. Per-key sensitivity is honoured —
    /// values for keys flagged sensitive are redacted via
    /// [`ConfigChange::redact_if`] before persistence.
    ConfigChanged(ConfigChangedData),

    /// `POST /v1/admin/config/reload` applied hot-reloadable settings
    /// in-place. Lists which keys actually re-applied (a key that
    /// was unchanged-or-already-active doesn't appear).
    ConfigReloaded(ConfigReloadedData),

    /// `POST /v1/admin/config/restart` initiated graceful shutdown.
    /// Emitted **before** the process exits so the next-boot replay
    /// can correlate the restart with the prior config patches that
    /// triggered it.
    RestartRequested(RestartRequestedData),

    /// `PUT /v1/community/profile` updated one or more profile
    /// fields. Records which fields changed by name; the values
    /// themselves stay out of the audit log (profile data isn't
    /// security-sensitive by nature, but keeping the event small
    /// is operator-friendly).
    CommunityProfileUpdated(CommunityProfileUpdatedData),

    /// The community `audit_key` was rotated. Emitted under the
    /// **new** key (the rotation itself is what creates the new
    /// epoch), so an investigator can find the row by querying the
    /// `audit_by_type` index without needing to walk the prior
    /// epoch.
    AuditKeyRotated(AuditKeyRotatedData),
}

// ---------------------------------------------------------------------------
// Variant data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommunityInstalledData {
    pub community_did: String,
    /// `jti` of the install token that was consumed. Lets a forensic
    /// audit correlate the bootstrap with the specific install URL
    /// the operator clicked.
    pub install_token_jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyBootstrapData {
    /// Host name of the machine running the CLI command, as
    /// reported by the OS. Recorded for forensic context — the CLI
    /// can't be trusted, but a mismatch with the expected operator
    /// host is a useful smoke signal.
    pub operator_hostname: String,
    /// Wall clock at the time the CLI ran. Distinct from the
    /// envelope timestamp, which is when the daemon next started
    /// and emitted the event — the gap between the two is itself
    /// audit-worthy.
    pub invoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminPasskeyData {
    /// Hex-encoded WebAuthn credential id. Operator-recognisable;
    /// distinct from the cred_id bytes the storage layer holds.
    pub credential_id_hex: String,
    /// Operator-friendly label (e.g. `"MacBook Air Touch ID"`).
    pub label: String,
    /// `usb` / `nfc` / `ble` / `internal` etc., as WebAuthn reports
    /// them. Helpful for "which device just got revoked" UX.
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChangedData {
    pub changes: Vec<ConfigChange>,
    /// `true` when at least one changed key is restart-required.
    /// Emitter computes this from the per-key taxonomy (M0.8) so the
    /// audit consumer doesn't need to know the schema.
    pub requires_restart: bool,
}

/// One field's worth of change. `old_value` is `None` if the key
/// wasn't previously set (default-only); `new_value` is the
/// post-PATCH value. Use [`Self::redact_if`] before persisting to
/// mask sensitive values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChange {
    pub key: String,
    pub old_value: Option<Value>,
    pub new_value: Value,
    pub source_before: ConfigSource,
}

impl ConfigChange {
    /// Mask the value fields in-place if `sensitive(&self.key)`.
    /// Returns `true` if a redaction was applied so the caller can
    /// log it.
    pub fn redact_if<F>(&mut self, sensitive: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        if sensitive(&self.key) {
            self.old_value = Some(Value::String(REDACTED_MARKER.to_string()));
            self.new_value = Value::String(REDACTED_MARKER.to_string());
            true
        } else {
            false
        }
    }
}

/// Where the prior value came from in the three-layer config
/// overlay. Mirrors the source annotation surfaced on
/// `GET /v1/admin/config` (spec §14.6). Reproduced here so the
/// audit log is self-contained and doesn't need the config module's
/// type to deserialise.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Env,
    Db,
    Toml,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReloadedData {
    /// Keys that actually re-applied. Excludes keys whose new value
    /// equalled the live value (no-op).
    pub keys_reloaded: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RestartRequestedData {
    /// `restart.drain_timeout` value (seconds) the daemon will use
    /// when draining in-flight requests. Lets an oncall correlate a
    /// long-tail timeout with a restart.
    pub drain_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommunityProfileUpdatedData {
    /// Names of fields that changed (e.g. `name`, `description`,
    /// `logo_url`, `extensions`). Values themselves stay out of the
    /// audit log.
    pub fields_changed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditKeyRotatedData {
    pub previous_key_id: String,
    pub new_key_id: String,
    pub rotation_reason: RotationReason,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip(event: &AuditEvent) {
        let s = serde_json::to_string(event).unwrap();
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(&back, event);
    }

    fn wire_value(event: &AuditEvent) -> Value {
        serde_json::to_value(event).unwrap()
    }

    // ──────────── tag + content shape ────────────

    #[test]
    fn community_installed_tagged_wire_shape() {
        let e = AuditEvent::CommunityInstalled(CommunityInstalledData {
            community_did: "did:webvh:example.com:abc".into(),
            install_token_jti: "jti-1".into(),
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CommunityInstalled");
        assert_eq!(v["data"]["communityDid"], "did:webvh:example.com:abc");
        assert_eq!(v["data"]["installTokenJti"], "jti-1");
        round_trip(&e);
    }

    #[test]
    fn emergency_bootstrap_tagged_wire_shape() {
        let invoked_at = DateTime::parse_from_rfc3339("2026-05-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let e = AuditEvent::EmergencyBootstrapInvoked(EmergencyBootstrapData {
            operator_hostname: "ops-01.example.com".into(),
            invoked_at,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "EmergencyBootstrapInvoked");
        assert_eq!(v["data"]["operatorHostname"], "ops-01.example.com");
        round_trip(&e);
    }

    #[test]
    fn admin_passkey_registered_round_trip() {
        let e = AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
            credential_id_hex: "deadbeef".into(),
            label: "MacBook Air Touch ID".into(),
            transports: vec!["internal".into(), "hybrid".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AdminPasskeyRegistered");
        assert_eq!(v["data"]["credentialIdHex"], "deadbeef");
        assert_eq!(v["data"]["transports"][0], "internal");
        round_trip(&e);
    }

    #[test]
    fn admin_passkey_revoked_round_trip() {
        let e = AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
            credential_id_hex: "feedface".into(),
            label: "iPhone Face ID".into(),
            transports: vec!["hybrid".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AdminPasskeyRevoked");
        round_trip(&e);
    }

    #[test]
    fn config_changed_round_trip() {
        let e = AuditEvent::ConfigChanged(ConfigChangedData {
            changes: vec![ConfigChange {
                key: "log.level".into(),
                old_value: Some(json!("info")),
                new_value: json!("debug"),
                source_before: ConfigSource::Toml,
            }],
            requires_restart: false,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "ConfigChanged");
        assert_eq!(v["data"]["changes"][0]["key"], "log.level");
        assert_eq!(v["data"]["changes"][0]["newValue"], "debug");
        assert_eq!(v["data"]["changes"][0]["sourceBefore"], "toml");
        round_trip(&e);
    }

    #[test]
    fn config_reloaded_round_trip() {
        let e = AuditEvent::ConfigReloaded(ConfigReloadedData {
            keys_reloaded: vec!["log.level".into(), "audit.retention.config_changed".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "ConfigReloaded");
        assert_eq!(
            v["data"]["keysReloaded"][1],
            "audit.retention.config_changed"
        );
        round_trip(&e);
    }

    #[test]
    fn restart_requested_round_trip() {
        let e = AuditEvent::RestartRequested(RestartRequestedData {
            drain_timeout_seconds: 30,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "RestartRequested");
        assert_eq!(v["data"]["drainTimeoutSeconds"], 30);
        round_trip(&e);
    }

    #[test]
    fn community_profile_updated_round_trip() {
        let e = AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
            fields_changed: vec!["name".into(), "logo_url".into()],
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "CommunityProfileUpdated");
        assert_eq!(v["data"]["fieldsChanged"][0], "name");
        round_trip(&e);
    }

    #[test]
    fn audit_key_rotated_round_trip() {
        let e = AuditEvent::AuditKeyRotated(AuditKeyRotatedData {
            previous_key_id: "11111111-1111-1111-1111-111111111111".into(),
            new_key_id: "22222222-2222-2222-2222-222222222222".into(),
            rotation_reason: RotationReason::Rtbf,
        });
        let v = wire_value(&e);
        assert_eq!(v["type"], "AuditKeyRotated");
        assert_eq!(v["data"]["rotationReason"], "Rtbf");
        round_trip(&e);
    }

    // ──────────── ConfigChange::redact_if ────────────

    #[test]
    fn redact_if_masks_sensitive_keys() {
        let mut change = ConfigChange {
            key: "server.tls.cert_path".into(),
            old_value: Some(json!("/etc/old.pem")),
            new_value: json!("/etc/new.pem"),
            source_before: ConfigSource::Db,
        };
        let redacted = change.redact_if(|k| k.starts_with("server.tls."));
        assert!(redacted);
        assert_eq!(change.old_value, Some(json!(REDACTED_MARKER)));
        assert_eq!(change.new_value, json!(REDACTED_MARKER));
        // Key + source survive — redaction is value-only.
        assert_eq!(change.key, "server.tls.cert_path");
        assert_eq!(change.source_before, ConfigSource::Db);
    }

    #[test]
    fn redact_if_leaves_non_sensitive_keys_untouched() {
        let mut change = ConfigChange {
            key: "log.level".into(),
            old_value: Some(json!("info")),
            new_value: json!("debug"),
            source_before: ConfigSource::Toml,
        };
        let original = change.clone();
        let redacted = change.redact_if(|k| k.starts_with("server.tls."));
        assert!(!redacted);
        assert_eq!(change, original);
    }

    #[test]
    fn redact_if_handles_unset_old_value() {
        let mut change = ConfigChange {
            key: "server.tls.key_path".into(),
            old_value: None,
            new_value: json!("/etc/new.key"),
            source_before: ConfigSource::Default,
        };
        change.redact_if(|k| k.starts_with("server.tls."));
        // Even when the previous value was unset, redaction inserts a
        // <redacted> marker so the audit record can't be distinguished
        // from "previously empty, now empty" — preserves the
        // sensitivity boundary.
        assert_eq!(change.old_value, Some(json!(REDACTED_MARKER)));
    }

    // ──────────── Variant catalog snapshot ────────────
    //
    // Pins the wire-discriminator strings. Renaming a variant
    // breaks SIEM ingestion and webhook consumers; this test makes
    // such a change visible in review.

    #[test]
    fn variant_discriminator_strings() {
        let cases: Vec<(AuditEvent, &str)> = vec![
            (
                AuditEvent::CommunityInstalled(CommunityInstalledData {
                    community_did: "did:webvh:x".into(),
                    install_token_jti: "j".into(),
                }),
                "CommunityInstalled",
            ),
            (
                AuditEvent::EmergencyBootstrapInvoked(EmergencyBootstrapData {
                    operator_hostname: "h".into(),
                    invoked_at: Utc::now(),
                }),
                "EmergencyBootstrapInvoked",
            ),
            (
                AuditEvent::AdminPasskeyRegistered(AdminPasskeyData {
                    credential_id_hex: "0".into(),
                    label: "x".into(),
                    transports: vec![],
                }),
                "AdminPasskeyRegistered",
            ),
            (
                AuditEvent::AdminPasskeyRevoked(AdminPasskeyData {
                    credential_id_hex: "0".into(),
                    label: "x".into(),
                    transports: vec![],
                }),
                "AdminPasskeyRevoked",
            ),
            (
                AuditEvent::ConfigChanged(ConfigChangedData {
                    changes: vec![],
                    requires_restart: false,
                }),
                "ConfigChanged",
            ),
            (
                AuditEvent::ConfigReloaded(ConfigReloadedData {
                    keys_reloaded: vec![],
                }),
                "ConfigReloaded",
            ),
            (
                AuditEvent::RestartRequested(RestartRequestedData {
                    drain_timeout_seconds: 0,
                }),
                "RestartRequested",
            ),
            (
                AuditEvent::CommunityProfileUpdated(CommunityProfileUpdatedData {
                    fields_changed: vec![],
                }),
                "CommunityProfileUpdated",
            ),
            (
                AuditEvent::AuditKeyRotated(AuditKeyRotatedData {
                    previous_key_id: "p".into(),
                    new_key_id: "n".into(),
                    rotation_reason: RotationReason::Initial,
                }),
                "AuditKeyRotated",
            ),
        ];
        for (event, expected) in cases {
            let v = serde_json::to_value(&event).unwrap();
            assert_eq!(v["type"], expected, "discriminator drift for {expected}");
        }
    }
}
