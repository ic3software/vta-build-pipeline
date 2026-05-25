use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhBody {
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional explicit hosting domain on the target server. When
    /// the server hosts multiple tenant domains, the caller may
    /// supply this to direct the new DID at a specific one;
    /// otherwise the server resolves via caller's ACL default →
    /// system default. An unknown domain on the server is rejected
    /// with `did-management:unknown_domain`. Ignored in serverless
    /// mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_mediator_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_count: Option<u32>,
    /// Client-provided DID Document template. When set, the VTA uses this
    /// instead of building the document internally. `{DID}` placeholders are
    /// resolved by `didwebvh-rs`. Mutually exclusive with `did_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    /// Complete, pre-signed did.jsonl log entry. When set, the VTA publishes
    /// it as-is without deriving keys or creating a log entry. Mutually
    /// exclusive with `did_document`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    /// Whether to set this DID as the primary DID for the context.
    /// Defaults to `true` for backwards compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_primary: Option<bool>,
    /// Use an existing key as the signing (Ed25519) verification method.
    /// When set, the VTA skips key derivation and uses this key instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    /// Use an existing key as the key-agreement (X25519) verification method.
    /// Required when the DID document includes DIDCommMessaging services.
    /// Requires `signing_key_id` to also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ka_key_id: Option<String>,
    /// Stored DID template name to render as the DID document. Mutually
    /// exclusive with `did_document` and `did_log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Scope to look the template up in. `None` means "global only"; `Some(ctx)`
    /// means "this context first, then global, then builtin".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_context: Option<String>,
    /// Caller-supplied template variables. Server injects `DID`,
    /// `SIGNING_KEY_MB`, `KA_KEY_MB`, `VTA_DID`, `VTA_URL`, `CONTEXT_ID`,
    /// `CONTEXT_DID`, `NOW` automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_vars: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateDidWebvhResultBody {
    pub did: String,
    pub context_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    pub scid: String,
    pub portable: bool,
    pub signing_key_id: String,
    pub ka_key_id: String,
    pub pre_rotation_key_count: u32,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_entry: Option<String>,
}

// Manual Debug — `mnemonic` is a 24-word BIP-39 phrase that recovers
// the entire key hierarchy under the DID. Logging it via `{:?}` is a
// total compromise. Serialize is unchanged so the wire shape and
// sealed-transfer payload still round-trip.
impl std::fmt::Debug for CreateDidWebvhResultBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateDidWebvhResultBody")
            .field("did", &self.did)
            .field("context_id", &self.context_id)
            .field("server_id", &self.server_id)
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("scid", &self.scid)
            .field("portable", &self.portable)
            .field("signing_key_id", &self.signing_key_id)
            .field("ka_key_id", &self.ka_key_id)
            .field("pre_rotation_key_count", &self.pre_rotation_key_count)
            .field("created_at", &self.created_at)
            .field("did_document", &self.did_document)
            .field("log_entry", &self.log_entry)
            .finish()
    }
}
