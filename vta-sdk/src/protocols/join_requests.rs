//! DIDComm wire types for VTC join-request submission.
//!
//! The corresponding REST endpoint is `POST /v1/join-requests`;
//! over DIDComm the message `type` field IS the Trust Task URL
//! (workspace convention) and the DIDComm authcrypt sender
//! authenticates the applicant DID — no separate holder-binding
//! signature is needed (the envelope already binds the sender).

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// DIDComm message `type` for a join-request submission.
pub const JOIN_REQUEST_SUBMIT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0";

/// DIDComm message `type` for the VTC's reply (the submission
/// receipt). Carried as a `thid` reply to the submit message id.
pub const JOIN_REQUEST_SUBMIT_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit-receipt/1.0";

/// Body of the submit message. Applicant_did comes from the
/// DIDComm `from` field, not the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitBody {
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
}

/// Body of the receipt message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitReceiptBody {
    pub request_id: Uuid,
    /// Status string. Always `"pending"` for a successful submit;
    /// future protocol versions may add `"deferred"` etc.
    pub status: String,
}

// ---------------------------------------------------------------------------
// Self-remove (M1.11.1 DIDComm twin)
// ---------------------------------------------------------------------------

/// DIDComm `type` for a member-side self-removal.
pub const MEMBER_SELF_REMOVE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0";

/// VTC's reply with the resolved disposition + audit hint.
pub const MEMBER_SELF_REMOVE_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove-receipt/1.0";

/// Body of the self-remove message. `did` comes from the DIDComm
/// `from` field — the caller's authcrypt sender authenticates
/// them. Disposition optional; falls back to the Member's stored
/// `departure_preference` and then to PolicyDefault→Tombstone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelfRemoveBody {
    #[serde(default)]
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfRemoveReceiptBody {
    pub did: String,
    /// Resolved disposition (`"purge"` | `"tombstone"` |
    /// `"historical"`). `policydefault` is never returned —
    /// the daemon resolves it before responding.
    pub disposition: String,
    pub removed: bool,
}
