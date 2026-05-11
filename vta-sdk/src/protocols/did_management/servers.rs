use serde::{Deserialize, Serialize};

use crate::webvh::WebvhServerRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddWebvhServerBody {
    pub id: String,
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub type AddWebvhServerResultBody = WebvhServerRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListWebvhServersBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListWebvhServersResultBody {
    pub servers: Vec<WebvhServerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateWebvhServerBody {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub type UpdateWebvhServerResultBody = WebvhServerRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveWebvhServerBody {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveWebvhServerResultBody {
    pub id: String,
    pub removed: bool,
}

/// Promote a serverless WebVH DID to a server-managed one. The
/// target server must already be registered via
/// [`AddWebvhServerBody`]; the DID's local `did.jsonl` is pushed
/// to the host atomically (single batched write — no resolver
/// gap) and the local record's `server_id` flips from
/// `"serverless"` to `server_id` so future updates auto-publish.
///
/// `force` is honoured only when the caller authenticates to the
/// host as an admin replacing a slot owned by a different DID.
/// An owner re-registering their own slot is idempotent and
/// always allowed without force.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDidWithServerBody {
    pub did: String,
    pub server_id: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDidWithServerResultBody {
    pub did: String,
    pub server_id: String,
    pub log_entry_count: u32,
}
