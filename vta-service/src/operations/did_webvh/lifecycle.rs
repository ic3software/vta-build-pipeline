//! Read operations for did:webvh records: fetch a single record, fetch
//! the `did.jsonl` log, or list records filtered by context/server.
//!
//! Delete lives in the parent module alongside the `WebvhTransport`
//! abstraction because it has to reach out to the hosting server for
//! remote cleanup. Create is the main flow and also stays in mod.rs.

use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;
use vta_sdk::protocols::did_management::lifecycle::GetDidWebvhLogResultBody;
use vta_sdk::protocols::did_management::list::ListDidsWebvhResultBody;
use vta_sdk::webvh::WebvhDidRecord;

// Wire types canonically live in vta-sdk per
// `memory::feedback-wire-types-in-sdk`. Re-export from there so
// existing op-layer call sites keep working unchanged.
pub use vta_sdk::protocols::did_management::lifecycle::GetDidWebvhLogResultBody as GetDidWebvhLogResult;

pub async fn get_did_webvh(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<WebvhDidRecord, AppError> {
    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    auth.require_context(&record.context_id)?;
    info!(channel, did = %did, "webvh DID retrieved");
    Ok(record)
}

pub async fn get_did_webvh_log(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
    channel: &str,
) -> Result<GetDidWebvhLogResult, AppError> {
    let record = webvh_store::get_did(webvh_ks, did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webvh DID not found: {did}")))?;
    auth.require_context(&record.context_id)?;
    let log = webvh_store::get_did_log(webvh_ks, did).await?;
    info!(channel, did = %did, "webvh DID log retrieved");
    Ok(GetDidWebvhLogResultBody {
        did: did.to_string(),
        log,
    })
}

pub async fn list_dids_webvh(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    context_id: Option<&str>,
    server_id: Option<&str>,
    channel: &str,
) -> Result<ListDidsWebvhResultBody, AppError> {
    let all = webvh_store::list_dids(webvh_ks).await?;
    let dids: Vec<WebvhDidRecord> = all
        .into_iter()
        .filter(|d| auth.has_context_access(&d.context_id))
        .filter(|d| context_id.is_none_or(|c| d.context_id == c))
        .filter(|d| server_id.is_none_or(|s| d.server_id == s))
        .collect();
    info!(channel, caller = %auth.did, count = dids.len(), "webvh DIDs listed");
    Ok(ListDidsWebvhResultBody { dids })
}
