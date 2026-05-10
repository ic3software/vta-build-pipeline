//! `did.jsonl` ↔ [`DIDWebVHState`] round-trip + record-by-SCID lookup.

use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;
use vta_sdk::webvh::WebvhDidRecord;

use super::errors::UpdateDidWebvhError;
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Find a `WebvhDidRecord` by SCID. The store is DID-keyed; this scans
/// `list_dids` and filters. Acceptable since updates are infrequent
/// (operator-driven). Optimise later with an SCID→DID index if needed.
pub(in crate::operations::did_webvh) async fn find_record_by_scid(
    webvh_ks: &KeyspaceHandle,
    scid: &str,
) -> Result<Option<WebvhDidRecord>, UpdateDidWebvhError> {
    let all = webvh_store::list_dids(webvh_ks)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("list_dids: {e}")))?;
    Ok(all.into_iter().find(|r| r.scid == scid))
}

/// Build a [`DIDWebVHState`] from a stored JSONL log string. Splits on
/// newlines, deserializes each non-empty line as a `LogEntry`, then
/// validates the chain so `validated_parameters` is populated.
pub(in crate::operations::did_webvh) fn state_from_jsonl(
    did_log: &str,
) -> Result<DIDWebVHState, UpdateDidWebvhError> {
    let mut state = DIDWebVHState::default();
    for line in did_log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, None)
            .map_err(|e| UpdateDidWebvhError::Library(format!("parse log entry: {e}")))?;
        let version_number = entry.get_version_id_fields().map(|f| f.0).unwrap_or(0);
        state
            .log_entries_mut()
            .push(didwebvh_rs::log_entry_state::LogEntryState {
                log_entry: entry,
                version_number,
                validation_status:
                    didwebvh_rs::log_entry_state::LogEntryValidationStatus::NotValidated,
                validated_parameters: didwebvh_rs::parameters::Parameters::default(),
            });
    }
    state
        .validate()
        .map_err(|e| UpdateDidWebvhError::Library(format!("chain validation: {e}")))?
        .assert_complete()
        .map_err(|e| UpdateDidWebvhError::Library(format!("chain validation: {e}")))?;
    Ok(state)
}

/// Serialize a [`DIDWebVHState`]'s log entries back to JSONL for
/// persistence in the webvh store.
pub(in crate::operations::did_webvh) fn state_to_jsonl(
    state: &DIDWebVHState,
) -> Result<String, UpdateDidWebvhError> {
    let mut out = String::new();
    for entry in state.log_entries() {
        let line = serde_json::to_string(&entry.log_entry)
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize log entry: {e}")))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}
