//! Server-side storage for DID templates.
//!
//! Phase 2 scope: **global** scope only. Record keys are `tpl:global:<name>`.
//! Context-scoped templates (keys `tpl:ctx:<context_id>:<name>`) arrive in
//! Phase 3.
//!
//! The record shape is defined in [`vta_sdk::did_templates::DidTemplateRecord`]
//! and reused verbatim on the wire — no server-side wrapper struct.

pub use vta_sdk::did_templates::DidTemplateRecord;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

const GLOBAL_PREFIX: &str = "tpl:global:";

fn global_key(name: &str) -> String {
    format!("{GLOBAL_PREFIX}{name}")
}

/// Fetch a global template by name.
pub async fn get_global_template(
    ks: &KeyspaceHandle,
    name: &str,
) -> Result<Option<DidTemplateRecord>, AppError> {
    ks.get(global_key(name)).await
}

/// Store (create or overwrite) a global template record.
pub async fn store_global_template(
    ks: &KeyspaceHandle,
    record: &DidTemplateRecord,
) -> Result<(), AppError> {
    ks.insert(global_key(&record.template.name), record).await
}

/// Delete a global template by name.
pub async fn delete_global_template(ks: &KeyspaceHandle, name: &str) -> Result<(), AppError> {
    ks.remove(global_key(name)).await
}

/// List every stored global template, sorted by name.
pub async fn list_global_templates(
    ks: &KeyspaceHandle,
) -> Result<Vec<DidTemplateRecord>, AppError> {
    let raw = ks.prefix_iter_raw(GLOBAL_PREFIX).await?;
    let mut records = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidTemplateRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    records.sort_by(|a, b| a.template.name.cmp(&b.template.name));
    Ok(records)
}
