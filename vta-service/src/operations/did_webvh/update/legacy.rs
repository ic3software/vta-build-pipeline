//! Legacy fallbacks for DIDs that predate the
//! [`crate::operations::did_webvh::webvh_keys`] storage convention.
//!
//! Operators with DIDs created on early VTA builds have keys stored
//! only at the legacy `key:*` keyspace. The fast-path lookups in
//! [`super::keys`] consult `webvh_keys` first; on a miss the
//! orchestrator falls back to one of these helpers, which scan
//! `key:*` records for a hash or pubkey match and synthesise a
//! [`WebvhKeyHandle`] from the record.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use vta_sdk::keys::KeyRecord;

use super::errors::UpdateDidWebvhError;
use crate::operations::did_webvh::webvh_keys::{WebvhKeyHandle, WebvhKeyRole};
use crate::store::KeyspaceHandle;

/// Legacy fallback: scan `key:*` records (the pre-`webvh_keys` storage
/// convention) for a record whose `public_key` hashes to `target_hash`.
/// Used by DIDs created before the genesis pre-rotation handles were
/// installed in the `webvh_keys` keyspace.
pub(in crate::operations::did_webvh) async fn legacy_lookup_pre_rotation_by_hash(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    target_hash: &str,
) -> Result<Option<WebvhKeyHandle>, UpdateDidWebvhError> {
    let raw_keys = keys_ks
        .prefix_keys(b"key:".to_vec())
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("legacy scan: {e}")))?;
    for raw in raw_keys {
        let record: Option<KeyRecord> = keys_ks
            .get(raw)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("legacy load: {e}")))?;
        let Some(record) = record else { continue };
        let computed = match Secret::base58_hash_string(&record.public_key) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if computed != target_hash {
            continue;
        }
        return Ok(Some(WebvhKeyHandle {
            scid: scid.to_string(),
            // Synthetic — legacy records pre-date the per-version
            // convention. Fine for re-deriving the secret; supersede
            // routines key off `webvh_keys` storage entries directly,
            // not this synthetic version.
            version_id: "legacy".into(),
            hash: target_hash.to_string(),
            public_key: record.public_key.clone(),
            derivation_path: record.derivation_path.clone(),
            seed_id: record.seed_id,
            role: WebvhKeyRole::PreRotation,
            label: record
                .label
                .unwrap_or_else(|| format!("legacy pre-rotation key for {scid}")),
            created_at: Utc::now(),
        }));
    }
    Ok(None)
}

/// Scan the legacy `key:*` keyspace for a record whose multibase
/// public_key matches `target_pubkey`. Synthesise a [`WebvhKeyHandle`]
/// from the record's `derivation_path` + `seed_id` so the caller can
/// re-derive the secret. Returns `Ok(None)` if no match.
pub(in crate::operations::did_webvh) async fn legacy_lookup_by_public_key(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    target_pubkey: &str,
    hash: &str,
) -> Result<Option<WebvhKeyHandle>, UpdateDidWebvhError> {
    let raw_keys = keys_ks
        .prefix_keys(b"key:".to_vec())
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("legacy scan: {e}")))?;
    for raw in raw_keys {
        let record: Option<KeyRecord> = keys_ks
            .get(raw)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("legacy load: {e}")))?;
        let Some(record) = record else { continue };
        if record.public_key != target_pubkey {
            continue;
        }
        return Ok(Some(WebvhKeyHandle {
            scid: scid.to_string(),
            // Synthetic version-id — legacy records pre-date the
            // per-version convention. Subsequent updates will install
            // fresh handles under the actual log version-id.
            version_id: "legacy".into(),
            hash: hash.to_string(),
            public_key: target_pubkey.to_string(),
            derivation_path: record.derivation_path.clone(),
            seed_id: record.seed_id,
            role: WebvhKeyRole::UpdateKey,
            label: record
                .label
                .unwrap_or_else(|| format!("legacy update key for {scid}")),
            created_at: Utc::now(),
        }));
    }
    Ok(None)
}
