//! Caller-supplied request types and result types shared across the
//! `update` submodule.
//!
//! `DerivedWebvhKey` is a phase-1 derive output — produced by
//! [`crate::operations::did_webvh::update::keys::derive_webvh_keys`]
//! before the consuming `didwebvh_rs::update_did` call has produced
//! the new log-entry's `version_id`. The handle is installed via
//! [`crate::operations::did_webvh::update::keys::install_derived_webvh_keys`]
//! once the version-id is known.

use std::time::Duration;

use didwebvh_rs::witness::Witnesses;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Caller-supplied parameters for
/// [`crate::operations::did_webvh::update::update_did_webvh`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateDidWebvhOptions {
    /// New DID document. `None` = keep existing. When `Some`, forces a
    /// parallel rotation of `update_keys` + pre-rotation commitments.
    #[serde(default)]
    pub document: Option<Value>,
    /// Override pre-rotation count. `None` = keep current. `Some(0)` =
    /// disable pre-rotation. `Some(n)` = use `n` keys.
    #[serde(default)]
    pub pre_rotation_count: Option<u32>,
    /// New witness configuration. `None` = keep current.
    #[serde(default)]
    pub witnesses: Option<Witnesses>,
    /// New watcher URLs. `None` = keep current. `Some(vec![])` disables.
    #[serde(default)]
    pub watchers: Option<Vec<String>>,
    /// New TTL in seconds. `None` = keep current.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Operator-facing label for audit. Optional.
    #[serde(default)]
    pub label: Option<String>,
    /// Optimistic-concurrency precondition. When `Some`, the operation
    /// refuses with `Conflict` if the DID's latest log entry no longer
    /// matches this versionId. Lets a `get → edit → save` flow detect
    /// lost updates instead of silently overwriting another operator's
    /// edits with a chain that's structurally valid but content-wise
    /// based on a stale read. `None` (default) preserves prior
    /// behaviour for scripted callers.
    #[serde(default)]
    pub expected_version_id: Option<String>,
}

/// Result of a successful update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDidWebvhResult {
    pub did: String,
    pub new_version_id: String,
    pub new_scid: String,
    pub new_log_entry: String,
    pub update_keys_count: u32,
    pub pre_rotation_key_count: u32,
}

/// A freshly-derived webvh key. Not yet persisted — the caller installs
/// it via
/// [`crate::operations::did_webvh::update::keys::install_derived_webvh_keys`]
/// after `didwebvh_rs::update_did` returns with the real new
/// `version_id` (the version-id is part of the storage key, and we
/// can't predict the hash component of it).
///
/// The secret itself isn't stored on the struct — webvh handles are
/// re-derivable from `(seed_id, derivation_path)`, so the caller gets
/// what it needs to persist the handle without holding key material
/// across the async boundary.
pub(in crate::operations::did_webvh) struct DerivedWebvhKey {
    pub public_key: String,
    pub hash: String,
    pub derivation_path: String,
    pub seed_id: u32,
}

/// Hard cap on per-witness DID resolution. Witnesses are typically
/// `did:key` (self-resolving, instant) but the library also accepts
/// `did:web`-style witnesses. 5s is generous for self-resolving keys
/// and short enough that an unresponsive web resolver doesn't hang the
/// admin's update call.
pub(in crate::operations::did_webvh) const WITNESS_RESOLVE_TIMEOUT: Duration =
    Duration::from_secs(5);

/// Caller-supplied parameters for
/// [`crate::operations::did_webvh::update::rotate_did_webvh_keys`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RotateDidWebvhKeysOptions {
    /// Override pre-rotation count for the new commitment set.
    /// `None` = keep current.
    #[serde(default)]
    pub pre_rotation_count: Option<u32>,
    /// Operator-facing label for audit. Optional.
    #[serde(default)]
    pub label: Option<String>,
}
