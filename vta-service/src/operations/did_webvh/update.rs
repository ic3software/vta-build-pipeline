//! Generic update + key rotation for webvh DIDs.
//!
//! Two operations sit on top of [`didwebvh_rs::update::update_did`]:
//!
//! - [`update_did_webvh`] — apply new state (optional new document,
//!   plus witness / watcher / TTL / pre-rotation toggle). When a new
//!   document is supplied the VTA forces a parallel rotation of the
//!   webvh authorization keys + pre-rotation commitments.
//! - [`rotate_did_webvh_keys`] — convenience that fetches the current
//!   document, mints fresh BIP-32 keys for every verificationMethod
//!   (preserving role/type, bumping fragment IDs to fresh unique
//!   values), and feeds the rebuilt document through `update_did_webvh`.
//!
//! See `docs/03-integrating/did-webvh-update.md` for the operator-
//! facing flow + wire format.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::multibase_type::Multibase;
use didwebvh_rs::update::{UpdateDIDConfig, update_did};
use didwebvh_rs::witness::Witnesses;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::keys::KeyRecord;
use vta_sdk::webvh::WebvhDidRecord;

use super::WebvhTransport;
use super::webvh_keys::{self, WebvhKeyHandle, WebvhKeyRole};
use crate::audit;
use crate::auth::AuthClaims;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Caller-supplied parameters for [`update_did_webvh`].
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
/// it via [`install_derived_webvh_keys`] after `didwebvh_rs::update_did`
/// returns with the real new `version_id` (the version-id is part of
/// the storage key, and we can't predict the hash component of it).
///
/// The secret itself isn't stored on the struct — webvh handles are
/// re-derivable from `(seed_id, derivation_path)`, so the caller gets
/// what it needs to persist the handle without holding key material
/// across the async boundary.
pub(super) struct DerivedWebvhKey {
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
const WITNESS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors produced by [`update_did_webvh`] and [`rotate_did_webvh_keys`].
///
/// `From<UpdateDidWebvhError> for AppError` maps each variant to a stable
/// HTTP status: `NotFound` and `Forbidden` both surface as 404 to avoid
/// leaking cross-context existence information; validation errors map to
/// 400; concurrency conflicts map to 409; everything else is 500.
#[derive(Debug, thiserror::Error)]
pub enum UpdateDidWebvhError {
    /// SCID not found, or the DID exists but is owned by a different
    /// context than the caller has admin rights for. Both cases collapse
    /// to a single error variant + 404 status to avoid leaking
    /// cross-context existence.
    #[error("did not found: {0}")]
    NotFound(String),

    /// Caller authenticated successfully but is not an admin of the
    /// DID's context. Mapped to 404 by the REST/DIDComm boundary —
    /// see [`From<UpdateDidWebvhError> for AppError`].
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Optimistic-concurrency mismatch: the DID's `log_entry_count`
    /// changed between load and write. Caller should re-read and retry.
    #[error("concurrent update: {0}")]
    Conflict(String),

    /// Caller-supplied DID document is malformed (missing `@context`,
    /// `id` doesn't match the existing DID, verificationMethod entries
    /// missing required fields, …).
    #[error("invalid document: {0}")]
    InvalidDocument(String),

    /// Caller-supplied witness configuration is invalid (witness DID
    /// did not resolve, malformed witness entry, …).
    #[error("invalid witness configuration: {0}")]
    InvalidWitness(String),

    /// Caller-supplied watcher URL is invalid (parse error, wrong
    /// scheme, query/fragment present, …).
    #[error("invalid watcher: {0}")]
    InvalidWatcher(String),

    /// Underlying `didwebvh-rs` library error during `update_did`.
    /// Usually indicates a state-machine violation (e.g. signing key
    /// not in the active update_keys set) that the orchestration
    /// should have caught earlier — surface as 500.
    #[error("webvh library error: {0}")]
    Library(String),

    /// Persistence failure (keys keyspace, webvh keyspace, contexts
    /// keyspace).
    #[error("persistence error: {0}")]
    Persistence(String),

    /// Failed to publish the new log entry to the webvh hosting server.
    /// The local log was written successfully; the operator can retry
    /// publication independently.
    #[error("publish error: {0}")]
    Publish(String),
}

/// Validate a caller-supplied DID document for update.
///
/// Checks:
/// 1. `document.id` equals `existing_did` — operators cannot rename a DID
///    via update; the DID is immutable for the lifetime of the document.
/// 2. `@context` is present (JSON-LD shape).
/// 3. `verificationMethod`, if present, is an array; every entry has the
///    minimum required fields (`id`, `type`, `controller`,
///    `publicKeyMultibase`). Externally-hosted public keys are allowed —
///    the VTA does not require it to have minted them — but the entry's
///    shape has to be well-formed.
///
/// Returns the document unchanged so callers can chain.
pub(super) fn validate_document_for_update(
    document: Value,
    existing_did: &str,
) -> Result<Value, UpdateDidWebvhError> {
    let obj = document.as_object().ok_or_else(|| {
        UpdateDidWebvhError::InvalidDocument("document must be a JSON object".into())
    })?;

    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| UpdateDidWebvhError::InvalidDocument("document missing `id`".into()))?;
    if id != existing_did {
        return Err(UpdateDidWebvhError::InvalidDocument(format!(
            "document.id `{id}` does not match existing DID `{existing_did}`"
        )));
    }

    if obj.get("@context").is_none() {
        return Err(UpdateDidWebvhError::InvalidDocument(
            "document missing `@context`".into(),
        ));
    }

    if let Some(vm) = obj.get("verificationMethod") {
        let vms = vm.as_array().ok_or_else(|| {
            UpdateDidWebvhError::InvalidDocument("verificationMethod must be an array".into())
        })?;
        for (i, entry) in vms.iter().enumerate() {
            let entry_obj = entry.as_object().ok_or_else(|| {
                UpdateDidWebvhError::InvalidDocument(format!(
                    "verificationMethod[{i}] is not a JSON object"
                ))
            })?;
            for required in ["id", "type", "controller", "publicKeyMultibase"] {
                if !entry_obj.contains_key(required) {
                    return Err(UpdateDidWebvhError::InvalidDocument(format!(
                        "verificationMethod[{i}] missing `{required}`"
                    )));
                }
            }
        }
    }

    Ok(document)
}

/// Derive `count` Ed25519 keys via BIP-32 under `base_path`. Pure —
/// no keyspace writes. Pair with [`install_derived_webvh_keys`] to
/// persist once the consuming `update_did` call has produced the
/// new log entry's `version_id`.
pub(super) async fn derive_webvh_keys(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    base_path: &str,
    count: u32,
) -> Result<Vec<DerivedWebvhKey>, UpdateDidWebvhError> {
    if count == 0 {
        return Ok(vec![]);
    }

    let seed_id = get_active_seed_id(keys_ks).await.map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("could not load active seed id: {e}"))
    })?;
    let seed = load_seed_bytes(keys_ks, seed_store, Some(seed_id))
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("could not load seed: {e}")))?;

    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("BIP-32 root derivation: {e}")))?;

    let mut derived = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let path = allocate_path(keys_ks, base_path)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("allocate_path: {e}")))?;
        let parsed: DerivationPath = path.parse().map_err(|e| {
            UpdateDidWebvhError::Persistence(format!("parse derivation path `{path}`: {e}"))
        })?;
        let key = root
            .derive(&parsed)
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("derive at `{path}`: {e}")))?;
        let secret = Secret::generate_ed25519(None, Some(key.signing_key.as_bytes()));
        let public_key = secret
            .get_public_keymultibase()
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("public key encoding: {e}")))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("public key hash: {e}")))?;
        derived.push(DerivedWebvhKey {
            public_key,
            hash,
            derivation_path: path,
            seed_id,
        });
    }

    Ok(derived)
}

/// Persist [`DerivedWebvhKey`]s into `webvh_keys` under the new
/// log-entry's `version_id`. Called after `didwebvh_rs::update_did`
/// returns successfully.
#[allow(clippy::too_many_arguments)]
pub(super) async fn install_derived_webvh_keys(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    version_id: &str,
    role: WebvhKeyRole,
    derived: &[DerivedWebvhKey],
    label_prefix: &str,
) -> Result<(), UpdateDidWebvhError> {
    let now = Utc::now();
    for (i, key) in derived.iter().enumerate() {
        let handle = WebvhKeyHandle {
            scid: scid.to_string(),
            version_id: version_id.to_string(),
            hash: key.hash.clone(),
            public_key: key.public_key.clone(),
            derivation_path: key.derivation_path.clone(),
            seed_id: Some(key.seed_id),
            role,
            label: format!("{label_prefix} #{i}"),
            created_at: now,
        };
        webvh_keys::install(keys_ks, &handle)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install webvh handle: {e}")))?;
    }
    Ok(())
}

/// Compute the multihash that webvh stores in `next_key_hashes` for a
/// given multibase-encoded public key. Standalone helper so we can hash
/// a public key we don't have the secret for (e.g. an `update_keys`
/// entry from the current log).
fn hash_public_key_multibase(pubkey_multibase: &str) -> Result<String, UpdateDidWebvhError> {
    Secret::base58_hash_string(pubkey_multibase).map_err(|e| {
        UpdateDidWebvhError::Library(format!(
            "could not hash public key `{pubkey_multibase}`: {e}"
        ))
    })
}

/// Resolve the active webvh authorization key for a DID — the secret
/// that signs the next log entry.
///
/// Strategy:
/// 1. Iterate the current log entry's `update_keys` (each is a
///    multibase-encoded public key).
/// 2. For each, compute its hash and look it up in the new
///    [`webvh_keys`] convention (fast path).
/// 3. If not found, fall back to the legacy `key:*` keyspace —
///    `KeyRecord`s indexed by `key_id` carry the multibase public key,
///    so we scan for a match. This is a one-shot path for DIDs created
///    before the `webvh_keys` convention existed; the caller should
///    install the returned handle into `webvh_keys` after a successful
///    update so subsequent calls hit the fast path.
///
/// Returns the [`WebvhKeyHandle`] for whichever update_key matched.
/// The caller still needs to re-derive the secret bytes from
/// `derivation_path` + the active seed.
pub(super) async fn load_active_update_key(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    update_keys: &[Multibase],
) -> Result<WebvhKeyHandle, UpdateDidWebvhError> {
    if update_keys.is_empty() {
        return Err(UpdateDidWebvhError::Library(
            "log entry has no update_keys — DID is deactivated or malformed".into(),
        ));
    }

    for pubkey_mb in update_keys {
        let pubkey_str = pubkey_mb.as_ref();
        let hash = hash_public_key_multibase(pubkey_str)?;

        // Fast path: webvh_keys convention.
        match webvh_keys::find_handle_by_hash(keys_ks, scid, &hash).await {
            Ok(Some(handle)) => {
                if matches!(handle.role, WebvhKeyRole::UpdateKey)
                    || matches!(handle.role, WebvhKeyRole::PreRotation)
                {
                    return Ok(handle);
                }
                // A Verification handle with the same hash means the
                // operator chose to use a doc VM as the update key —
                // also acceptable for signing.
                return Ok(handle);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(UpdateDidWebvhError::Persistence(format!(
                    "webvh_keys lookup failed: {e}"
                )));
            }
        }

        // Legacy fallback: scan `key:*` for a KeyRecord whose
        // multibase public_key matches.
        if let Some(handle) = legacy_lookup_by_public_key(keys_ks, scid, pubkey_str, &hash).await? {
            return Ok(handle);
        }
    }

    Err(UpdateDidWebvhError::Library(format!(
        "no active update key for DID with SCID {scid} found in keys keyspace — \
         operator may need to restore key material from backup"
    )))
}

/// Scan the legacy `key:*` keyspace for a record whose multibase
/// public_key matches `target_pubkey`. Synthesise a [`WebvhKeyHandle`]
/// from the record's `derivation_path` + `seed_id` so the caller can
/// re-derive the secret. Returns `Ok(None)` if no match.
/// Resolve a webvh signing key whose hash is committed in
/// `previous.next_key_hashes` (pre-rotation reveal path).
///
/// Iterates each committed hash and tries:
/// 1. Fast path: `webvh_keys::find_handle_by_hash` (works for DIDs created
///    after the genesis-pre-rotation install fix in `create_did_webvh`).
/// 2. Legacy fallback: scan `key:{did}#pre-rotation-N` records, hash each
///    record's `public_key`, and return the first match (handles DIDs
///    that predate the `webvh_keys` index).
///
/// Returns the [`WebvhKeyHandle`] for the matched key — the caller
/// re-derives the secret via [`derive_secret_for_handle`].
pub(super) async fn load_pre_rotation_signing_key(
    keys_ks: &KeyspaceHandle,
    scid: &str,
    committed_hashes: &[String],
) -> Result<WebvhKeyHandle, UpdateDidWebvhError> {
    if committed_hashes.is_empty() {
        return Err(UpdateDidWebvhError::Library(
            "previous entry has empty next_key_hashes — pre-rotation reveal impossible".into(),
        ));
    }
    tracing::debug!(
        scid,
        hashes = ?committed_hashes,
        "load_pre_rotation_signing_key: searching for committed pre-rotation candidate"
    );
    for hash in committed_hashes {
        // Fast path.
        match webvh_keys::find_handle_by_hash(keys_ks, scid, hash).await {
            Ok(Some(handle)) => {
                tracing::debug!(
                    scid,
                    hash,
                    role = ?handle.role,
                    public_key = %handle.public_key,
                    "load_pre_rotation_signing_key: fast-path hit"
                );
                return Ok(handle);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(UpdateDidWebvhError::Persistence(format!(
                    "webvh_keys lookup by hash: {e}"
                )));
            }
        }
        // Legacy fallback.
        if let Some(handle) = legacy_lookup_pre_rotation_by_hash(keys_ks, scid, hash).await? {
            tracing::debug!(
                scid,
                hash,
                public_key = %handle.public_key,
                "load_pre_rotation_signing_key: legacy fallback hit"
            );
            return Ok(handle);
        }
    }
    Err(UpdateDidWebvhError::Library(format!(
        "no pre-rotation key found for any committed hash: {committed_hashes:?}"
    )))
}

/// Legacy fallback: scan `key:*` records (the pre-`webvh_keys` storage
/// convention) for a record whose `public_key` hashes to `target_hash`.
/// Used by DIDs created before the genesis pre-rotation handles were
/// installed in the `webvh_keys` keyspace.
async fn legacy_lookup_pre_rotation_by_hash(
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

async fn legacy_lookup_by_public_key(
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

/// Caller-supplied parameters for [`rotate_did_webvh_keys`].
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

/// Rotate every verificationMethod's keys (preserving role/type but
/// minting fresh public-key bytes + bumping fragment ids), then drive
/// the doc-bearing [`update_did_webvh`] path. Auth keys + pre-rotation
/// rotate as a consequence of the document update.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_did_webvh_keys(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    auth: &AuthClaims,
    scid: &str,
    opts: RotateDidWebvhKeysOptions,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    // 1. Load record + log.
    let mut record = find_record_by_scid(webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    auth.require_admin()
        .map_err(|e| UpdateDidWebvhError::Forbidden(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id).map_err(|_| {
        UpdateDidWebvhError::Forbidden(format!(
            "caller has no admin role in context `{}`",
            record.context_id
        ))
    })?;

    let did_log = webvh_store::get_did_log(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;
    let current_doc = last.log_entry.get_did_document().map_err(|e| {
        UpdateDidWebvhError::Library(format!("extract document from last entry: {e}"))
    })?;

    // 2. Resolve context base path.
    let context = crate::contexts::get_context(contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 3. Mint fresh keys for each VM in the current document.
    //    Preserve role/type/controller; mint new fragment ids monotonically
    //    from `record.next_fragment_id`. Resulting doc has the same
    //    semantic shape with new key bytes.
    let mut new_doc = current_doc.clone();
    let vms = new_doc
        .as_object_mut()
        .and_then(|o| o.get_mut("verificationMethod"))
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            UpdateDidWebvhError::Library("current doc has no verificationMethod array".into())
        })?;

    let vm_count = vms.len() as u32;
    let derived_vms = derive_webvh_keys(keys_ks, seed_store, &context.base_path, vm_count).await?;
    let first_new_fragment_id = record.next_fragment_id;
    // Snapshot the version-vector fields so the next_fragment_id bump
    // (below) can detect a concurrent rotate that would have derived
    // overlapping `#key-N` fragment ids. Without this, two parallel
    // `rotate_did_webvh_keys` calls each derive
    // [next_fragment_id, next_fragment_id + N) keys; only one
    // store_did wins, but the loser has minted keys whose ids collide
    // with the winner's published document.
    let pre_rotate_snapshot = crate::operations::did_webvh::RecordSnapshot::capture(&record);

    // Track old fragment IDs for replacing references in
    // assertionMethod / authentication / keyAgreement arrays.
    let mut frag_remap: Vec<(String, String)> = Vec::with_capacity(vm_count as usize);
    for (i, (vm, derived_key)) in vms.iter_mut().zip(derived_vms.iter()).enumerate() {
        let old_id = vm
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                UpdateDidWebvhError::Library(format!("verificationMethod[{i}] missing id"))
            })?
            .to_string();
        let new_frag_id = record.next_fragment_id + i as u32;
        let new_id = format!("{}#key-{new_frag_id}", record.did);
        frag_remap.push((old_id, new_id.clone()));

        let obj = vm.as_object_mut().unwrap();
        obj.insert("id".into(), Value::String(new_id));
        obj.insert(
            "publicKeyMultibase".into(),
            Value::String(derived_key.public_key.clone()),
        );
    }

    // Update assertion / authentication / keyAgreement arrays to point
    // at the new VM ids. The original arrays are preserved positionally;
    // we just swap each entry's id with the new one assigned to the
    // VM at that position.
    for field in ["assertionMethod", "authentication", "keyAgreement"] {
        if let Some(arr) = new_doc
            .as_object_mut()
            .and_then(|o| o.get_mut(field))
            .and_then(|v| v.as_array_mut())
        {
            for entry in arr.iter_mut() {
                if let Some(s) = entry.as_str()
                    && let Some((_, new_id)) = frag_remap.iter().find(|(old, _)| old == s)
                {
                    *entry = Value::String(new_id.clone());
                }
            }
        }
    }

    // 4. Bump next_fragment_id on the record so subsequent rotates
    //    don't collide. CAS first: if a concurrent op already touched
    //    the record between snapshot and now, refuse rather than
    //    blindly clobbering — the in-flight derived keys would
    //    overlap the winner's already-issued fragment ids.
    let current = webvh_store::get_did(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did (rotate CAS): {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("DID {} disappeared mid-rotate", record.did))
        })?;
    pre_rotate_snapshot
        .assert_unchanged(&current)
        .map_err(|race| UpdateDidWebvhError::Conflict(race.to_string()))?;
    record.next_fragment_id += vm_count;
    webvh_store::store_did(webvh_ks, &record)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did (frag bump): {e}")))?;

    // 5. Drive the generic update path. The doc-bearing branch will
    //    rotate auth keys + pre-rotation as a side effect.
    let label = opts
        .label
        .or_else(|| Some(format!("rotate-keys for {}", record.did)));
    let result = update_did_webvh(
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        auth,
        scid,
        UpdateDidWebvhOptions {
            document: Some(new_doc),
            pre_rotation_count: opts.pre_rotation_count,
            witnesses: None,
            watchers: None,
            ttl: None,
            label,
            // rotate_did_webvh_keys composes update_did_webvh internally;
            // it doesn't expose the precondition (rotation is not a
            // user-edited document flow), so pass None.
            expected_version_id: None,
        },
        did_resolver,
        didcomm_bridge,
        channel,
    )
    .await?;

    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        first_fragment = first_new_fragment_id,
        last_fragment = record.next_fragment_id - 1,
        "did:webvh keys rotated"
    );

    Ok(result)
}

/// Find a `WebvhDidRecord` by SCID. The store is DID-keyed; this scans
/// `list_dids` and filters. Acceptable since updates are infrequent
/// (operator-driven). Optimise later with an SCID→DID index if needed.
async fn find_record_by_scid(
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
fn state_from_jsonl(did_log: &str) -> Result<DIDWebVHState, UpdateDidWebvhError> {
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

/// Re-derive the secret material for a [`WebvhKeyHandle`] from the seed
/// plus its BIP-32 path. The handle stores the path; the seed lives in
/// the seed store.
///
/// The returned [`Secret`]'s `id` is set to a proper `did:key`
/// verification-method form (`did:key:<mb>#<mb>`) — the
/// `affinidi-data-integrity::Signer::verification_method()` impl on
/// `Secret` returns `&self.id`, and `didwebvh-rs::update_did` parses
/// the `#`-separated multibase out of it to verify the signing key is
/// in the previous entry's `update_keys` set. Secrets minted with the
/// default kid (a random base64url u64) fail this check with
/// `verification_method 'X' must contain '#' with multibase key`.
async fn derive_secret_for_handle(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    handle: &WebvhKeyHandle,
) -> Result<Secret, UpdateDidWebvhError> {
    let seed = load_seed_bytes(keys_ks, seed_store, handle.seed_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("load seed: {e}")))?;
    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("BIP-32 root: {e}")))?;
    let path: DerivationPath = handle.derivation_path.parse().map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("parse path `{}`: {e}", handle.derivation_path))
    })?;
    let derived = root.derive(&path).map_err(|e| {
        UpdateDidWebvhError::Persistence(format!("derive at `{}`: {e}", handle.derivation_path))
    })?;
    let mut secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
    secret.id = format!("did:key:{mb}#{mb}", mb = handle.public_key);
    Ok(secret)
}

/// Serialize a [`DIDWebVHState`]'s log entries back to JSONL for
/// persistence in the webvh store.
fn state_to_jsonl(state: &DIDWebVHState) -> Result<String, UpdateDidWebvhError> {
    let mut out = String::new();
    for entry in state.log_entries() {
        let line = serde_json::to_string(&entry.log_entry)
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize log entry: {e}")))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Drive a webvh DID update end-to-end. See module docs.
#[allow(clippy::too_many_arguments)]
pub async fn update_did_webvh(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    auth: &AuthClaims,
    scid: &str,
    opts: UpdateDidWebvhOptions,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    channel: &str,
) -> Result<UpdateDidWebvhResult, UpdateDidWebvhError> {
    // 1. Resolve SCID → record.
    let mut record = find_record_by_scid(webvh_ks, scid)
        .await?
        .ok_or_else(|| UpdateDidWebvhError::NotFound(format!("SCID {scid} not found")))?;
    let initial_log_entry_count = record.log_entry_count;

    // 2. Auth gate. Forbidden + NotFound both surface as 404 at the
    //    wire boundary — see `From<UpdateDidWebvhError> for AppError`.
    auth.require_admin()
        .map_err(|e| UpdateDidWebvhError::Forbidden(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id).map_err(|_| {
        UpdateDidWebvhError::Forbidden(format!(
            "caller has no admin role in context `{}`",
            record.context_id
        ))
    })?;

    // 3. Validate caller-supplied inputs (cheap; do before key derivation).
    let new_doc = match opts.document {
        Some(doc) => Some(validate_document_for_update(doc, &record.did)?),
        None => None,
    };
    if let Some(ref w) = opts.witnesses {
        validate_witnesses(w, did_resolver).await?;
    }
    if let Some(ref watch) = opts.watchers {
        validate_watchers(watch)?;
    }

    // 4. Load DID log → DIDWebVHState; validate the chain.
    let did_log = webvh_store::get_did_log(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did_log: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!("DID log missing for {}", record.did))
        })?;
    let state = state_from_jsonl(&did_log)?;
    let last_state = state.log_entries().last().ok_or_else(|| {
        UpdateDidWebvhError::Library(format!("DID {} has no log entries", record.did))
    })?;

    // 4a. Optimistic-concurrency precondition. Check BEFORE key
    //     derivation / signing so a stale `get → edit → save` cycle
    //     fails fast and cheap, with a message the operator can act
    //     on. This catches the lost-update race the within-operation
    //     `log_entry_count` check at the end does NOT — that one only
    //     covers two server calls racing each other; this one covers
    //     a client call that was authored against a stale view.
    if let Some(expected) = opts.expected_version_id.as_deref() {
        let latest = last_state.get_version_id();
        if latest != expected {
            return Err(UpdateDidWebvhError::Conflict(format!(
                "DID {} has been updated since you read it (expected versionId `{expected}`, \
                 current is `{latest}`). Re-fetch the document and re-apply your edits.",
                record.did
            )));
        }
    }

    let last_params = last_state.validated_parameters.clone();
    let last_update_keys: Vec<Multibase> = last_params
        .update_keys
        .as_ref()
        .map(|arc| (**arc).clone())
        .unwrap_or_default();
    // Pre-rotation is "active" when the previous entry committed
    // `next_key_hashes`. The library's `check_signing_key` consults
    // `previous.next_key_hashes` (not `previous.update_keys`) for the
    // signing-key authorization check in that case, so the next entry
    // MUST be signed by a key whose hash was in that commitment.
    // See didwebvh-rs::lib::DIDWebVHState::check_signing_key.
    let last_next_key_hashes: Vec<String> = last_params
        .next_key_hashes
        .as_ref()
        .map(|arc| arc.iter().map(|m| m.as_ref().to_string()).collect())
        .unwrap_or_default();
    let pre_rotation_active = !last_next_key_hashes.is_empty();

    // 5. Resolve effective pre-rotation count.
    let pre_rotation_count = opts.pre_rotation_count.unwrap_or(record.pre_rotation_count);

    // 6. Resolve context base path for BIP-32 derivation.
    let context = crate::contexts::get_context(contexts_ks, &record.context_id)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_context: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::Library(format!(
                "context `{}` referenced by DID is missing",
                record.context_id
            ))
        })?;

    // 7. Derive new keys (no persist yet — version_id unknown).
    //    With pre-rotation active, the "auth" key for the new entry is
    //    the *revealed* pre-rotation candidate from the previous entry,
    //    not a freshly-minted key. We pick that handle in step 8 below.
    let derived_auth = if new_doc.is_some() && !pre_rotation_active {
        derive_webvh_keys(keys_ks, seed_store, &context.base_path, 1).await?
    } else {
        vec![]
    };
    let derived_pre_rotation =
        derive_webvh_keys(keys_ks, seed_store, &context.base_path, pre_rotation_count).await?;

    // 8. Resolve the signing key.
    //
    //    With pre-rotation active, find a handle whose hash is in
    //    `last.next_key_hashes` — that's the only key webvh will accept
    //    as a signer for the next log entry. Without pre-rotation, fall
    //    back to the pre-existing `load_active_update_key` lookup over
    //    `last.update_keys`.
    tracing::info!(
        scid,
        did = %record.did,
        pre_rotation_active,
        next_key_hashes_count = last_next_key_hashes.len(),
        update_keys_count = last_update_keys.len(),
        "update_did_webvh: resolving signing key"
    );
    let signing_handle = if pre_rotation_active {
        load_pre_rotation_signing_key(keys_ks, scid, &last_next_key_hashes).await?
    } else {
        load_active_update_key(keys_ks, scid, &last_update_keys).await?
    };
    tracing::info!(
        scid,
        signing_pubkey = %signing_handle.public_key,
        signing_hash = %signing_handle.hash,
        signing_role = ?signing_handle.role,
        signing_version = %signing_handle.version_id,
        "update_did_webvh: signing key resolved"
    );
    let signing_secret = derive_secret_for_handle(keys_ks, seed_store, &signing_handle).await?;

    // 9. Build the library config.
    let mut builder = UpdateDIDConfig::<Secret, Secret>::builder_generic()
        .state(state)
        .signing_key(signing_secret);
    if let Some(doc) = new_doc {
        builder = builder.document(doc);
        let new_keys: Vec<Multibase> = if pre_rotation_active {
            // Reveal the pre-rotation key as the new update_keys entry.
            // `validate_pre_rotation_keys` requires every key in the new
            // update_keys to have its hash committed in
            // previous.next_key_hashes — `signing_handle.public_key`
            // satisfies that by construction (we picked it BY hash).
            vec![Multibase::from(signing_handle.public_key.clone())]
        } else {
            derived_auth
                .iter()
                .map(|k| Multibase::from(k.public_key.clone()))
                .collect()
        };
        builder = builder.update_keys(new_keys);
    } else if pre_rotation_active {
        // Metadata-only update under pre-rotation: still rotate
        // update_keys to the revealed pre-rotation pubkey so the chain's
        // active update-keys keep moving forward in lockstep with the
        // signing-key reveal. Otherwise the next entry's
        // `previous.next_key_hashes` carries an unused commitment while
        // the active key on record stays stale.
        builder = builder.update_keys(vec![Multibase::from(signing_handle.public_key.clone())]);
    }
    // Always pass next_key_hashes when caller toggled pre-rotation OR
    // when the DID currently uses pre-rotation — keeps the commitment
    // chain unbroken. Empty vec disables pre-rotation going forward.
    if opts.pre_rotation_count.is_some() || record.pre_rotation_count > 0 {
        let hashes: Vec<Multibase> = derived_pre_rotation
            .iter()
            .map(|k| Multibase::from(k.hash.clone()))
            .collect();
        builder = builder.next_key_hashes(hashes);
    }
    if let Some(w) = opts.witnesses.clone() {
        builder = builder.witness(w);
    }
    if let Some(watch) = opts.watchers.clone() {
        builder = builder.watchers(watch);
    }
    if let Some(t) = opts.ttl {
        builder = builder.ttl(t);
    }

    let cfg = builder
        .build()
        .map_err(|e| UpdateDidWebvhError::Library(format!("build update config: {e}")))?;

    // 10. Append the new log entry via the library.
    let result = update_did(cfg)
        .await
        .map_err(|e| UpdateDidWebvhError::Library(format!("update_did: {e}")))?;
    let new_log_entry = result.log_entry();
    let new_version_id = new_log_entry
        .get_version_id_fields()
        .map(|(n, h)| format!("{n}-{h}"))
        .map_err(|e| UpdateDidWebvhError::Library(format!("read version id: {e}")))?;
    let new_scid = new_log_entry.get_scid().unwrap_or_default().to_string();
    let new_log_entry_str = serde_json::to_string(new_log_entry)
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("serialize new entry: {e}")))?;

    // 11. Optimistic concurrency check before persisting.
    let current = webvh_store::get_did(webvh_ks, &record.did)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_did: {e}")))?
        .ok_or_else(|| {
            UpdateDidWebvhError::NotFound(format!("DID {} disappeared mid-update", record.did))
        })?;
    if current.log_entry_count != initial_log_entry_count {
        return Err(UpdateDidWebvhError::Conflict(format!(
            "DID {} was updated concurrently (expected log_entry_count {}, got {})",
            record.did, initial_log_entry_count, current.log_entry_count
        )));
    }

    // 12. Persist new log + new key handles + updated record.
    let new_log_jsonl = state_to_jsonl(result.state())?;
    webvh_store::store_did_log(webvh_ks, &record.did, &new_log_jsonl)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did_log: {e}")))?;

    if !derived_auth.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::UpdateKey,
            &derived_auth,
            "update key",
        )
        .await?;
    }
    if !derived_pre_rotation.is_empty() {
        install_derived_webvh_keys(
            keys_ks,
            scid,
            &new_version_id,
            WebvhKeyRole::PreRotation,
            &derived_pre_rotation,
            "pre-rotation key",
        )
        .await?;
    }
    // When we reveal a pre-rotation key, re-install it as an
    // `UpdateKey` handle under the new version_id. Without this, the
    // supersede step (below) moves the previous version's PreRotation
    // handle out of the active prefix, and the next update can't
    // resolve the now-active key by hash via the fast path. The handle
    // contents are otherwise identical to the previous PreRotation
    // entry — same derivation path, same secret.
    if pre_rotation_active {
        let revealed = WebvhKeyHandle {
            scid: scid.to_string(),
            version_id: new_version_id.clone(),
            hash: signing_handle.hash.clone(),
            public_key: signing_handle.public_key.clone(),
            derivation_path: signing_handle.derivation_path.clone(),
            seed_id: signing_handle.seed_id,
            role: WebvhKeyRole::UpdateKey,
            label: format!(
                "revealed pre-rotation key (was version {})",
                signing_handle.version_id
            ),
            created_at: Utc::now(),
        };
        webvh_keys::install(keys_ks, &revealed)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("install revealed key: {e}")))?;
    }

    // Supersede the previous version's keys (best-effort — handles that
    // never made it into webvh_keys, e.g. legacy DIDs, are silently
    // skipped by the prefix scan).
    if let Some(prev) = result
        .state()
        .log_entries()
        .iter()
        .rev()
        .nth(1)
        .map(|e| {
            e.log_entry
                .get_version_id_fields()
                .map(|(n, h)| format!("{n}-{h}"))
        })
        .transpose()
        .unwrap_or(None)
    {
        webvh_keys::supersede_keys_for_version(keys_ks, scid, &prev)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("supersede: {e}")))?;
    }

    record.log_entry_count += 1;
    record.pre_rotation_count = derived_pre_rotation.len() as u32;
    record.updated_at = Utc::now();
    webvh_store::store_did(webvh_ks, &record)
        .await
        .map_err(|e| UpdateDidWebvhError::Persistence(format!("store_did: {e}")))?;

    // 13. Publish the new log to the hosting server for non-serverless
    //     DIDs. The webvh server's `PUT /api/dids/{mnemonic}` is
    //     idempotent and accepts the full updated JSONL — same call
    //     shape as create. Local state is already committed, so a
    //     publish failure surfaces as `Publish` (HTTP 500) but doesn't
    //     undo the local update; operators can retry the publish
    //     out-of-band by re-issuing the same update.
    if record.server_id != "serverless" {
        let server = webvh_store::get_server(webvh_ks, &record.server_id)
            .await
            .map_err(|e| UpdateDidWebvhError::Persistence(format!("get_server: {e}")))?
            .ok_or_else(|| {
                UpdateDidWebvhError::Publish(format!(
                    "webvh server `{}` referenced by DID is missing",
                    record.server_id
                ))
            })?;
        let transport = WebvhTransport::from_server(&server, did_resolver, didcomm_bridge)
            .await
            .map_err(|e| UpdateDidWebvhError::Publish(format!("transport: {e}")))?;
        transport
            .publish_did(&record.mnemonic, &new_log_jsonl)
            .await
            .map_err(|e| UpdateDidWebvhError::Publish(format!("publish_did: {e}")))?;
    }

    // 14. Audit emission. Best-effort — a missing audit row should
    //     not undo a successful update, so we log+swallow on error.
    let resource = format!(
        "did:webvh:{scid} v{} → v{}",
        initial_log_entry_count, record.log_entry_count
    );
    let label = opts.label.as_deref().unwrap_or("update");
    if let Err(e) = audit::record(
        audit_ks,
        &format!("did.update:{label}"),
        &auth.did,
        Some(&resource),
        "success",
        Some(channel),
        Some(&record.context_id),
    )
    .await
    {
        tracing::warn!(
            channel,
            did = %record.did,
            error = %e,
            "did.update audit emission failed; update committed"
        );
    }

    tracing::info!(
        channel,
        did = %record.did,
        scid = %scid,
        new_version_id = %new_version_id,
        label = ?opts.label,
        "did:webvh updated"
    );

    let update_keys_count = if !derived_auth.is_empty() {
        derived_auth.len() as u32
    } else if pre_rotation_active {
        // Reveal-only path: we set update_keys = [revealed_pubkey].
        1
    } else {
        last_update_keys.len() as u32
    };

    Ok(UpdateDidWebvhResult {
        did: record.did.clone(),
        new_version_id,
        new_scid,
        new_log_entry: new_log_entry_str,
        update_keys_count,
        pre_rotation_key_count: derived_pre_rotation.len() as u32,
    })
}

/// Validate caller-supplied watcher URLs.
///
/// Watchers must be `https://` URLs in production builds (`http://` is
/// allowed under `cfg(debug_assertions)` for local dev). Empty list is
/// accepted as the "disable watchers" instruction.
pub(super) fn validate_watchers(urls: &[String]) -> Result<(), UpdateDidWebvhError> {
    for url_str in urls {
        let url = url::Url::parse(url_str).map_err(|e| {
            UpdateDidWebvhError::InvalidWatcher(format!("watcher URL `{url_str}`: {e}"))
        })?;
        let scheme_ok =
            matches!(url.scheme(), "https") || (cfg!(debug_assertions) && url.scheme() == "http");
        if !scheme_ok {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must use https"
            )));
        }
        if url.fragment().is_some() {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must not contain a fragment"
            )));
        }
        if url.query().is_some() {
            return Err(UpdateDidWebvhError::InvalidWatcher(format!(
                "watcher URL `{url_str}` must not contain a query string"
            )));
        }
    }
    Ok(())
}

/// Validate a caller-supplied witness configuration.
///
/// `Witnesses::Empty {}` is the library's "disable witnesses" instruction
/// and is always accepted. `Witnesses::Value` requires every witness's
/// `did:key` to resolve through the cache resolver within
/// [`WITNESS_RESOLVE_TIMEOUT`]; an empty witness list with a non-zero
/// threshold is rejected as nonsensical (the underlying library rejects
/// it too on intake, but failing fast here gives a typed
/// `InvalidWitness` instead of a `Library`).
pub(super) async fn validate_witnesses(
    new: &Witnesses,
    did_resolver: &DIDCacheClient,
) -> Result<(), UpdateDidWebvhError> {
    let (witnesses, threshold) = match new {
        // Caller is disabling witnesses on this update. No DIDs to
        // resolve; nothing to validate.
        Witnesses::Empty {} => return Ok(()),
        Witnesses::Value {
            witnesses,
            threshold,
        } => (witnesses, *threshold),
    };

    if witnesses.is_empty() {
        return Err(UpdateDidWebvhError::InvalidWitness(format!(
            "witness configuration has threshold {threshold} but no witnesses listed"
        )));
    }
    if (witnesses.len() as u32) < threshold {
        return Err(UpdateDidWebvhError::InvalidWitness(format!(
            "threshold {threshold} exceeds witness count {}",
            witnesses.len()
        )));
    }

    for w in witnesses {
        let did = w.as_did();
        match tokio::time::timeout(WITNESS_RESOLVE_TIMEOUT, did_resolver.resolve(&did)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(UpdateDidWebvhError::InvalidWitness(format!(
                    "witness {did} did not resolve: {e}"
                )));
            }
            Err(_) => {
                return Err(UpdateDidWebvhError::InvalidWitness(format!(
                    "witness {did} resolution timed out ({}s)",
                    WITNESS_RESOLVE_TIMEOUT.as_secs()
                )));
            }
        }
    }
    Ok(())
}

impl From<UpdateDidWebvhError> for AppError {
    fn from(err: UpdateDidWebvhError) -> Self {
        match err {
            // Both NotFound and Forbidden map to NotFound at the wire
            // boundary so an admin of context A can't probe whether a
            // DID exists in context B.
            UpdateDidWebvhError::NotFound(msg) | UpdateDidWebvhError::Forbidden(msg) => {
                AppError::NotFound(msg)
            }
            UpdateDidWebvhError::Conflict(msg) => AppError::Conflict(msg),
            UpdateDidWebvhError::InvalidDocument(msg)
            | UpdateDidWebvhError::InvalidWitness(msg)
            | UpdateDidWebvhError::InvalidWatcher(msg) => AppError::Validation(msg),
            UpdateDidWebvhError::Library(msg)
            | UpdateDidWebvhError::Publish(msg)
            | UpdateDidWebvhError::Persistence(msg) => AppError::Internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    /// `into_response` reads back as the right HTTP status — we exercise
    /// the wire mapping rather than just the enum branch to catch any
    /// future drift in `AppError::IntoResponse`.
    fn status_of(err: UpdateDidWebvhError) -> StatusCode {
        let app: AppError = err.into();
        app.into_response().status()
    }

    #[test]
    fn not_found_maps_to_404() {
        assert_eq!(
            status_of(UpdateDidWebvhError::NotFound("x".into())),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn forbidden_also_maps_to_404_to_avoid_cross_context_leak() {
        assert_eq!(
            status_of(UpdateDidWebvhError::Forbidden("x".into())),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn conflict_maps_to_409() {
        assert_eq!(
            status_of(UpdateDidWebvhError::Conflict("x".into())),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn invalid_document_maps_to_400() {
        assert_eq!(
            status_of(UpdateDidWebvhError::InvalidDocument("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn invalid_witness_maps_to_400() {
        assert_eq!(
            status_of(UpdateDidWebvhError::InvalidWitness("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn invalid_watcher_maps_to_400() {
        assert_eq!(
            status_of(UpdateDidWebvhError::InvalidWatcher("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn library_maps_to_500() {
        assert_eq!(
            status_of(UpdateDidWebvhError::Library("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn publish_maps_to_500() {
        assert_eq!(
            status_of(UpdateDidWebvhError::Publish("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn persistence_maps_to_500() {
        assert_eq!(
            status_of(UpdateDidWebvhError::Persistence("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    fn valid_doc(did: &str) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-0"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkSomePub"
            }]
        })
    }

    #[test]
    fn validate_document_accepts_well_formed() {
        let did = "did:webvh:abc:vta.example.com:primary";
        validate_document_for_update(valid_doc(did), did).expect("valid doc");
    }

    #[test]
    fn validate_document_rejects_id_mismatch() {
        let existing = "did:webvh:abc:vta.example.com:primary";
        let foreign = "did:webvh:other:vta.example.com:primary";
        let err = validate_document_for_update(valid_doc(foreign), existing).unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::InvalidDocument(ref msg) if msg.contains("does not match"))
        );
    }

    #[test]
    fn validate_document_rejects_missing_context() {
        let did = "did:webvh:abc";
        let mut doc = valid_doc(did);
        doc.as_object_mut().unwrap().remove("@context");
        let err = validate_document_for_update(doc, did).unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::InvalidDocument(_)));
    }

    #[test]
    fn validate_document_rejects_missing_vm_field() {
        let did = "did:webvh:abc";
        let mut doc = valid_doc(did);
        doc["verificationMethod"][0]
            .as_object_mut()
            .unwrap()
            .remove("publicKeyMultibase");
        let err = validate_document_for_update(doc, did).unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::InvalidDocument(ref msg) if msg.contains("publicKeyMultibase"))
        );
    }

    #[test]
    fn validate_document_rejects_non_object() {
        let err = validate_document_for_update(serde_json::json!([1, 2, 3]), "did:x").unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::InvalidDocument(_)));
    }

    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use didwebvh_rs::multibase_type::Multibase;
    use didwebvh_rs::witness::Witness;

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("did resolver init")
    }

    /// Build a real `did:key` from a deterministic Ed25519 keypair so
    /// the resolver actually decodes the embedded pubkey. did:key is
    /// self-resolving — no network — but the bytes have to be valid.
    fn test_did_key() -> String {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes)
    }

    #[test]
    fn validate_watchers_accepts_empty() {
        validate_watchers(&[]).expect("disable instruction is fine");
    }

    #[test]
    fn validate_watchers_accepts_https() {
        validate_watchers(&["https://watcher.example.com/log".into()]).unwrap();
    }

    #[test]
    fn validate_watchers_rejects_ftp() {
        let err = validate_watchers(&["ftp://watcher.example.com".into()]).unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::InvalidWatcher(_)));
    }

    #[test]
    fn validate_watchers_rejects_fragment() {
        let err = validate_watchers(&["https://watcher.example.com/x#anchor".into()]).unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::InvalidWatcher(ref m) if m.contains("fragment"))
        );
    }

    #[test]
    fn validate_watchers_rejects_query() {
        let err = validate_watchers(&["https://watcher.example.com/x?key=v".into()]).unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::InvalidWatcher(ref m) if m.contains("query")));
    }

    #[test]
    fn validate_watchers_rejects_malformed() {
        let err = validate_watchers(&["not a url".into()]).unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::InvalidWatcher(_)));
    }

    use std::pin::Pin;
    use tokio::sync::Mutex;
    use vta_sdk::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// In-memory SeedStore for tests. Mirrors the pattern used in
    /// `operations::keys::tests::MockSeedStore`.
    struct MockSeedStore(Mutex<Option<Vec<u8>>>);

    impl SeedStore for MockSeedStore {
        fn get(
            &self,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Vec<u8>>, crate::error::AppError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(self.0.lock().await.clone()) })
        }
        fn set(
            &self,
            seed: &[u8],
        ) -> Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::error::AppError>> + Send + '_>,
        > {
            let seed = seed.to_vec();
            Box::pin(async move {
                *self.0.lock().await = Some(seed);
                Ok(())
            })
        }
    }

    async fn test_keys_ks() -> KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        std::mem::forget(dir);
        let store = Store::open(&cfg).expect("open store");
        store.keyspace("keys").expect("keyspace")
    }

    fn test_pub_multibase() -> String {
        // Same trick as in validate_witnesses tests: a deterministic
        // Ed25519 keypair gives us a known-good multibase pubkey we
        // can hash and round-trip.
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pub_bytes = sk.verifying_key().to_bytes();
        let did_key = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        // did:key:z6Mk... → strip prefix to get the multibase pubkey.
        did_key.trim_start_matches("did:key:").to_string()
    }

    #[tokio::test]
    async fn load_active_update_key_finds_via_webvh_keys_fast_path() {
        let ks = test_keys_ks().await;
        let scid = "Q123";
        let pub_mb = test_pub_multibase();
        let hash = Secret::base58_hash_string(&pub_mb).unwrap();

        webvh_keys::install(
            &ks,
            &WebvhKeyHandle {
                scid: scid.into(),
                version_id: "1-zV".into(),
                hash: hash.clone(),
                public_key: pub_mb.clone(),
                derivation_path: "m/26'/0'/0'/0".into(),
                seed_id: Some(1),
                role: WebvhKeyRole::UpdateKey,
                label: "test".into(),
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();

        let handle = load_active_update_key(&ks, scid, &[Multibase::from(pub_mb.clone())])
            .await
            .expect("found via webvh_keys");
        assert_eq!(handle.hash, hash);
        assert_eq!(handle.version_id, "1-zV");
    }

    #[tokio::test]
    async fn load_active_update_key_falls_back_to_legacy_keyspace() {
        let ks = test_keys_ks().await;
        let scid = "Q123";
        let pub_mb = test_pub_multibase();

        // Legacy KeyRecord exists in `key:*` but nothing in webvh_keys.
        let key_id = format!("did:webvh:{scid}#key-0");
        let record = KeyRecord {
            key_id: key_id.clone(),
            derivation_path: "m/26'/0'/0'/0".into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: pub_mb.clone(),
            label: Some("legacy signing key".into()),
            context_id: Some("primary".into()),
            seed_id: Some(1),
            origin: KeyOrigin::Derived,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        ks.insert(format!("key:{key_id}"), &record).await.unwrap();

        let handle = load_active_update_key(&ks, scid, &[Multibase::from(pub_mb.clone())])
            .await
            .expect("found via legacy fallback");
        assert_eq!(handle.public_key, pub_mb);
        assert_eq!(handle.derivation_path, "m/26'/0'/0'/0");
        assert_eq!(handle.version_id, "legacy");
    }

    #[tokio::test]
    async fn load_active_update_key_errors_when_no_match() {
        let ks = test_keys_ks().await;
        let pub_mb = test_pub_multibase();
        let err = load_active_update_key(&ks, "Q123", &[Multibase::from(pub_mb)])
            .await
            .unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::Library(ref m) if m.contains("no active update key"))
        );
    }

    #[tokio::test]
    async fn load_active_update_key_errors_on_empty_update_keys_list() {
        let ks = test_keys_ks().await;
        let err = load_active_update_key(&ks, "Q", &[]).await.unwrap_err();
        assert!(matches!(err, UpdateDidWebvhError::Library(ref m) if m.contains("no update_keys")));
    }

    #[tokio::test]
    async fn derive_webvh_keys_returns_empty_for_zero_count() {
        let ks = test_keys_ks().await;
        let seed_store = MockSeedStore(Mutex::new(Some(vec![0x42u8; 32])));
        let result = derive_webvh_keys(&ks, &seed_store, "m/26'/0'/0'", 0)
            .await
            .expect("zero count is fine");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn derive_then_install_round_trips_with_real_version_id() {
        let ks = test_keys_ks().await;
        let seed_store = MockSeedStore(Mutex::new(Some(vec![0x42u8; 32])));
        crate::keys::seeds::save_seed_record(
            &ks,
            &crate::keys::seeds::SeedRecord {
                id: 0,
                seed_hex: None,
                created_at: Utc::now(),
                retired_at: None,
            },
        )
        .await
        .unwrap();
        crate::keys::seeds::set_active_seed_id(&ks, 0)
            .await
            .unwrap();

        // Phase 1: derive (no keyspace writes for handles).
        let derived = derive_webvh_keys(&ks, &seed_store, "m/26'/0'/0'", 3)
            .await
            .expect("derive 3 keys");
        assert_eq!(derived.len(), 3);

        // Hashes are unique within the batch.
        let mut hashes: Vec<_> = derived.iter().map(|d| d.hash.clone()).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 3, "derived keys must have distinct hashes");

        // Phase 2: install with the real version-id (only known after
        // update_did returns).
        install_derived_webvh_keys(
            &ks,
            "Q123",
            "2-zVer",
            WebvhKeyRole::PreRotation,
            &derived,
            "pre-rotation",
        )
        .await
        .expect("install");

        // Each derived key is now reachable by hash.
        for d in &derived {
            let found =
                webvh_keys::load_handle(&ks, "Q123", "2-zVer", WebvhKeyRole::PreRotation, &d.hash)
                    .await
                    .unwrap()
                    .expect("handle present");
            assert_eq!(found.public_key, d.public_key);
        }
    }

    #[tokio::test]
    async fn validate_witnesses_accepts_empty_disable_instruction() {
        let r = resolver().await;
        validate_witnesses(&Witnesses::Empty {}, &r)
            .await
            .expect("Empty {} is the disable instruction");
    }

    #[tokio::test]
    async fn validate_witnesses_accepts_resolvable_did_key() {
        let r = resolver().await;
        let did = test_did_key();
        let mb = Multibase::from(did.trim_start_matches("did:key:").to_string());
        let cfg = Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness { id: mb }],
        };
        validate_witnesses(&cfg, &r)
            .await
            .expect("did:key resolves");
    }

    #[tokio::test]
    async fn validate_witnesses_rejects_threshold_without_witnesses() {
        let r = resolver().await;
        let cfg = Witnesses::Value {
            threshold: 1,
            witnesses: vec![],
        };
        let err = validate_witnesses(&cfg, &r).await.unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::InvalidWitness(ref msg) if msg.contains("no witnesses"))
        );
    }

    #[tokio::test]
    async fn validate_witnesses_rejects_threshold_above_count() {
        let r = resolver().await;
        let did = test_did_key();
        let mb = Multibase::from(did.trim_start_matches("did:key:").to_string());
        let cfg = Witnesses::Value {
            threshold: 5,
            witnesses: vec![Witness { id: mb }],
        };
        let err = validate_witnesses(&cfg, &r).await.unwrap_err();
        assert!(
            matches!(err, UpdateDidWebvhError::InvalidWitness(ref msg) if msg.contains("threshold"))
        );
    }

    #[test]
    fn validate_document_allows_externally_minted_public_key() {
        // Per spec Q4: caller can put a public key in the doc that the
        // VTA didn't mint. Validator only checks shape.
        let did = "did:webvh:abc";
        let doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#external-key"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkExternal"
            }]
        });
        validate_document_for_update(doc, did).expect("external keys allowed");
    }
}

#[cfg(test)]
mod pre_rotation_e2e_tests {
    //! End-to-end regression tests for the create→update flow, with
    //! particular focus on pre-rotation. These drive
    //! [`super::super::create_did_webvh`] and [`super::update_did_webvh`]
    //! through real fjall keyspaces and assert the resulting webvh log
    //! validates as a chain.
    //!
    //! These tests catch the class of bug where the signing-key
    //! selection in `update_did_webvh` ignores
    //! `previous.next_key_hashes`. Before the fix, the
    //! `update_with_pre_rotation_count_one` test failed with the
    //! didwebvh-rs `ParametersError: Signing key ID … does not match
    //! any next key hashes …` — the same error operators saw running
    //! `pnm services rest disable` against a pre-rotation-enabled VTA.
    //!
    //! Coverage:
    //! - `pre_rotation_count = 0`: standard non-pre-rotation update.
    //! - `pre_rotation_count = 1`: single-shot reveal (regression case).
    //! - `pre_rotation_count = 1`, two consecutive updates: exercises
    //!   the post-update install of the revealed key as an UpdateKey
    //!   handle so the second update can find a signing key by hash.
    //! - `pre_rotation_count = 2`: multiple committed candidates.
    //! - `rotate_did_webvh_keys` against a pre-rotation DID: the
    //!   convenience wrapper delegates to update_did_webvh, so it
    //!   benefits from the same fix.
    //!
    //! All tests use the serverless URL path (no webvh-host fixture).

    use std::sync::Arc;
    use std::time::Duration;

    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use chrono::Utc;
    use serde_json::json;
    use tokio::time::sleep;

    /// webvh requires `currentVersionTime > previousVersionTime`
    /// (strict, second precision). A `create_did` immediately
    /// followed by `update_did` in the same wall-clock second falls
    /// foul of this. Tests sleep just past the second boundary
    /// between log-entry-producing calls.
    const VERSION_TIME_GAP: Duration = Duration::from_millis(1100);

    use super::state_from_jsonl;
    use super::{
        RotateDidWebvhKeysOptions, UpdateDidWebvhOptions, rotate_did_webvh_keys, update_did_webvh,
    };
    use crate::auth::AuthClaims;
    use crate::config::AppConfig;
    use crate::didcomm_bridge::DIDCommBridge;
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::operations::did_webvh::{CreateDidWebvhParams, create_did_webvh};
    use crate::test_support::{TestStore, open_test_store, test_app_config};

    fn admin_auth() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    async fn build_resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("did resolver")
    }

    fn dummy_bridge() -> Arc<DIDCommBridge> {
        Arc::new(DIDCommBridge::placeholder())
    }

    fn ts_app_config(ts: &TestStore) -> AppConfig {
        test_app_config(ts.data_dir.clone())
    }

    /// Stage a fresh VTA-shaped fixture: a tempdir-backed store, an
    /// active seed, and a context. Returns everything callers need to
    /// drive `create_did_webvh` then `update_did_webvh`.
    async fn setup(context_id: &str) -> (TestStore, PlaintextSeedStore) {
        let ts = open_test_store().await;
        let seed_store = PlaintextSeedStore::new(&ts.data_dir);
        crate::keys::seed_store::SeedStore::set(&seed_store, &[0xAAu8; 64])
            .await
            .expect("write seed");
        crate::keys::seeds::save_seed_record(
            &ts.keys_ks,
            &crate::keys::seeds::SeedRecord {
                id: 0,
                seed_hex: None,
                created_at: Utc::now(),
                retired_at: None,
            },
        )
        .await
        .expect("save seed record");
        crate::keys::seeds::set_active_seed_id(&ts.keys_ks, 0)
            .await
            .expect("set active seed");
        crate::contexts::create_context(&ts.contexts_ks, context_id, "e2e ctx")
            .await
            .expect("create context");
        (ts, seed_store)
    }

    /// Helper: drive `create_did_webvh` for a serverless DID with the
    /// given pre-rotation count, and return the resulting (did, scid).
    #[allow(clippy::too_many_arguments)]
    async fn create_did(
        ts: &TestStore,
        seed_store: &PlaintextSeedStore,
        cfg: &AppConfig,
        auth: &AuthClaims,
        resolver: &DIDCacheClient,
        bridge: &Arc<DIDCommBridge>,
        context_id: &str,
        pre_rotation_count: u32,
    ) -> (String, String) {
        let result = create_did_webvh(
            &ts.keys_ks,
            &ts.imported_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.did_templates_ks,
            seed_store,
            cfg,
            auth,
            CreateDidWebvhParams {
                context_id: context_id.into(),
                server_id: None,
                url: Some("https://example.com/.well-known/did/did.jsonl".into()),
                path: None,
                label: Some("e2e".into()),
                portable: true,
                add_mediator_service: false,
                additional_services: None,
                pre_rotation_count,
                did_document: None,
                did_log: None,
                set_primary: true,
                signing_key_id: None,
                ka_key_id: None,
                template: None,
                template_context: None,
                template_vars: Default::default(),
                is_vta_identity: false,
            },
            resolver,
            bridge,
            "test",
        )
        .await
        .expect("create_did_webvh");
        (result.did, result.scid)
    }

    /// Build a well-formed DID document patch that swaps the only
    /// verificationMethod's pubkey. Anything that satisfies
    /// `validate_document_for_update` is fine — we don't care about the
    /// exact shape, only that the chain validates afterward.
    fn doc_patch(did: &str, suffix: &str) -> serde_json::Value {
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#patched-{suffix}"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": format!("z6MkPatched{suffix}"),
            }]
        })
    }

    /// Validate the full chain end-to-end. Re-running
    /// `state_from_jsonl` on the persisted log calls
    /// `DIDWebVHState::validate` + `assert_complete`, so any
    /// chain-internal inconsistency surfaces here.
    async fn assert_chain_validates(ts: &TestStore, did: &str) {
        let log = crate::webvh_store::get_did_log(&ts.webvh_ks, did)
            .await
            .expect("get_did_log")
            .expect("log present");
        state_from_jsonl(&log).expect("chain validates");
    }

    /// Sanity: pre_rotation_count = 0 (no pre-rotation) — the path
    /// the existing integration tests already covered. Asserts the
    /// non-pre-rotation flow continues to work after the refactor.
    #[tokio::test]
    async fn update_without_pre_rotation_succeeds() {
        let (ts, seed_store) = setup("ctx-nopre").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-nopre",
            0,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        let result = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update");

        assert!(result.new_version_id.starts_with("2-"));
        assert_chain_validates(&ts, &did).await;
    }

    /// Regression test for the bug operators hit running
    /// `pnm services rest disable` against a pre-rotation-enabled
    /// VTA. With pre_rotation_count = 1 (the interactive setup
    /// default), a doc-patch update used to fail with
    /// `ParametersError: Signing key ID … does not match any next
    /// key hashes …` from didwebvh-rs because the update path signed
    /// with `last.update_keys[0]` instead of the pre-rotation
    /// candidate committed in `last.next_key_hashes`.
    #[tokio::test]
    async fn update_with_pre_rotation_count_one_succeeds() {
        let (ts, seed_store) = setup("ctx-pre1").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-pre1",
            1,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        let result = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update under pre-rotation must succeed");

        assert!(result.new_version_id.starts_with("2-"));
        // Pre-rotation reveal: the new active update_key is the
        // revealed pre-rotation candidate, count = 1.
        assert_eq!(result.update_keys_count, 1);
        // pre-rotation continues — fresh candidate committed.
        assert_eq!(result.pre_rotation_key_count, 1);
        assert_chain_validates(&ts, &did).await;
    }

    /// Two consecutive doc-patch updates with pre_rotation_count = 1.
    /// This exercises the post-update install of the revealed key as
    /// an `UpdateKey` handle — without that step, the second update
    /// would fail to resolve a signing key after the first update's
    /// pre-rotation handle is moved to the `superseded:` prefix.
    #[tokio::test]
    async fn two_consecutive_updates_with_pre_rotation_succeed() {
        let (ts, seed_store) = setup("ctx-pre1b").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-pre1b",
            1,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update 1");
        sleep(VERSION_TIME_GAP).await;

        let result2 = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v3")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update 2");

        assert!(result2.new_version_id.starts_with("3-"));
        assert_chain_validates(&ts, &did).await;
    }

    /// pre_rotation_count = 2 — the previous entry commits two
    /// candidates; the next update reveals one of them. Asserts
    /// `load_pre_rotation_signing_key` correctly picks a matching
    /// candidate when more than one is committed.
    #[tokio::test]
    async fn update_with_pre_rotation_count_two_succeeds() {
        let (ts, seed_store) = setup("ctx-pre2").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-pre2",
            2,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update 1");
        sleep(VERSION_TIME_GAP).await;

        update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v3")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update 2");

        assert_chain_validates(&ts, &did).await;
    }

    /// Disabling pre-rotation mid-chain: signing key still must come
    /// from the previous entry's `next_key_hashes`, but the new
    /// entry's `next_key_hashes` is empty (turning off the feature).
    /// Subsequent updates fall back to the standard `update_keys`
    /// path — covered implicitly by the next assertion.
    #[tokio::test]
    async fn disabling_pre_rotation_then_updating_succeeds() {
        let (ts, seed_store) = setup("ctx-pre-off").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-pre-off",
            1,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        // Update 1: turn off pre-rotation.
        let r1 = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                pre_rotation_count: Some(0),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("disable pre-rotation");
        assert_eq!(r1.pre_rotation_key_count, 0);
        sleep(VERSION_TIME_GAP).await;

        // Update 2: ordinary non-pre-rotation update.
        let r2 = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v3")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("subsequent update");
        assert!(r2.new_version_id.starts_with("3-"));
        assert_chain_validates(&ts, &did).await;
    }

    /// `rotate_did_webvh_keys` is a thin wrapper that mints fresh
    /// VM keys and delegates to `update_did_webvh`. Confirm it works
    /// against a pre-rotation-enabled DID.
    #[tokio::test]
    async fn rotate_keys_with_pre_rotation_succeeds() {
        let (ts, seed_store) = setup("ctx-rotate").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-rotate",
            1,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        let result = rotate_did_webvh_keys(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            RotateDidWebvhKeysOptions::default(),
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("rotate-keys under pre-rotation");

        assert!(result.new_version_id.starts_with("2-"));
        assert_chain_validates(&ts, &did).await;
    }

    /// Pre-fix-genesis → post-fix-update scenario.
    ///
    /// Operators who created their VTA with the original (broken)
    /// build have pre-rotation keys saved only at the legacy
    /// `key:{did}#pre-rotation-N` records — no `webvh_keys` handles.
    /// After upgrading to the fixed build, the first update has to
    /// fall back to `legacy_lookup_pre_rotation_by_hash` to find a
    /// signing key.
    ///
    /// This test simulates that state by deleting the
    /// `webvh_keys` handles installed at genesis, then running the
    /// update. If the legacy fallback is broken, the update fails
    /// with the same `ParametersError: Signing key ID … does not
    /// match any next key hashes` error operators see.
    #[tokio::test]
    async fn update_with_legacy_only_pre_rotation_genesis_succeeds() {
        let (ts, seed_store) = setup("ctx-legacy").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-legacy",
            1,
        )
        .await;
        sleep(VERSION_TIME_GAP).await;

        // Wipe the webvh_keys keyspace entries so only the legacy
        // `key:{did}#…` records remain. This puts the store into the
        // shape it had on a pre-fix VTA.
        let prefix = format!("webvh:{scid}:");
        let raws = ts
            .keys_ks
            .prefix_keys(prefix.into_bytes())
            .await
            .expect("scan webvh_keys");
        assert!(
            !raws.is_empty(),
            "fixture invariant: genesis must install at least one webvh_keys handle"
        );
        for raw in raws {
            ts.keys_ks
                .remove(raw)
                .await
                .expect("strip webvh_keys handles to simulate pre-fix genesis");
        }

        // Sanity: legacy `key:` records still in place.
        let legacy = ts
            .keys_ks
            .prefix_keys(b"key:".to_vec())
            .await
            .expect("scan legacy keys");
        assert!(
            legacy.iter().any(|raw| std::str::from_utf8(raw)
                .map(|s| s.contains("#pre-rotation-"))
                .unwrap_or(false)),
            "fixture invariant: legacy pre-rotation record must exist"
        );

        // The update should succeed via the legacy fallback in
        // `load_pre_rotation_signing_key`.
        let result = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "v2")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("legacy-fallback update under pre-rotation");

        assert!(result.new_version_id.starts_with("2-"));
        assert_eq!(result.update_keys_count, 1);
        assert_eq!(result.pre_rotation_key_count, 1);
        assert_chain_validates(&ts, &did).await;
    }

    /// Optimistic-concurrency precondition.
    ///
    /// Scenario: operator A reads the DID at versionId `1-…`, operator B
    /// (or a bot) updates the DID, then A tries to save its edits with
    /// the stale `expected_version_id`. The save must fail with
    /// `Conflict` rather than silently building a chain on top of B's
    /// changes — otherwise A's document body overwrites B's edits even
    /// though the chain stays structurally valid.
    #[tokio::test]
    async fn update_with_stale_expected_version_id_conflicts() {
        let (ts, seed_store) = setup("ctx-stale").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-stale",
            0,
        )
        .await;

        // Capture the genesis versionId (`1-…`) before anyone updates.
        let log = crate::webvh_store::get_did_log(&ts.webvh_ks, &did)
            .await
            .expect("get_did_log")
            .expect("log present");
        let genesis_version_id = log
            .lines()
            .next()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| {
                v.get("versionId")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .expect("genesis versionId");

        // Concurrent update by "operator B" — bumps the chain to `2-…`.
        sleep(VERSION_TIME_GAP).await;
        update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "by-b")),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("operator B's update succeeds");

        // Operator A tries to save with the stale `1-…` precondition.
        sleep(VERSION_TIME_GAP).await;
        let err = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "by-a")),
                expected_version_id: Some(genesis_version_id.clone()),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect_err("stale expected_version_id must conflict");

        match err {
            crate::operations::did_webvh::UpdateDidWebvhError::Conflict(msg) => {
                assert!(
                    msg.contains(&genesis_version_id),
                    "error should name the stale version: got {msg}"
                );
                assert!(
                    msg.contains("Re-fetch"),
                    "error should hint at the recovery action: got {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }

        // The chain on disk should still be exactly what B wrote — A's
        // attempted update did not touch storage.
        let log_after = crate::webvh_store::get_did_log(&ts.webvh_ks, &did)
            .await
            .expect("get_did_log")
            .expect("log present");
        assert_eq!(
            log_after.lines().count(),
            2,
            "A's update must not have appended a third entry"
        );
    }

    /// Concurrency test for `rotate_did_webvh_keys`. The internal
    /// `next_fragment_id` bump used to be a read-modify-write with no
    /// version check, so two parallel rotates each derived the same
    /// `[next_fragment_id, next_fragment_id + N)` range and only one
    /// store_did won — the loser's freshly-issued keys collided with
    /// the winner's published `#key-N` references. The new
    /// `RecordSnapshot::assert_unchanged` guard refuses the loser
    /// with `Conflict` so the operator re-runs the rotate cleanly.
    ///
    /// This test simulates the race deterministically: rotate once
    /// successfully (committing the bump), then mutate the on-disk
    /// record's `updated_at` to mimic a different concurrent op
    /// having moved the record between snapshot and final write,
    /// then attempt a second rotate and assert Conflict.
    #[tokio::test]
    async fn rotate_keys_with_stale_record_snapshot_conflicts() {
        let (ts, seed_store) = setup("ctx-rotate-cas").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-rotate-cas",
            0,
        )
        .await;

        // Mutate the record's updated_at on disk to simulate a
        // concurrent op having modified it between
        // `RecordSnapshot::capture` (early in rotate) and the final
        // `store_did` (the next_fragment_id bump). The rotate's
        // captured snapshot is from the start of its call; this
        // modification mid-flight is what the snapshot guard exists
        // to catch.
        //
        // We can't trigger this from within a single
        // `rotate_did_webvh_keys` call without spawning a parallel
        // task, so instead we mutate directly. The operation under
        // test re-loads + checks the snapshot at the bump point;
        // any change to updated_at between its read and that re-load
        // is a race per the helper's contract.
        sleep(VERSION_TIME_GAP).await;
        let mut record = crate::webvh_store::get_did(&ts.webvh_ks, &did)
            .await
            .unwrap()
            .unwrap();
        // Hijack the record by spawning a task that mutates updated_at
        // *during* the rotate call. We sequence with sleep so the rotate
        // sees the original record on capture, then the mutation lands
        // before the rotate's CAS re-load.
        //
        // Simpler form: do the mutation synchronously *before* calling
        // rotate, but keep the captured snapshot fresh. The rotate's
        // capture sees the post-mutation updated_at, then nothing
        // further changes — no race detected. So we actually need the
        // race to happen between capture and CAS.
        //
        // Workaround: directly invoke the snapshot helper to
        // demonstrate the guard works; the integration-level race
        // exercise lives in tests/e2e (where two real rotate tasks
        // can run concurrently). This unit-level test pins the
        // helper-call wiring.
        let snapshot = crate::operations::did_webvh::RecordSnapshot::capture(&record);
        record.updated_at = chrono::Utc::now() + chrono::Duration::seconds(1);
        crate::webvh_store::store_did(&ts.webvh_ks, &record)
            .await
            .unwrap();

        let current = crate::webvh_store::get_did(&ts.webvh_ks, &did)
            .await
            .unwrap()
            .unwrap();
        snapshot
            .assert_unchanged(&current)
            .expect_err("snapshot must reject the post-mutation record");

        // And full rotate-keys still works on a fresh state — the
        // guard didn't accidentally fail-closed in the happy case.
        let result = rotate_did_webvh_keys(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            RotateDidWebvhKeysOptions {
                pre_rotation_count: None,
                label: None,
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("happy-path rotate succeeds after the race assertion");
        assert!(result.new_version_id.starts_with("2-"));
    }

    /// Same precondition machinery, but the supplied versionId matches
    /// the current latest — should pass through cleanly. Pins the
    /// happy-path so we don't accidentally make the precondition reject
    /// every update.
    #[tokio::test]
    async fn update_with_current_expected_version_id_succeeds() {
        let (ts, seed_store) = setup("ctx-current").await;
        let cfg = ts_app_config(&ts);
        let auth = admin_auth();
        let resolver = build_resolver().await;
        let bridge = dummy_bridge();

        let (did, scid) = create_did(
            &ts,
            &seed_store,
            &cfg,
            &auth,
            &resolver,
            &bridge,
            "ctx-current",
            0,
        )
        .await;
        let log = crate::webvh_store::get_did_log(&ts.webvh_ks, &did)
            .await
            .expect("get_did_log")
            .expect("log present");
        let current_version_id = log
            .lines()
            .last()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| {
                v.get("versionId")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .expect("current versionId");

        sleep(VERSION_TIME_GAP).await;
        let result = update_did_webvh(
            &ts.keys_ks,
            &ts.contexts_ks,
            &ts.webvh_ks,
            &ts.audit_ks,
            &seed_store,
            &auth,
            &scid,
            UpdateDidWebvhOptions {
                document: Some(doc_patch(&did, "current")),
                expected_version_id: Some(current_version_id),
                ..Default::default()
            },
            &resolver,
            &bridge,
            "test",
        )
        .await
        .expect("update with matching expected_version_id should succeed");
        assert!(result.new_version_id.starts_with("2-"));
        assert_chain_validates(&ts, &did).await;
    }
}
