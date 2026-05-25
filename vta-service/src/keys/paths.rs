use crate::error::AppError;
use crate::store::KeyspaceHandle;
use std::sync::LazyLock;
use tokio::sync::Mutex;
use tracing::debug;

/// Construct a full derivation path from a base and index.
pub fn path_at(base: &str, index: u32) -> String {
    format!("{base}/{index}'")
}

/// Serializes the read-increment-write of path counters across the
/// process. The fjall store has no atomic increment primitive, so two
/// concurrent `allocate_path` callers would otherwise observe the same
/// counter value and be handed identical BIP-32 derivation paths —
/// producing two `KeyRecord`s that share a private key. Allocation is
/// infrequent and the section is short, so a single global lock is
/// acceptable; per-base sharding would be a refinement only if this
/// becomes a hot path.
static ALLOC_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Allocate the next sequential derivation path from a group's counter.
///
/// Reads the current counter for `base` from the keys keyspace,
/// constructs `{base}/{N}'`, increments the counter, and returns the path.
pub async fn allocate_path(keys_ks: &KeyspaceHandle, base: &str) -> Result<String, AppError> {
    let _guard = ALLOC_LOCK.lock().await;
    let counter_key = format!("path_counter:{base}");
    let current: u32 = match keys_ks.get_raw(counter_key.as_str()).await? {
        Some(bytes) => {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| AppError::Internal("corrupt path counter".into()))?;
            u32::from_le_bytes(arr)
        }
        None => 0,
    };
    let path = path_at(base, current);
    keys_ks
        .insert_raw(counter_key, (current + 1).to_le_bytes().to_vec())
        .await?;
    debug!(base, path = %path, "derivation path allocated");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tempfile::TempDir;
    use vti_common::config::StoreConfig as VtiStoreConfig;

    /// Regression test for the BIP-32 derivation-path race: launching N
    /// concurrent `allocate_path` calls against the same base must
    /// produce N distinct paths. Without the serialization lock, this
    /// test fails reliably under release-mode contention because the
    /// non-atomic get → +1 → insert sequence hands the same counter to
    /// multiple awaiting tasks before any of them writes it back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn allocate_path_is_collision_free_under_concurrency() {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&VtiStoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let keys_ks = Arc::new(store.keyspace("keys").expect("keyspace"));

        let base = "m/26'/0'";
        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let ks = keys_ks.clone();
            handles.push(tokio::spawn(async move {
                allocate_path(&ks, base).await.expect("alloc")
            }));
        }

        let mut paths = HashSet::with_capacity(n);
        for h in handles {
            let p = h.await.expect("join");
            assert!(
                paths.insert(p.clone()),
                "duplicate derivation path {p} — allocate_path lost a race",
            );
        }
        assert_eq!(
            paths.len(),
            n,
            "expected {n} unique paths, got {}",
            paths.len()
        );
    }
}
