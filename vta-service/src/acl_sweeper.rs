//! Background pruning of expired ACL rows.
//!
//! Called from the storage thread's interval loop. Walks the ACL keyspace
//! once and deletes any rows whose `expires_at` has passed.

use tracing::{debug, info};

use crate::acl::{AclEntry, delete_acl_entry};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn sweep_expired(acl_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let now = now_epoch();
    let mut pruned = 0usize;

    let rows = acl_ks.prefix_iter_raw("acl:").await?;
    for (key, value) in rows {
        let entry: AclEntry = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    key = %String::from_utf8_lossy(&key),
                    error = %e,
                    "sweeper: skipping unreadable acl row",
                );
                continue;
            }
        };
        if entry.is_expired(now) {
            delete_acl_entry(acl_ks, &entry.did).await?;
            pruned += 1;
        }
    }

    if pruned > 0 {
        info!(acl_pruned = pruned, "acl sweeper pruned expired rows");
    }
    Ok(())
}
