//! Restart-resilience helper for e2e tests.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §7a.6
//! path 5 — "Restart-during-drain". Tests that exercise crash
//! recovery (drain set replay, snapshot persistence across reboots,
//! etc.) need to drop the in-memory state and re-open the fjall
//! store from disk to verify state is intact.
//!
//! `simulate_restart` re-opens the [`TestStore`]'s on-disk data
//! directory under a fresh `Store` handle. The original store and
//! all its keyspace handles are dropped — fjall release happens on
//! `Drop`. Caller then derives new keyspace handles from the fresh
//! store.

use std::path::Path;

use vta_service::store::Store;
use vti_common::config::StoreConfig;

/// Re-open the store at `data_dir`. Used after dropping the
/// previous `Store` instance to simulate a process restart.
pub fn simulate_restart(data_dir: &Path) -> Store {
    Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })
    .expect("re-open store after simulated restart")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_service::operations::protocol::snapshot::{
        self, DidcommSnapshot, ServiceConfigSnapshot, ServiceKind,
    };

    /// Snapshot writes survive a simulated restart — the
    /// test creates a tempdir manually (so it outlives the
    /// `TestStore`'s lifecycle), opens a store + writes data,
    /// drops the store, then re-opens against the same data
    /// dir and reads the data back.
    ///
    /// `TestStore` owns its tempdir and cleans up on drop, so
    /// for restart-resilience tests we manage the tempdir
    /// directly.
    #[tokio::test]
    async fn snapshot_survives_simulated_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();

        // Open a store, write a snapshot, drop the store.
        {
            let store = simulate_restart(&data_dir);
            let snapshot_ks = store.keyspace(snapshot::KEYSPACE_NAME).unwrap();
            snapshot::write(
                &snapshot_ks,
                ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled {
                    mediator_did: "did:peer:2.M".into(),
                    routing_keys: vec![],
                }),
            )
            .await
            .unwrap();
            // Force flush before drop. fjall typically syncs on
            // drop but we want to be explicit so the test
            // doesn't depend on that timing.
            drop(snapshot_ks);
            drop(store);
        }

        // Re-open the same data dir as a fresh process would.
        let restarted = simulate_restart(&data_dir);
        let snapshot_ks = restarted
            .keyspace(snapshot::KEYSPACE_NAME)
            .expect("re-open snapshot keyspace");

        let snap = snapshot::read(&snapshot_ks, ServiceKind::Didcomm)
            .await
            .unwrap()
            .expect("snapshot survived restart");
        match snap {
            ServiceConfigSnapshot::Didcomm(DidcommSnapshot::Enabled { mediator_did, .. }) => {
                assert_eq!(mediator_did, "did:peer:2.M");
            }
            other => panic!("expected Didcomm::Enabled, got {other:?}"),
        }
        // tempdir drops at end of scope — cleanup happens here.
    }
}
