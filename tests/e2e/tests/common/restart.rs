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

    /// Spec §7a.6 path 5 — drain entries persisted to fjall survive
    /// a process restart and the [`DrainSweeper`] re-arms its
    /// in-memory timers from the on-disk set. Doesn't require a
    /// running mediator: the assertion is purely "set persisted →
    /// fresh sweeper sees the same entries → arms the right
    /// number of timers."
    #[tokio::test]
    async fn drain_set_survives_simulated_restart() {
        use chrono::{Duration, Utc};
        use std::sync::Arc;
        use vta_service::messaging::drain_store::{self, PersistedDrainEntry};
        use vta_service::messaging::drain_sweeper::{DrainSweeper, teardown_channel};
        use vta_service::messaging::registry::MediatorListenerRegistry;
        use vti_common::telemetry::RingBufferTelemetry;

        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let deadline = Utc::now() + Duration::hours(24);

        // Phase 1: open the store, write a drain entry, drop.
        {
            let store = simulate_restart(&data_dir);
            let drains_ks = store.keyspace("drains").unwrap();
            drain_store::store_drain(
                &drains_ks,
                &PersistedDrainEntry {
                    mediator_did: "did:peer:2.M-DRAINING".into(),
                    endpoint: "https://m.example".into(),
                    drains_until: deadline,
                },
            )
            .await
            .unwrap();
            drop(drains_ks);
            drop(store);
        }

        // Phase 2: re-open the store (simulating fresh process
        // boot), build a fresh registry + sweeper from the persisted
        // set, and assert it arms one timer.
        let restarted = simulate_restart(&data_dir);
        let drains_ks = restarted.keyspace("drains").unwrap();
        let persisted = drain_store::list_drains(&drains_ks).await.unwrap();
        assert_eq!(
            persisted.len(),
            1,
            "drain entry must survive restart; got {persisted:?}"
        );
        assert_eq!(persisted[0].mediator_did, "did:peer:2.M-DRAINING");

        let telemetry = Arc::new(RingBufferTelemetry::with_capacity(16));
        let registry =
            Arc::new(MediatorListenerRegistry::new(Arc::clone(&telemetry)
                as Arc<dyn vti_common::telemetry::TelemetrySink + Send + Sync>));
        let (tx, _rx) = teardown_channel(8);
        let sweeper = DrainSweeper::new(Arc::clone(&registry), drains_ks.clone(), tx);

        // Re-arm from persisted set the way the runtime does at
        // boot. We pass the registry's own DrainEntry shape;
        // build one from the persisted record.
        let entries: Vec<vta_service::messaging::registry::DrainEntry> = persisted
            .iter()
            .map(|p| vta_service::messaging::registry::DrainEntry {
                mediator_did: p.mediator_did.clone(),
                endpoint: p.endpoint.clone(),
                drains_until: p.drains_until,
                generation: 0,
            })
            .collect();
        sweeper.arm_all(&entries).await;
        assert_eq!(
            sweeper.armed_count().await,
            1,
            "sweeper must arm one timer per persisted drain entry"
        );
    }
}
