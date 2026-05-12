//! `MembershipSyncer` — Phase 3 M3.4.
//!
//! The async task that drives trust-registry reconciliation.
//! Spec §8.3.
//!
//! ## Tick loop
//!
//! Every `tick_interval` the task does, in order:
//!
//! 1. **Boot recovery** (first tick only) — walk
//!    `sync_queue:` and flip any `InFlight` rows back to
//!    `Pending`. The daemon may have crashed between
//!    "marked InFlight" and "wrote outcome"; we re-dispatch
//!    rather than wait for the client to time out a row that's
//!    already been delivered.
//!
//! 2. **Tail walk** — call [`super::tail::walk`] to enqueue
//!    fresh jobs from new audit envelopes. Advance the
//!    `sync_cursor` row.
//!
//! 3. **Dispatch** — for each `Pending` row where
//!    `now >= next_attempt_at`:
//!    - Flip to `InFlight`.
//!    - Call the appropriate `TrustRegistryClient` method.
//!    - On success: delete the row + emit
//!      `RegistrySyncSucceeded` + update the local
//!      `registry_records` mirror.
//!    - On retriable failure: `record_failure` (bumps
//!      attempts, reschedules per backoff). Row stays in
//!      the queue.
//!    - On permanent failure: flip immediately to `Failed` +
//!      emit `RegistrySyncFailed`.
//!    - After every dispatch, [`super::RegistryHealth`] is
//!      updated (success → Active, failure → Degraded).
//!
//! ## Failure isolation
//!
//! One job's failure can't cascade — every dispatch is its
//! own `Result<()>` boundary. A registry that's down keeps
//! producing `RegistryError::Unreachable`; the queue grows;
//! `RegistryHealth.status()` flips to Degraded; the
//! diagnostics endpoint surfaces queue depth + oldest pending.
//! No retry storms — backoff caps at 1h.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};
use vti_common::audit::{AuditEvent, AuditWriter, RegistrySyncOutcomeData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::client::{RegistryError, TrustRegistryClient};
use super::health::RegistryHealth;
use super::model::{RegistryRecord, SyncJob, SyncJobKind, SyncJobState};
use super::storage::{
    delete_sync_job, get_sync_cursor, list_sync_jobs, set_sync_cursor, store_record, store_sync_job,
};
use super::tail::walk;

/// Default tick interval. Mirrors the spec §8.3 ≥-1h-behind
/// threshold by being well under it.
pub const DEFAULT_TICK_INTERVAL_SECONDS: u64 = 5;

/// Owned handle to the syncer task. Spawn via [`Self::run`];
/// shutdown via the workspace's `watch::Receiver<bool>`
/// channel (same pattern the REST/DIDComm threads use).
pub struct MembershipSyncer {
    audit_ks: KeyspaceHandle,
    sync_queue_ks: KeyspaceHandle,
    sync_cursor_ks: KeyspaceHandle,
    registry_records_ks: KeyspaceHandle,
    client: Arc<dyn TrustRegistryClient>,
    health: RegistryHealth,
    audit_writer: Option<AuditWriter>,
    actor_did: String,
    tick_interval: Duration,
}

impl MembershipSyncer {
    /// Construct a fresh syncer. `actor_did` is the VTC's
    /// own DID — used as the `actor_did` on
    /// `RegistrySyncSucceeded` / `RegistrySyncFailed` audit
    /// envelopes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        audit_ks: KeyspaceHandle,
        sync_queue_ks: KeyspaceHandle,
        sync_cursor_ks: KeyspaceHandle,
        registry_records_ks: KeyspaceHandle,
        client: Arc<dyn TrustRegistryClient>,
        health: RegistryHealth,
        audit_writer: Option<AuditWriter>,
        actor_did: impl Into<String>,
    ) -> Self {
        Self {
            audit_ks,
            sync_queue_ks,
            sync_cursor_ks,
            registry_records_ks,
            client,
            health,
            audit_writer,
            actor_did: actor_did.into(),
            tick_interval: Duration::from_secs(DEFAULT_TICK_INTERVAL_SECONDS),
        }
    }

    /// Override the tick interval (default 5s). Lower in tests
    /// so async-driven assertions resolve quickly.
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Run the syncer's tick loop. Returns when `shutdown`
    /// flips to `true`. Spawn via `tokio::spawn` in the
    /// daemon's boot path.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            tick_interval_secs = self.tick_interval.as_secs(),
            "membership-syncer task starting"
        );
        // Boot recovery — flip any InFlight rows back to
        // Pending. The daemon may have died between "set
        // InFlight" and "record outcome"; we re-dispatch.
        if let Err(e) = self.recover_in_flight().await {
            warn!(error = %e, "in-flight recovery failed at syncer boot");
        }

        let mut timer = tokio::time::interval(self.tick_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately — skip so we don't
        // overlap the recovery scan above.
        timer.tick().await;
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    if let Err(e) = self.tick().await {
                        warn!(error = %e, "syncer tick failed");
                    }
                }
                _ = shutdown.changed() => {
                    debug!("membership-syncer task shutting down");
                    return;
                }
            }
        }
    }

    /// One tick: walk audit tail + dispatch every eligible
    /// pending job. Exposed for tests.
    pub async fn tick(&self) -> Result<(), AppError> {
        let cursor = get_sync_cursor(&self.sync_cursor_ks).await?;
        let outcome = walk(&self.audit_ks, &self.sync_queue_ks, cursor).await?;
        if let Some(new) = outcome.new_cursor
            && Some(new) != cursor
        {
            set_sync_cursor(&self.sync_cursor_ks, new).await?;
        }
        if outcome.jobs_enqueued > 0 {
            debug!(jobs = outcome.jobs_enqueued, "tail walk enqueued jobs");
        }

        let jobs = list_sync_jobs(&self.sync_queue_ks).await?;
        let now = chrono::Utc::now();
        for job in jobs.into_iter().filter(|j| j.is_dispatchable(now)) {
            self.dispatch_one(job).await;
        }
        Ok(())
    }

    /// Boot-time recovery: flip any `InFlight` rows back to
    /// `Pending`. Exposed for tests.
    pub async fn recover_in_flight(&self) -> Result<usize, AppError> {
        let jobs = list_sync_jobs(&self.sync_queue_ks).await?;
        let mut recovered = 0_usize;
        for mut job in jobs {
            if job.state == SyncJobState::InFlight {
                job.state = SyncJobState::Pending;
                store_sync_job(&self.sync_queue_ks, &job).await?;
                recovered += 1;
                debug!(
                    job_id = %job.id,
                    did = %job.member_did,
                    "recovered InFlight job → Pending after restart"
                );
            }
        }
        if recovered > 0 {
            info!(
                recovered,
                "membership-syncer recovered InFlight jobs at boot"
            );
        }
        Ok(recovered)
    }

    /// Dispatch one job. All failure paths land here so the
    /// caller stays simple; the `Result` is `()` because we
    /// never propagate — every error is captured on the job
    /// row + the audit envelope.
    async fn dispatch_one(&self, mut job: SyncJob) {
        // Flip to InFlight + persist before the network call
        // so a crash mid-flight leaves a row the recovery
        // path will see.
        job.state = SyncJobState::InFlight;
        if let Err(e) = store_sync_job(&self.sync_queue_ks, &job).await {
            warn!(error = %e, job_id = %job.id, "failed to persist InFlight transition");
            return;
        }

        let outcome = self.run_call(&job).await;
        match outcome {
            Ok(()) => {
                job.record_success();
                // Mirror update: PublishMember + UpdateMember
                // land as Active records; MarkDeparted lands
                // as Departed; DeleteMember removes the row.
                self.update_mirror(&job).await;
                self.health
                    .record_success(self.audit_writer.as_ref(), &self.actor_did)
                    .await;
                self.emit_outcome(&job, true);
                if let Err(e) = delete_sync_job(&self.sync_queue_ks, job.id).await {
                    warn!(error = %e, job_id = %job.id, "failed to delete completed job row");
                }
            }
            Err(e) => {
                if e.is_retriable() {
                    job.record_failure(format!("{e}"));
                    self.health
                        .record_failure(format!("{e}"), self.audit_writer.as_ref(), &self.actor_did)
                        .await;
                    if let Err(s) = store_sync_job(&self.sync_queue_ks, &job).await {
                        warn!(error = %s, job_id = %job.id, "failed to persist retry state");
                    }
                    if job.state == SyncJobState::Failed {
                        // record_failure flipped to Failed (hit
                        // max attempts).
                        self.emit_outcome(&job, false);
                    }
                } else {
                    // Permanent — flip to Failed immediately.
                    job.attempts += 1;
                    job.last_attempted_at = Some(chrono::Utc::now());
                    job.last_error = Some(format!("{e}"));
                    job.state = SyncJobState::Failed;
                    if let Err(s) = store_sync_job(&self.sync_queue_ks, &job).await {
                        warn!(error = %s, job_id = %job.id, "failed to persist Failed state");
                    }
                    self.emit_outcome(&job, false);
                    warn!(
                        job_id = %job.id,
                        did = %job.member_did,
                        kind = job.kind.as_str(),
                        error = %e,
                        "registry rejected sync job permanently — operator intervention required"
                    );
                }
            }
        }
    }

    async fn run_call(&self, job: &SyncJob) -> Result<(), RegistryError> {
        match job.kind {
            SyncJobKind::PublishMember | SyncJobKind::UpdateMember => {
                let record = RegistryRecord::fresh_active(&job.member_did);
                self.client.publish_member(&record).await
            }
            SyncJobKind::MarkDeparted => {
                let now = chrono::Utc::now();
                let active_to = if job.disposition.as_deref() == Some("historical") {
                    Some(now)
                } else {
                    None
                };
                let record = RegistryRecord::departed(&job.member_did, now, active_to);
                self.client.publish_member(&record).await
            }
            SyncJobKind::DeleteMember => self.client.delete_member(&job.member_did).await,
        }
    }

    async fn update_mirror(&self, job: &SyncJob) {
        match job.kind {
            SyncJobKind::PublishMember | SyncJobKind::UpdateMember => {
                let record = RegistryRecord::fresh_active(&job.member_did);
                if let Err(e) = store_record(&self.registry_records_ks, &record).await {
                    warn!(error = %e, did = %job.member_did, "failed to update registry_records mirror");
                }
            }
            SyncJobKind::MarkDeparted => {
                let now = chrono::Utc::now();
                let active_to = if job.disposition.as_deref() == Some("historical") {
                    Some(now)
                } else {
                    None
                };
                let record = RegistryRecord::departed(&job.member_did, now, active_to);
                if let Err(e) = store_record(&self.registry_records_ks, &record).await {
                    warn!(error = %e, did = %job.member_did, "failed to update registry_records mirror");
                }
            }
            SyncJobKind::DeleteMember => {
                if let Err(e) =
                    super::storage::delete_record(&self.registry_records_ks, &job.member_did).await
                {
                    warn!(error = %e, did = %job.member_did, "failed to delete registry_records mirror row");
                }
            }
        }
    }

    fn emit_outcome(&self, job: &SyncJob, succeeded: bool) {
        let Some(writer) = self.audit_writer.as_ref() else {
            return;
        };
        let payload = RegistrySyncOutcomeData {
            job_id: job.id.to_string(),
            kind: job.kind.as_str().to_string(),
            attempts: job.attempts,
            last_error: if succeeded {
                None
            } else {
                job.last_error.clone()
            },
        };
        let event = if succeeded {
            AuditEvent::RegistrySyncSucceeded(payload)
        } else {
            AuditEvent::RegistrySyncFailed(payload)
        };
        let actor_did = self.actor_did.clone();
        let target_did = job.member_did.clone();
        let writer = writer.clone();
        // Fire-and-forget — the audit emission failing
        // shouldn't surface back to the syncer's hot path,
        // and the audit writer's own logging covers the
        // failure mode.
        tokio::spawn(async move {
            if let Err(e) = writer.write(&actor_did, Some(&target_did), event).await {
                warn!(error = %e, "failed to emit RegistrySync outcome");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::client::MockRegistryClient;
    use crate::registry::model::{SyncJob, SyncJobKind};
    use crate::registry::storage::{get_record, store_sync_job};
    use vti_common::audit::{AuditEvent, AuditKeyStore, AuditWriter, MemberAddedData};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn fixture() -> (MembershipSyncer, MockRegistryClient, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let sync_queue_ks = store.keyspace("sync_queue").unwrap();
        let sync_cursor_ks = store.keyspace("sync_cursor").unwrap();
        let registry_records_ks = store.keyspace("registry_records").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        let audit_writer = AuditWriter::new(audit_ks.clone(), key_store);
        let mock = MockRegistryClient::new();
        let client: Arc<dyn TrustRegistryClient> = Arc::new(mock.clone());
        let syncer = MembershipSyncer::new(
            audit_ks,
            sync_queue_ks,
            sync_cursor_ks,
            registry_records_ks,
            client,
            RegistryHealth::new(),
            Some(audit_writer),
            "did:webvh:vtc.example",
        );
        (syncer, mock, dir)
    }

    async fn write_member_added(audit_ks: &KeyspaceHandle, target: &str) {
        let audit_key_ks_dir = tempfile::tempdir().unwrap();
        let key_store_for_test = Store::open(&StoreConfig {
            data_dir: audit_key_ks_dir.path().to_path_buf(),
        })
        .unwrap();
        let aks = AuditKeyStore::new(key_store_for_test.keyspace("audit_key").unwrap());
        aks.ensure_initial(&[0xAB; 32]).await.unwrap();
        let w = AuditWriter::new(audit_ks.clone(), aks);
        w.write(
            "did:webvh:vtc.example",
            Some(target),
            AuditEvent::MemberAdded(MemberAddedData {
                role: "member".into(),
                via_join_request_id: None,
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn happy_path_drains_one_publish_job() {
        let (syncer, mock, _dir) = fixture().await;
        write_member_added(&syncer.audit_ks, "did:key:zA").await;

        syncer.tick().await.unwrap();

        assert_eq!(mock.call_counts().await.publish, 1);
        let snap = mock.snapshot().await;
        assert!(snap.contains_key("did:key:zA"));

        // Job row deleted; mirror updated.
        let jobs = list_sync_jobs(&syncer.sync_queue_ks).await.unwrap();
        assert!(jobs.is_empty(), "completed jobs should be deleted");
        let mirror = get_record(&syncer.registry_records_ks, "did:key:zA")
            .await
            .unwrap();
        assert!(
            mirror.is_some(),
            "registry_records mirror should reflect the publish"
        );

        // Health flipped to Active.
        assert_eq!(
            syncer.health.status().await,
            crate::registry::HealthStatus::Active
        );
    }

    #[tokio::test]
    async fn transient_failure_bumps_attempts_and_keeps_job_pending() {
        let (syncer, mock, _dir) = fixture().await;
        write_member_added(&syncer.audit_ks, "did:key:zA").await;
        mock.fail_next_publish(RegistryError::Transient("flaky".into()))
            .await;

        syncer.tick().await.unwrap();

        let jobs = list_sync_jobs(&syncer.sync_queue_ks).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, SyncJobState::Pending);
        assert_eq!(jobs[0].attempts, 1);
        assert!(jobs[0].last_error.as_deref().unwrap().contains("flaky"));
    }

    #[tokio::test]
    async fn permanent_failure_flips_to_failed_immediately() {
        let (syncer, mock, _dir) = fixture().await;
        write_member_added(&syncer.audit_ks, "did:key:zA").await;
        mock.fail_next_publish(RegistryError::Permanent("bad input".into()))
            .await;

        syncer.tick().await.unwrap();

        let jobs = list_sync_jobs(&syncer.sync_queue_ks).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, SyncJobState::Failed);
        assert_eq!(jobs[0].attempts, 1, "single attempt then Failed");
    }

    #[tokio::test]
    async fn in_flight_rows_recover_to_pending_on_boot() {
        let (syncer, _mock, _dir) = fixture().await;
        // Seed an InFlight row by hand (simulates a crash mid-
        // dispatch).
        let mut job = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zStranded");
        job.state = SyncJobState::InFlight;
        store_sync_job(&syncer.sync_queue_ks, &job).await.unwrap();

        let recovered = syncer.recover_in_flight().await.unwrap();
        assert_eq!(recovered, 1);

        let jobs = list_sync_jobs(&syncer.sync_queue_ks).await.unwrap();
        assert_eq!(jobs[0].state, SyncJobState::Pending);
    }

    #[tokio::test]
    async fn delete_member_job_drops_mirror_row() {
        let (syncer, _mock, _dir) = fixture().await;
        // Seed the mirror so the delete path has something to
        // remove.
        store_record(
            &syncer.registry_records_ks,
            &RegistryRecord::fresh_active("did:key:zDrop"),
        )
        .await
        .unwrap();
        let job = SyncJob::fresh(SyncJobKind::DeleteMember, "did:key:zDrop");
        store_sync_job(&syncer.sync_queue_ks, &job).await.unwrap();

        syncer.tick().await.unwrap();

        let mirror = get_record(&syncer.registry_records_ks, "did:key:zDrop")
            .await
            .unwrap();
        assert!(mirror.is_none(), "mirror row should be deleted");
    }
}
