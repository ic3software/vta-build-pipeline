//! Audit-log tail walker — Phase 3 M3.3.
//!
//! Walks the `audit:` keyspace from a persisted cursor and
//! converts membership-affecting envelopes into [`SyncJob`]
//! rows. The cursor is the RFC3339 timestamp of the
//! last-processed envelope; a daemon restart picks up
//! exactly where the prior run left off (no double-enqueue,
//! no missed event).
//!
//! ## Why poll, not subscribe
//!
//! Plan §D3 traded latency for a clean separation: emitters
//! (the route handlers + the syncer task) never know about
//! each other. A future architecture could plumb an in-process
//! channel to drop tail latency below the audit-row write
//! latency, but the polling design wins on restart resilience
//! — the audit log IS the event source of truth, so cursor-
//! driven replay handles every "daemon crashed mid-flight"
//! scenario the same way.
//!
//! ## Which audit variants enqueue jobs
//!
//! - `MemberAdded` → `SyncJobKind::PublishMember`
//! - `MemberRemoved` → `SyncJobKind::DeleteMember` when
//!   disposition is `Purge`; `SyncJobKind::MarkDeparted`
//!   when `Tombstone` / `Historical`. (Disposition resolves
//!   at the emitter; we trust the `MemberRemovedData.disposition`
//!   field.)
//! - `RoleChanged` → `SyncJobKind::UpdateMember`. The role
//!   itself doesn't propagate to the registry record shape
//!   today — the registry-record `status` flips between
//!   `Active`/`Departed` only — but the `UpdateMember` job
//!   keeps the local mirror's `last_synced_at` fresh so drift
//!   detection has something to anchor against.
//!
//! Every other audit variant is ignored. Operator-action
//! envelopes (`ConfigChanged`, `AdminPasskeyRegistered`, etc.)
//! never reach the registry.

use chrono::{DateTime, Utc};
use tracing::{debug, warn};
use vti_common::audit::{AuditEnvelope, AuditEvent, MemberRemovedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{SyncJob, SyncJobKind};
use super::storage::store_sync_job;

/// Outcome of one walk pass. `new_cursor` is the RFC3339
/// timestamp of the latest envelope inspected (Some unless the
/// audit log is empty); `jobs_enqueued` counts how many fresh
/// `SyncJob` rows landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkOutcome {
    pub new_cursor: Option<DateTime<Utc>>,
    pub jobs_enqueued: usize,
}

/// Walk audit envelopes since `cursor`. Returns the new cursor
/// + the number of jobs enqueued.
///
/// `cursor = None` walks from the start of the audit log
/// (first-boot path). Subsequent calls pass the previous
/// `new_cursor` back in.
///
/// The function is idempotent under concurrent runs only when
/// the caller serializes calls (typically the syncer's tick
/// loop holds exclusive access). A racy double-call could
/// enqueue duplicate jobs; the syncer's tick loop never runs
/// concurrently with itself, so this isn't a hazard in
/// production.
pub async fn walk(
    audit_ks: &KeyspaceHandle,
    sync_queue_ks: &KeyspaceHandle,
    cursor: Option<DateTime<Utc>>,
) -> Result<WalkOutcome, AppError> {
    let pairs = audit_ks.prefix_iter_raw(Vec::new()).await?;
    let mut jobs_enqueued = 0_usize;
    let mut latest_seen = cursor;

    for (key, value) in pairs {
        let envelope: AuditEnvelope = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(&key),
                    "skipping unparseable audit envelope during tail walk"
                );
                continue;
            }
        };
        // Skip envelopes at-or-before the cursor. The cursor
        // semantic is "everything up to and including this
        // timestamp has been processed", so equality also
        // skips.
        if let Some(c) = cursor
            && envelope.timestamp <= c
        {
            continue;
        }
        // Track the latest-seen timestamp regardless of
        // whether we enqueue — cursor advances over rows we
        // chose not to enqueue (other audit variants), so a
        // future restart doesn't re-walk them.
        if latest_seen.is_none_or(|prev| envelope.timestamp > prev) {
            latest_seen = Some(envelope.timestamp);
        }
        if let Some(job) = audit_to_sync_job(&envelope) {
            store_sync_job(sync_queue_ks, &job).await?;
            jobs_enqueued += 1;
            debug!(
                job_id = %job.id,
                kind = job.kind.as_str(),
                did = %job.member_did,
                "enqueued sync job from audit envelope"
            );
        }
    }

    Ok(WalkOutcome {
        new_cursor: latest_seen,
        jobs_enqueued,
    })
}

/// Convert an audit envelope into a `SyncJob`. Returns `None`
/// for variants that don't drive registry mutations.
fn audit_to_sync_job(envelope: &AuditEnvelope) -> Option<SyncJob> {
    match &envelope.event {
        AuditEvent::MemberAdded(_data) => {
            let target = envelope.target_did_plain.as_deref()?;
            Some(SyncJob::fresh(SyncJobKind::PublishMember, target))
        }
        AuditEvent::MemberRemoved(MemberRemovedData { disposition, .. }) => {
            let target = envelope.target_did_plain.as_deref()?;
            let mut job = match disposition.as_str() {
                "purge" => SyncJob::fresh(SyncJobKind::DeleteMember, target),
                "tombstone" | "historical" => SyncJob::fresh(SyncJobKind::MarkDeparted, target),
                other => {
                    warn!(
                        disposition = other,
                        target = target,
                        "MemberRemoved with unknown disposition — defaulting to MarkDeparted"
                    );
                    SyncJob::fresh(SyncJobKind::MarkDeparted, target)
                }
            };
            job.disposition = Some(disposition.clone());
            Some(job)
        }
        AuditEvent::RoleChanged(_data) => {
            let target = envelope.target_did_plain.as_deref()?;
            Some(SyncJob::fresh(SyncJobKind::UpdateMember, target))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::model::SyncJobState;
    use crate::registry::storage::list_sync_jobs;
    use vti_common::audit::{
        AuditKeyStore, AuditWriter, JoinRequestData, MemberAddedData, MemberRemovedData,
        RoleChangedData,
    };
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_keyspaces() -> (
        KeyspaceHandle,
        KeyspaceHandle,
        AuditWriter,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let audit_ks = store.keyspace("audit").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let sync_queue_ks = store.keyspace("sync_queue").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        let writer = AuditWriter::new(audit_ks.clone(), key_store);
        (audit_ks, sync_queue_ks, writer, dir)
    }

    async fn write_member_added(writer: &AuditWriter, target: &str) {
        writer
            .write(
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

    async fn write_member_removed(writer: &AuditWriter, target: &str, disposition: &str) {
        writer
            .write(
                "did:webvh:vtc.example",
                Some(target),
                AuditEvent::MemberRemoved(MemberRemovedData {
                    disposition: disposition.into(),
                    reason: String::new(),
                }),
            )
            .await
            .unwrap();
    }

    async fn write_role_changed(writer: &AuditWriter, target: &str) {
        writer
            .write(
                "did:webvh:vtc.example",
                Some(target),
                AuditEvent::RoleChanged(RoleChangedData {
                    previous_role: "member".into(),
                    new_role: "moderator".into(),
                }),
            )
            .await
            .unwrap();
    }

    async fn write_unrelated_envelope(writer: &AuditWriter) {
        writer
            .write(
                "did:webvh:vtc.example",
                None,
                AuditEvent::JoinRequestSubmitted(JoinRequestData {
                    request_id: "ignored".into(),
                    transport: "rest".into(),
                }),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enqueues_publish_for_member_added() {
        let (audit_ks, queue_ks, writer, _dir) = temp_keyspaces().await;
        write_member_added(&writer, "did:key:zA").await;

        let outcome = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&queue_ks).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, SyncJobKind::PublishMember);
        assert_eq!(jobs[0].member_did, "did:key:zA");
        assert_eq!(jobs[0].state, SyncJobState::Pending);
    }

    #[tokio::test]
    async fn member_removed_dispositions_map_to_correct_kinds() {
        let (audit_ks, queue_ks, writer, _dir) = temp_keyspaces().await;
        write_member_removed(&writer, "did:key:zPurge", "purge").await;
        write_member_removed(&writer, "did:key:zTomb", "tombstone").await;
        write_member_removed(&writer, "did:key:zHist", "historical").await;

        let outcome = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(outcome.jobs_enqueued, 3);
        let mut jobs = list_sync_jobs(&queue_ks).await.unwrap();
        jobs.sort_by(|a, b| a.member_did.cmp(&b.member_did));
        let by_did: std::collections::HashMap<_, _> = jobs
            .into_iter()
            .map(|j| (j.member_did.clone(), j))
            .collect();
        assert_eq!(by_did["did:key:zPurge"].kind, SyncJobKind::DeleteMember);
        assert_eq!(
            by_did["did:key:zPurge"].disposition.as_deref(),
            Some("purge")
        );
        assert_eq!(by_did["did:key:zTomb"].kind, SyncJobKind::MarkDeparted);
        assert_eq!(by_did["did:key:zHist"].kind, SyncJobKind::MarkDeparted);
    }

    #[tokio::test]
    async fn role_changed_enqueues_update_member() {
        let (audit_ks, queue_ks, writer, _dir) = temp_keyspaces().await;
        write_role_changed(&writer, "did:key:zRole").await;

        let outcome = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&queue_ks).await.unwrap();
        assert_eq!(jobs[0].kind, SyncJobKind::UpdateMember);
    }

    #[tokio::test]
    async fn unrelated_envelopes_are_ignored() {
        let (audit_ks, queue_ks, writer, _dir) = temp_keyspaces().await;
        write_unrelated_envelope(&writer).await;
        write_member_added(&writer, "did:key:zA").await;
        write_unrelated_envelope(&writer).await;

        let outcome = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        // Cursor still advances over the unrelated rows so a
        // subsequent walk doesn't re-process them.
        assert!(outcome.new_cursor.is_some());
    }

    #[tokio::test]
    async fn cursor_advances_so_restart_is_idempotent() {
        let (audit_ks, queue_ks, writer, _dir) = temp_keyspaces().await;
        write_member_added(&writer, "did:key:zA").await;
        let first = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(first.jobs_enqueued, 1);

        // Second walk with the prior cursor enqueues nothing.
        let second = walk(&audit_ks, &queue_ks, first.new_cursor).await.unwrap();
        assert_eq!(second.jobs_enqueued, 0);

        // New event after the cursor lands as a fresh job.
        write_member_added(&writer, "did:key:zB").await;
        let third = walk(&audit_ks, &queue_ks, first.new_cursor).await.unwrap();
        assert_eq!(third.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&queue_ks).await.unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn empty_audit_log_yields_no_cursor() {
        let (audit_ks, queue_ks, _writer, _dir) = temp_keyspaces().await;
        let outcome = walk(&audit_ks, &queue_ks, None).await.unwrap();
        assert_eq!(outcome.jobs_enqueued, 0);
        assert!(outcome.new_cursor.is_none());
    }
}
