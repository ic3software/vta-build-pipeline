//! CRUD helpers for the three Phase-3 registry keyspaces.
//!
//! - `registry_records:<member_did>` — local mirror of what
//!   the registry knows.
//! - `sync_queue:<job_id>` — pending sync jobs.
//! - `sync_cursor` (singleton, key `cursor`) — audit-log
//!   tail position.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{RegistryRecord, SyncJob};

/// Prefix every registry-record row sits under.
pub const REGISTRY_RECORDS_PREFIX: &[u8] = b"registry_records:";

/// Prefix every sync-job row sits under.
pub const SYNC_QUEUE_PREFIX: &[u8] = b"sync_queue:";

/// Singleton row key inside the `sync_cursor` keyspace.
const SYNC_CURSOR_KEY: &[u8] = b"cursor";

// ---------------------------------------------------------------------------
// registry_records
// ---------------------------------------------------------------------------

fn registry_record_key(member_did: &str) -> Vec<u8> {
    let mut k = REGISTRY_RECORDS_PREFIX.to_vec();
    k.extend_from_slice(member_did.as_bytes());
    k
}

pub async fn get_record(
    ks: &KeyspaceHandle,
    member_did: &str,
) -> Result<Option<RegistryRecord>, AppError> {
    let raw = ks.get_raw(registry_record_key(member_did)).await?;
    match raw {
        Some(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
                AppError::Internal(format!("RegistryRecord decode: {e}"))
            })?))
        }
        None => Ok(None),
    }
}

pub async fn store_record(ks: &KeyspaceHandle, record: &RegistryRecord) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(registry_record_key(&record.member_did))
            .expect("registry_record key is ASCII"),
        record,
    )
    .await
}

pub async fn delete_record(ks: &KeyspaceHandle, member_did: &str) -> Result<(), AppError> {
    ks.remove(registry_record_key(member_did)).await
}

pub async fn list_records(ks: &KeyspaceHandle) -> Result<Vec<RegistryRecord>, AppError> {
    let pairs = ks.prefix_iter_raw(REGISTRY_RECORDS_PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        match serde_json::from_slice::<RegistryRecord>(&v) {
            Ok(r) => out.push(r),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable registry_record row"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// sync_queue
// ---------------------------------------------------------------------------

fn sync_job_key(id: Uuid) -> Vec<u8> {
    let mut k = SYNC_QUEUE_PREFIX.to_vec();
    k.extend_from_slice(id.to_string().as_bytes());
    k
}

pub async fn get_sync_job(ks: &KeyspaceHandle, id: Uuid) -> Result<Option<SyncJob>, AppError> {
    let raw = ks.get_raw(sync_job_key(id)).await?;
    match raw {
        Some(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
                AppError::Internal(format!("SyncJob decode: {e}"))
            })?))
        }
        None => Ok(None),
    }
}

pub async fn store_sync_job(ks: &KeyspaceHandle, job: &SyncJob) -> Result<(), AppError> {
    ks.insert(
        String::from_utf8(sync_job_key(job.id)).expect("sync_job key is ASCII"),
        job,
    )
    .await
}

pub async fn delete_sync_job(ks: &KeyspaceHandle, id: Uuid) -> Result<(), AppError> {
    ks.remove(sync_job_key(id)).await
}

pub async fn list_sync_jobs(ks: &KeyspaceHandle) -> Result<Vec<SyncJob>, AppError> {
    let pairs = ks.prefix_iter_raw(SYNC_QUEUE_PREFIX.to_vec()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_k, v) in pairs {
        match serde_json::from_slice::<SyncJob>(&v) {
            Ok(j) => out.push(j),
            Err(err) => tracing::warn!(error = %err, "skipping unparseable sync_job row"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// sync_cursor — singleton
// ---------------------------------------------------------------------------

/// Read the audit-log tail's last-seen timestamp. `None` on
/// first boot (the syncer walks from the start of the audit log).
pub async fn get_sync_cursor(ks: &KeyspaceHandle) -> Result<Option<DateTime<Utc>>, AppError> {
    let raw = ks.get_raw(SYNC_CURSOR_KEY.to_vec()).await?;
    let Some(bytes) = raw else { return Ok(None) };
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| AppError::Internal(format!("sync_cursor not utf-8: {e}")))?;
    let ts = DateTime::parse_from_rfc3339(s)
        .map_err(|e| AppError::Internal(format!("sync_cursor not rfc3339: {e}")))?
        .with_timezone(&Utc);
    Ok(Some(ts))
}

/// Persist the audit-log tail's last-seen timestamp. Called
/// after the syncer has enqueued every job from the audit
/// envelopes up to (and including) this timestamp.
pub async fn set_sync_cursor(ks: &KeyspaceHandle, ts: DateTime<Utc>) -> Result<(), AppError> {
    ks.insert_raw(SYNC_CURSOR_KEY.to_vec(), ts.to_rfc3339().into_bytes())
        .await
}

/// Reset the cursor — useful for diagnostic tools that want a
/// full audit-log replay. Not exposed on any production
/// endpoint.
pub async fn clear_sync_cursor(ks: &KeyspaceHandle) -> Result<(), AppError> {
    ks.remove(SYNC_CURSOR_KEY.to_vec()).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::model::{
        RegistryRecord, RegistryStatus, SyncJob, SyncJobKind, SyncJobState,
    };
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn temp_keyspaces() -> (
        KeyspaceHandle,
        KeyspaceHandle,
        KeyspaceHandle,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let records = store.keyspace("registry_records").unwrap();
        let queue = store.keyspace("sync_queue").unwrap();
        let cursor = store.keyspace("sync_cursor").unwrap();
        (records, queue, cursor, dir)
    }

    #[tokio::test]
    async fn registry_record_round_trip() {
        let (records, _q, _c, _dir) = temp_keyspaces().await;
        let rec = RegistryRecord::fresh_active("did:key:zMember");
        store_record(&records, &rec).await.unwrap();
        let got = get_record(&records, "did:key:zMember")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.member_did, "did:key:zMember");
        assert_eq!(got.status, RegistryStatus::Active);

        delete_record(&records, "did:key:zMember").await.unwrap();
        assert!(
            get_record(&records, "did:key:zMember")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_records_walks_keyspace() {
        let (records, _q, _c, _dir) = temp_keyspaces().await;
        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_record(&records, &RegistryRecord::fresh_active(did))
                .await
                .unwrap();
        }
        let all = list_records(&records).await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn sync_job_round_trip_across_each_state() {
        let (_r, queue, _c, _dir) = temp_keyspaces().await;
        for kind in [
            SyncJobKind::PublishMember,
            SyncJobKind::UpdateMember,
            SyncJobKind::DeleteMember,
            SyncJobKind::MarkDeparted,
        ] {
            let job = SyncJob::fresh(kind, "did:key:zMember");
            store_sync_job(&queue, &job).await.unwrap();
            let got = get_sync_job(&queue, job.id).await.unwrap().unwrap();
            assert_eq!(got.kind, kind);
            assert_eq!(got.state, SyncJobState::Pending);
            delete_sync_job(&queue, job.id).await.unwrap();
            assert!(get_sync_job(&queue, job.id).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn list_sync_jobs_returns_all_pending() {
        let (_r, queue, _c, _dir) = temp_keyspaces().await;
        for did in ["did:key:zA", "did:key:zB"] {
            let job = SyncJob::fresh(SyncJobKind::PublishMember, did);
            store_sync_job(&queue, &job).await.unwrap();
        }
        let all = list_sync_jobs(&queue).await.unwrap();
        assert_eq!(all.len(), 2);
        for j in all {
            assert_eq!(j.state, SyncJobState::Pending);
        }
    }

    #[tokio::test]
    async fn sync_cursor_round_trip() {
        let (_r, _q, cursor, _dir) = temp_keyspaces().await;
        assert!(get_sync_cursor(&cursor).await.unwrap().is_none());
        let ts = Utc::now();
        set_sync_cursor(&cursor, ts).await.unwrap();
        let got = get_sync_cursor(&cursor).await.unwrap().unwrap();
        // RFC3339 round-trip can lose sub-second precision; compare to the second.
        assert_eq!(got.timestamp(), ts.timestamp());
        clear_sync_cursor(&cursor).await.unwrap();
        assert!(get_sync_cursor(&cursor).await.unwrap().is_none());
    }
}
