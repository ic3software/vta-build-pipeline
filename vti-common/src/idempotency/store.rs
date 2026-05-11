//! Persistent idempotency cache: `(principal, key) → CacheEntry`.

use std::net::IpAddr;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::class::IdempotencyClass;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Identifier scoping the idempotency cache. **Never plaintext on
/// disk** — the principal bytes are hashed and the hash becomes part
/// of the storage key. Different principals therefore inhabit
/// disjoint namespaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// Authenticated request — principal is the bearer credential
    /// itself (hashed at storage time, never persisted in the clear).
    /// Different tokens are different principals; token rotation
    /// resets the cache namespace (conservatively).
    AuthToken(Vec<u8>),
    /// Unauthenticated request scoped to the source IP. Phase-0
    /// unauth surfaces are `/v1/join-requests` and `/v1/install/*`;
    /// the IP-scoping prevents one IP's idempotent retry returning
    /// another IP's cached response.
    Ip(IpAddr),
    /// Fallback when neither Authorization nor `ConnectInfo` is
    /// available (e.g. unit tests). Cache is effectively shared
    /// across anonymous callers — acceptable because no Phase-0
    /// production path lacks both signals.
    Anonymous,
}

impl Principal {
    /// 32-byte hash of the principal — the actual cache namespace.
    /// Stable across calls; equal `Principal`s hash to equal bytes.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match self {
            Principal::AuthToken(bytes) => {
                hasher.update(b"auth-token:");
                hasher.update(bytes);
            }
            Principal::Ip(ip) => {
                hasher.update(b"ip:");
                hasher.update(ip.to_string().as_bytes());
            }
            Principal::Anonymous => {
                hasher.update(b"anonymous");
            }
        }
        hasher.finalize().into()
    }
}

/// Derive a [`Principal`] from request parts.
///
/// Prefers the Authorization header (hashed) when present, falls
/// back to `ConnectInfo<SocketAddr>` (which Axum populates from
/// `into_make_service_with_connect_info`), and finally to
/// [`Principal::Anonymous`].
///
/// Public so a service can inspect / log the principal without
/// re-implementing the precedence.
pub fn principal_from_request(parts: &Parts) -> Principal {
    if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        return Principal::AuthToken(auth.as_bytes().to_vec());
    }
    if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<std::net::SocketAddr>>() {
        return Principal::Ip(addr.ip());
    }
    Principal::Anonymous
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// Persisted cache record. The response is held in full so a retry
/// reproduces every header + body byte the original delivered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub idempotency_key: String,
    /// SHA-256 over the request body. Differing hashes for the same
    /// `(principal, key)` cause [`AppError::IdempotencyKeyConflict`].
    pub request_hash: [u8; 32],
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub class: IdempotencyClass,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CacheEntry {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

// ---------------------------------------------------------------------------
// IdempotencyStore
// ---------------------------------------------------------------------------

/// Wraps an `idempotency` keyspace. Cheap to clone — the underlying
/// keyspace handle is `Arc`-shared.
#[derive(Clone)]
pub struct IdempotencyStore {
    ks: KeyspaceHandle,
}

impl IdempotencyStore {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }

    /// Look up an existing entry. **Expired entries are treated as
    /// absent** so a long-stale cached response is never served, even
    /// if a background sweeper hasn't yet reclaimed the disk space.
    pub async fn get(
        &self,
        principal_hash: &[u8; 32],
        key: &str,
    ) -> Result<Option<CacheEntry>, AppError> {
        let storage_key = storage_key(principal_hash, key);
        let entry: Option<CacheEntry> = self.ks.get(storage_key).await?;
        let now = Utc::now();
        Ok(entry.filter(|e| !e.is_expired(now)))
    }

    /// Insert or replace a cache entry. Caller is responsible for
    /// setting `expires_at = created_at + class.ttl_seconds()`.
    pub async fn put(&self, principal_hash: &[u8; 32], entry: &CacheEntry) -> Result<(), AppError> {
        let storage_key = storage_key(principal_hash, &entry.idempotency_key);
        self.ks.insert(storage_key, entry).await
    }
}

fn storage_key(principal_hash: &[u8; 32], key: &str) -> Vec<u8> {
    // Hex-encode the principal hash so the resulting fjall key stays
    // ASCII for grepping during debugging. Newlines / NUL bytes are
    // rejected upstream by the idempotency middleware's header
    // validation, so the unencoded `key` part is safe to embed
    // directly.
    let mut out = Vec::with_capacity(64 + key.len() + 5);
    out.extend_from_slice(b"idem:");
    out.extend_from_slice(hex::encode(principal_hash).as_bytes());
    out.push(b':');
    out.extend_from_slice(key.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use chrono::Duration;

    fn temp_store() -> (IdempotencyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("idempotency-test").expect("ks");
        (IdempotencyStore::new(ks), dir)
    }

    fn sample_entry() -> CacheEntry {
        let now = Utc::now();
        CacheEntry {
            idempotency_key: "key-1".into(),
            request_hash: [0xAB; 32],
            response_status: 201,
            response_headers: vec![("content-type".into(), "application/json".into())],
            response_body: br#"{"ok":true}"#.to_vec(),
            class: IdempotencyClass::NonDestructive,
            created_at: now,
            expires_at: now
                + Duration::seconds(IdempotencyClass::NonDestructive.ttl_seconds() as i64),
        }
    }

    #[test]
    fn principal_hash_is_stable_and_distinct_across_kinds() {
        let a = Principal::AuthToken(b"Bearer abc".to_vec());
        let a_again = Principal::AuthToken(b"Bearer abc".to_vec());
        let b = Principal::AuthToken(b"Bearer xyz".to_vec());
        let ip = Principal::Ip(IpAddr::V4("127.0.0.1".parse().unwrap()));
        let anon = Principal::Anonymous;

        assert_eq!(a.hash(), a_again.hash());
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), ip.hash());
        assert_ne!(a.hash(), anon.hash());
        assert_ne!(ip.hash(), anon.hash());
    }

    #[tokio::test]
    async fn put_then_get_returns_entry() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let entry = sample_entry();

        store.put(&principal, &entry).await.unwrap();
        let got = store.get(&principal, &entry.idempotency_key).await.unwrap();
        assert_eq!(got.as_ref(), Some(&entry));
    }

    #[tokio::test]
    async fn entries_are_scoped_by_principal() {
        let (store, _dir) = temp_store();
        let a = Principal::AuthToken(b"alice".to_vec()).hash();
        let b = Principal::AuthToken(b"bob".to_vec()).hash();
        let entry = sample_entry();

        store.put(&a, &entry).await.unwrap();
        let got_a = store.get(&a, &entry.idempotency_key).await.unwrap();
        let got_b = store.get(&b, &entry.idempotency_key).await.unwrap();
        assert!(got_a.is_some());
        assert!(got_b.is_none(), "principal scoping leaked");
    }

    #[tokio::test]
    async fn expired_entries_are_filtered_at_read_time() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let mut entry = sample_entry();
        entry.expires_at = Utc::now() - Duration::seconds(1);
        store.put(&principal, &entry).await.unwrap();

        let got = store.get(&principal, &entry.idempotency_key).await.unwrap();
        assert!(got.is_none(), "stale entry served");
    }

    #[tokio::test]
    async fn put_overwrites_existing_entry_under_same_key() {
        let (store, _dir) = temp_store();
        let principal = Principal::AuthToken(b"Bearer t".to_vec()).hash();
        let first = sample_entry();
        store.put(&principal, &first).await.unwrap();

        let mut second = first.clone();
        second.response_status = 204;
        second.response_body = b"updated".to_vec();
        store.put(&principal, &second).await.unwrap();

        let got = store.get(&principal, &first.idempotency_key).await.unwrap();
        assert_eq!(got.unwrap().response_status, 204);
    }
}
