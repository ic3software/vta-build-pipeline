//! File-descriptor / content cache for live-mode static serving
//! (§12.1, Phase 5 M5.4.1).
//!
//! Trades RAM for syscall pressure: files are read into memory the
//! first time they're requested and held for
//! `website.live_cache_ttl_seconds` (default 5). After expiry the
//! next request triggers a fresh read. The cache also stores the
//! SHA-256 digest so the ETag response header doesn't re-hash on
//! every conditional GET.
//!
//! Managed mode generally benefits from a longer TTL since
//! generation directories are immutable; PR-3 (M5.5) wires that
//! optimisation. PR-2 keeps the TTL semantics uniform.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// One cached file. The `digest` is the SHA-256 of `body`; both
/// outlive the cache miss together so the ETag header is
/// computable without a re-read.
#[derive(Debug, Clone)]
pub struct CachedFile {
    pub body: Arc<Vec<u8>>,
    pub digest_hex: Arc<String>,
    pub fetched_at: Instant,
}

/// Thread-safe content cache shared across handler invocations.
#[derive(Debug, Clone)]
pub struct WebsiteCache {
    inner: Arc<RwLock<HashMap<PathBuf, CachedFile>>>,
    ttl: Duration,
}

impl WebsiteCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Read the file at `path` through the cache. On cache miss,
    /// reads from disk and stores the entry. On cache hit, refresh
    /// the entry from disk if its TTL has elapsed; otherwise
    /// return the cached copy.
    pub async fn get(&self, path: &std::path::Path) -> std::io::Result<CachedFile> {
        // Try cached read first.
        if let Some(entry) = self.inner.read().await.get(path)
            && entry.fetched_at.elapsed() < self.ttl
        {
            return Ok(entry.clone());
        }

        // Miss / expired — fall through to disk read.
        let bytes = tokio::fs::read(path).await?;
        let digest_hex = hex::encode(Sha256::digest(&bytes));
        let entry = CachedFile {
            body: Arc::new(bytes),
            digest_hex: Arc::new(digest_hex),
            fetched_at: Instant::now(),
        };
        self.inner
            .write()
            .await
            .insert(path.to_path_buf(), entry.clone());
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_returns_consistent_digest() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, b"hello world").unwrap();

        let cache = WebsiteCache::new(60);
        let a = cache.get(&file).await.unwrap();
        let b = cache.get(&file).await.unwrap();

        assert_eq!(a.digest_hex, b.digest_hex);
        // Compare via expected SHA-256 prefix.
        assert!(
            a.digest_hex.starts_with("b94d27b9934d3e08"),
            "got {}",
            a.digest_hex
        );
    }

    #[tokio::test]
    async fn cache_misses_after_ttl_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, b"v1").unwrap();

        // Zero TTL → every get triggers a disk read.
        let cache = WebsiteCache::new(0);
        let a = cache.get(&file).await.unwrap();

        std::fs::write(&file, b"v2-different").unwrap();
        let b = cache.get(&file).await.unwrap();

        assert_ne!(a.digest_hex, b.digest_hex, "TTL expiry must re-read");
    }
}
