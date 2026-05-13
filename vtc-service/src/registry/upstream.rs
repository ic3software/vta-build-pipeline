//! `UpstreamRegistryClient` — production implementation of
//! [`TrustRegistryClient`] talking to a real upstream
//! `affinidi-trust-registry-rs` server.
//!
//! ## Transport split
//!
//! The upstream's HTTP surface exposes only TRQP queries
//! (`POST /recognition`, `POST /authorization`,
//! `GET /.well-known/did.json`). Record mutations go over
//! DIDComm against the upstream's `tr-admin/1.0/*` protocol
//! family.
//!
//! M3.2 lands the **HTTP transport** + the `health()` method
//! (drives `registry_status` on the community profile). The
//! DIDComm-backed write methods (`publish_member`,
//! `delete_member`) are scaffolded as "not yet wired" — they
//! return `RegistryError::Permanent` so consumers (the syncer
//! task in M3.4) fail closed until the DIDComm transport
//! lands.
//!
//! ## Why the write methods land as "not wired" first
//!
//! M3.2's load-bearing scope is the *registry_status*
//! surface — that needs only `health()`. The syncer (M3.4)
//! is the first real consumer of `publish_member` /
//! `delete_member`; the DIDComm send-and-wait plumbing lands
//! in the same PR so its failure paths are visible alongside
//! the call sites.

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::messaging::ATM;
use async_trait::async_trait;
use reqwest::Client;
use tracing::{debug, warn};

use super::client::{RegistryError, TrustRegistryClient};
use super::model::RegistryRecord;

/// Configuration for the upstream HTTP transport.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Base URL of the upstream registry — e.g.
    /// `https://registry.example.com`. No trailing slash.
    pub base_url: String,
    /// Per-call HTTP timeout. Mirrors
    /// `RegistryConfig::http_timeout_seconds`.
    pub http_timeout: Duration,
}

/// Reqwest-backed client. Lazy field: the ATM handle is only
/// needed for the DIDComm write path. `None` until M3.4 wires
/// it in — at which point `publish_member` / `delete_member`
/// will dispatch real DIDComm messages.
pub struct UpstreamRegistryClient {
    http: Client,
    base_url: String,
    /// ATM handle for DIDComm sends. `None` in M3.2; lands in
    /// M3.4 when the syncer needs the write path.
    #[allow(dead_code)]
    atm: Option<Arc<ATM>>,
}

impl std::fmt::Debug for UpstreamRegistryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamRegistryClient")
            .field("base_url", &self.base_url)
            .field("atm_set", &self.atm.is_some())
            .finish()
    }
}

impl UpstreamRegistryClient {
    /// Build the client from config. Returns an `Err` if
    /// reqwest fails to construct (typically a misconfigured
    /// TLS backend on this platform).
    pub fn new(cfg: UpstreamConfig) -> Result<Self, RegistryError> {
        let http = Client::builder()
            .timeout(cfg.http_timeout)
            // No retry middleware here — the syncer's
            // exponential backoff handles retries at the
            // job-row level, which gives us restart
            // resilience for free. A retry-middleware here
            // would mask connection-pool failures.
            .build()
            .map_err(|e| RegistryError::Permanent(format!("reqwest client init: {e}")))?;
        Ok(Self {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            atm: None,
        })
    }

    /// Inject the ATM handle for DIDComm writes. M3.4 calls
    /// this at boot once `init_auth` has produced the ATM.
    #[allow(dead_code)]
    pub fn with_atm(mut self, atm: Arc<ATM>) -> Self {
        self.atm = Some(atm);
        self
    }

    /// Classify a reqwest error into the workspace's error
    /// taxonomy. Connect / timeout / DNS errors are
    /// `Unreachable`; 5xx are `Transient`; 4xx are
    /// `Permanent`.
    fn classify_http_error(e: reqwest::Error) -> RegistryError {
        if e.is_timeout() {
            RegistryError::Unreachable(format!("timeout: {e}"))
        } else if e.is_connect() {
            RegistryError::Unreachable(format!("connect: {e}"))
        } else if let Some(s) = e.status() {
            if s.is_server_error() {
                RegistryError::Transient(format!("{s}: {e}"))
            } else {
                RegistryError::Permanent(format!("{s}: {e}"))
            }
        } else {
            RegistryError::Transient(format!("http: {e}"))
        }
    }
}

#[async_trait]
impl TrustRegistryClient for UpstreamRegistryClient {
    async fn publish_member(&self, _record: &RegistryRecord) -> Result<(), RegistryError> {
        // DIDComm transport lands in M3.4. Until then, the
        // syncer should not be dispatching against this
        // client — but if it does, fail closed loudly.
        warn!(
            "UpstreamRegistryClient.publish_member called before M3.4's DIDComm transport landed"
        );
        Err(RegistryError::Permanent(
            "publish_member is not yet implemented in M3.2 — DIDComm transport lands in M3.4"
                .into(),
        ))
    }

    async fn delete_member(&self, _member_did: &str) -> Result<(), RegistryError> {
        warn!("UpstreamRegistryClient.delete_member called before M3.4's DIDComm transport landed");
        Err(RegistryError::Permanent(
            "delete_member is not yet implemented in M3.2 — DIDComm transport lands in M3.4".into(),
        ))
    }

    async fn read_member(
        &self,
        _member_did: &str,
    ) -> Result<Option<RegistryRecord>, RegistryError> {
        // The upstream's TRQP recognition query takes a
        // 4-tuple (authority_id, entity_id, action, resource)
        // and the VTC needs to construct the right key shape
        // — that mapping lands in M3.10 alongside the
        // cross-community session-mint path.
        warn!("UpstreamRegistryClient.read_member called before M3.10's TRQP mapping landed");
        Err(RegistryError::Permanent(
            "read_member is not yet implemented in M3.2 — TRQP query mapping lands in M3.10".into(),
        ))
    }

    async fn recognise(&self, _foreign_issuer_did: &str) -> Result<bool, RegistryError> {
        // TRQP `POST /recognition` wire shape is documented by
        // upstream as a 4-tuple query (authority_id, entity_id,
        // action, resource). Pinning the exact payload — and
        // the response envelope — needs a live integration
        // test against a running upstream, which is out of
        // scope for this milestone. The verifier (M3.9) calls
        // through the trait and is exercised end-to-end via
        // `MockRegistryClient` until the wire format is
        // pinned. Production deployments using this client
        // get a clear, retriable-classification failure rather
        // than silently passing the recognition check.
        warn!("UpstreamRegistryClient.recognise called before TRQP v2.0 payload shape is pinned");
        Err(RegistryError::Permanent(
            "recognise is not yet implemented in this build — pin the upstream TRQP v2.0 wire shape first".into(),
        ))
    }

    async fn health(&self) -> Result<(), RegistryError> {
        // `GET /.well-known/did.json` is the cheapest live
        // probe the upstream exposes. A 2xx confirms the
        // service is responding to requests; a 4xx still
        // counts as "reachable" (the upstream is up; the
        // resource is just missing — that's still a green
        // signal for connectivity).
        let url = format!("{}/.well-known/did.json", self.base_url);
        debug!(%url, "trust-registry health probe");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(Self::classify_http_error)?;
        let status = resp.status();
        if status.is_success() || status.is_client_error() {
            // 2xx = OK. 4xx = upstream is up but the URL
            // isn't where we expected — still proves reachability.
            Ok(())
        } else if status.is_server_error() {
            Err(RegistryError::Transient(format!(
                "registry returned {status}"
            )))
        } else {
            Err(RegistryError::Transient(format!(
                "unexpected status {status}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_trims_trailing_slash() {
        let cfg = UpstreamConfig {
            base_url: "https://registry.example.com/".into(),
            http_timeout: Duration::from_secs(5),
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        assert_eq!(c.base_url, "https://registry.example.com");
    }

    #[tokio::test]
    async fn health_against_unreachable_host_is_unreachable() {
        let cfg = UpstreamConfig {
            // `localhost:1` is reserved + nothing listens
            // there → connection refused.
            base_url: "http://127.0.0.1:1".into(),
            http_timeout: Duration::from_millis(200),
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let err = c.health().await.expect_err("should fail");
        assert!(
            err.is_retriable(),
            "connection refused is retriable: {err:?}"
        );
    }

    #[tokio::test]
    async fn publish_member_returns_permanent_until_m3_4() {
        let cfg = UpstreamConfig {
            base_url: "http://localhost:9999".into(),
            http_timeout: Duration::from_secs(1),
        };
        let c = UpstreamRegistryClient::new(cfg).unwrap();
        let record = RegistryRecord::fresh_active("did:key:zMember");
        let err = c
            .publish_member(&record)
            .await
            .expect_err("M3.2 doesn't implement writes");
        assert!(matches!(err, RegistryError::Permanent(_)));
        assert!(!err.is_retriable());
    }
}
