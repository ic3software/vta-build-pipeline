use serde::Deserialize;
use tracing::{debug, info};
use url::{Host, Url};

use crate::error::AppError;

pub struct WebvhClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

/// Decide whether a host is a loopback address we're willing to dial
/// over plaintext `http://` in dev. We accept:
///
/// - the literal domain `localhost` (and only that — `localhost.evil`
///   resolves to attacker-controlled IPs),
/// - any IPv4 in `127.0.0.0/8` (covers `127.0.0.1` and dev shims like
///   `127.0.0.2`),
/// - the IPv6 loopback `::1` (and only that — `::ffff:8.8.8.8` IPv4-
///   mapped IPv6 is *not* a loopback even though it sometimes parses
///   as one in laxer stacks).
///
/// We deliberately exclude `0.0.0.0` (a listen-on-all-interfaces
/// sentinel an operator should rarely *dial*) and
/// `host.docker.internal` (resolution depends on the container
/// runtime). Operators who need plain HTTP from outside loopback
/// should terminate TLS at a reverse proxy and advertise its
/// `https://` URL in the daemon DID's service entry.
fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => *d == "localhost",
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Reject schemes other than `https://` (always) or `http://` to a
/// loopback host (dev only). Bearer tokens, the VTA-signed
/// authenticate JWS, and refresh tokens must never travel over
/// plaintext. The check happens at client construction so every
/// REST entrypoint inherits it — there is no "skip the check"
/// path for individual requests.
fn enforce_transport_security(parsed: &Url, raw: &str) -> Result<(), AppError> {
    let scheme = parsed.scheme();
    if scheme == "https" {
        return Ok(());
    }
    if scheme == "http" {
        if parsed.host().map(|h| is_loopback_host(&h)).unwrap_or(false) {
            return Ok(());
        }
        return Err(AppError::Validation(format!(
            "refusing to dial webvh-server `{raw}` over plaintext `http://`: \
             bearer tokens and the VTA's signed authenticate payload must not be sent \
             over plaintext. Only `http://` to a loopback host \
             (localhost, 127/8, ::1) is permitted; advertise an `https://` endpoint in \
             the server DID's service entry instead.",
        )));
    }
    Err(AppError::Validation(format!(
        "webvh-server URL `{raw}` uses unsupported scheme `{scheme}://`; \
         only `https://` (recommended) or `http://` to a loopback host are accepted.",
    )))
}

#[derive(Debug, Deserialize)]
pub struct RequestUriResponse {
    pub did_url: String,
    pub mnemonic: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckPathResponse {
    pub available: bool,
}

impl WebvhClient {
    /// Construct a client for a daemon REST URL. Rejects URLs whose
    /// scheme would send the bearer token / authenticate JWS over
    /// plaintext to a non-loopback host. See
    /// [`enforce_transport_security`] for the policy.
    pub fn new(server_url: &str) -> Result<Self, AppError> {
        let parsed = Url::parse(server_url).map_err(|e| {
            AppError::Validation(format!("invalid webvh-server URL `{server_url}`: {e}"))
        })?;
        enforce_transport_security(&parsed, server_url)?;
        Ok(Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        })
    }

    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    /// Apply authorization header (if set) to a request builder.
    fn with_auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.access_token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req
    }

    /// Send a request and check for success. Returns an error with context on failure.
    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        context: &str,
    ) -> Result<reqwest::Response, AppError> {
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "webvh-server {context} failed ({status}): {text}"
            )));
        }
        Ok(resp)
    }

    /// POST /api/dids — allocate URI (optional path).
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };
        let req = self.with_auth(self.http.post(&url)).json(&body);
        let resp = self.send(req, "POST /api/dids").await?;
        debug!(method = "POST", status = 200, "webvh: received via rest");
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// POST /api/dids/register — atomic claim-and-publish.
    ///
    /// Single round-trip equivalent to `request_uri(path)` +
    /// `publish_did(mnemonic, log_content)` but committed in one fjall
    /// batch on the server, so resolvers never see the slot empty
    /// between allocation and content upload. The relevant flow for
    /// promoting an existing serverless DID to a host without a
    /// resolvability gap.
    ///
    /// `force` is honoured only when the caller is an admin replacing a
    /// slot owned by a different DID. The owner re-registering their
    /// own slot is idempotent and needs no force.
    pub async fn register_did_atomic(
        &self,
        path: &str,
        did_log: &str,
        force: bool,
    ) -> Result<RequestUriResponse, AppError> {
        let url = format!("{}/api/dids/register", self.server_url);
        info!(method = "POST", %url, "webvh: sending via rest");
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::json!({
                "path": path,
                "did_log": did_log,
                "force": force,
            }));
        let resp = self.send(req, "POST /api/dids/register").await?;
        debug!(method = "POST", status = 200, "webvh: received via rest");
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }

    /// PUT /api/dids/{mnemonic} — publish DID log.
    pub async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "PUT", %url, "webvh: sending via rest");
        let req = self
            .with_auth(self.http.put(&url))
            .header("Content-Type", "application/jsonl")
            .body(log_content.to_string());
        self.send(req, &format!("PUT /api/dids/{mnemonic}")).await?;
        debug!(method = "PUT", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// DELETE /api/dids/{mnemonic}.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let url = format!("{}/api/dids/{mnemonic}", self.server_url);
        info!(method = "DELETE", %url, "webvh: sending via rest");
        let req = self.with_auth(self.http.delete(&url));
        self.send(req, &format!("DELETE /api/dids/{mnemonic}"))
            .await?;
        debug!(method = "DELETE", status = 200, "webvh: received via rest");
        Ok(())
    }

    /// POST /api/dids/check — check if a path is available.
    pub async fn check_path(&self, path: &str) -> Result<CheckPathResponse, AppError> {
        let url = format!("{}/api/dids/check", self.server_url);
        let req = self
            .with_auth(self.http.post(&url))
            .json(&serde_json::json!({ "path": path }));
        let resp = self.send(req, "POST /api/dids/check").await?;
        resp.json()
            .await
            .map_err(|e| AppError::Internal(format!("webvh-server response parse error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_validation_err(result: Result<WebvhClient, AppError>, needle: &str) {
        match result {
            Err(AppError::Validation(msg)) => assert!(
                msg.contains(needle),
                "expected validation error to contain `{needle}`, got: {msg}"
            ),
            Err(other) => panic!("expected Validation error, got {other:?}"),
            Ok(_) => panic!("expected Validation error, got Ok"),
        }
    }

    #[test]
    fn https_url_is_accepted() {
        // Standard production case — DID advertises an https endpoint.
        let c = WebvhClient::new("https://daemon.example").expect("https must be accepted");
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn https_url_trailing_slash_is_normalised() {
        // Match the existing trim_end_matches('/') behaviour so callers
        // can format paths with a leading slash without producing `//`.
        let c = WebvhClient::new("https://daemon.example/").unwrap();
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn http_to_non_loopback_is_rejected() {
        // The core invariant: bearer tokens and the signed JWS must
        // not be sent over plaintext to a network-reachable host.
        assert_validation_err(
            WebvhClient::new("http://daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn http_to_localhost_is_accepted_for_dev() {
        // Local-dev escape hatch — operator's daemon on the same host.
        let c = WebvhClient::new("http://localhost:8530").unwrap();
        assert_eq!(c.server_url, "http://localhost:8530");
    }

    #[test]
    fn http_to_127_0_0_1_is_accepted() {
        let c = WebvhClient::new("http://127.0.0.1:8530").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.1:8530");
    }

    #[test]
    fn http_to_127_0_0_x_subnet_is_accepted() {
        // We use the IPv4 `is_loopback()` predicate, which covers all
        // of `127.0.0.0/8` — including dev shims like 127.0.0.2 that
        // operators use to bind multiple local services.
        let c = WebvhClient::new("http://127.0.0.5:8530").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.5:8530");
    }

    #[test]
    fn http_to_ipv6_loopback_is_accepted() {
        let c = WebvhClient::new("http://[::1]:8530").unwrap();
        // The url crate normalises bracketed IPv6 in display form.
        assert!(c.server_url.contains("::1"));
    }

    #[test]
    fn http_to_0_0_0_0_is_rejected() {
        // 0.0.0.0 is a listen-on-all address. An operator dialing it
        // from the VTA host is technically loopback-equivalent, but
        // it's also the kind of typo that a misconfigured daemon DID
        // can introduce — fail loud rather than silently allow it.
        assert_validation_err(
            WebvhClient::new("http://0.0.0.0:8530"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        assert_validation_err(
            WebvhClient::new("ftp://daemon.example/"),
            "unsupported scheme",
        );
    }

    #[test]
    fn ws_scheme_is_rejected() {
        // WebSocket isn't a wire we serve daemon REST over —
        // a daemon DID advertising ws:// is a misconfiguration.
        assert_validation_err(
            WebvhClient::new("ws://daemon.example/"),
            "unsupported scheme",
        );
    }

    #[test]
    fn malformed_url_is_rejected() {
        assert_validation_err(WebvhClient::new("not-a-url"), "invalid webvh-server URL");
    }

    #[test]
    fn empty_url_is_rejected() {
        assert_validation_err(WebvhClient::new(""), "invalid webvh-server URL");
    }

    #[test]
    fn https_to_loopback_is_also_accepted() {
        // Operators running a TLS-terminating proxy locally
        // (mkcert + nginx, mitmproxy) should still work.
        let c = WebvhClient::new("https://localhost:8443").unwrap();
        assert_eq!(c.server_url, "https://localhost:8443");
    }

    #[test]
    fn http_to_hostname_resembling_localhost_is_rejected() {
        // `localhost.evil.com` resolves wherever the attacker wants —
        // accept only the literal `localhost`, not anything ending in it.
        assert_validation_err(
            WebvhClient::new("http://localhost.evil.example"),
            "refusing to dial webvh-server",
        );
    }
}
