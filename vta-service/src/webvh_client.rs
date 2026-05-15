use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::error::AppError;
use crate::webvh_auth::{
    ChallengeContext, VtaSigningIdentity, build_authenticate_message, build_refresh_message,
};

pub struct WebvhClient {
    http: reqwest::Client,
    server_url: String,
    /// The daemon's DID. Bound at construction so the auth flow can
    /// populate the DIDComm `to:` field for audience-binding, and so
    /// the operator-facing error messages can name *which* daemon
    /// the failure came from.
    server_did: String,
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

/// Tokens returned by the daemon's `/api/auth/` and `/api/auth/refresh`
/// endpoints. Field names match the daemon's
/// `affinidi_webvh_common::AuthenticateData` / `RefreshData` (camelCase
/// on the wire). The daemon **always rotates the refresh token** on
/// use, so a `TokenData` returned from `refresh()` carries a
/// different `refresh_token` from the one supplied as input —
/// callers must persist the new value.
///
/// Hygiene:
/// - `ZeroizeOnDrop` overwrites the token bytes when the instance
///   falls out of scope.
/// - `Debug` is manually implemented to redact the token strings —
///   accidental `tracing::error!(?tokens, ...)` then logs
///   `<redacted>` instead of the secret.
#[derive(Clone, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

impl std::fmt::Debug for TokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenData")
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Wire shape of `/api/auth/` and `/api/auth/refresh` responses.
/// Wrapped in `{session_id, data}` per the daemon's
/// `AuthenticateResponse` / `RefreshResponse` types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponseWire {
    #[allow(dead_code)] // accepted for shape match; client doesn't need the value
    session_id: String,
    data: TokenData,
}

/// Wire shape of `/api/auth/challenge` response. Daemon emits
/// camelCase (`sessionId`); we accept both forms via `alias` to
/// stay compatible with any deployment that hasn't redeployed yet
/// (the daemon's older builds emitted snake_case before the
/// `#[serde(rename_all = "camelCase")]` annotation was added).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponseWire {
    #[serde(alias = "session_id")]
    session_id: String,
    data: ChallengeData,
}

#[derive(Debug, Deserialize)]
struct ChallengeData {
    challenge: String,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WebvhClient {
    /// Construct a client for a daemon REST URL. Rejects URLs whose
    /// scheme would send the bearer token / authenticate JWS over
    /// plaintext to a non-loopback host. See
    /// [`enforce_transport_security`] for the policy.
    ///
    /// `server_did` is the daemon's DID. The auth flow uses it for
    /// the DIDComm `to:` field (audience binding) and operator-facing
    /// error messages name it explicitly.
    pub fn new(server_url: &str, server_did: &str) -> Result<Self, AppError> {
        let parsed = Url::parse(server_url).map_err(|e| {
            AppError::Validation(format!("invalid webvh-server URL `{server_url}`: {e}"))
        })?;
        enforce_transport_security(&parsed, server_url)?;
        Ok(Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            server_did: server_did.to_string(),
            access_token: None,
        })
    }

    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    /// Run the full challenge → JWS-authenticate flow against the
    /// daemon, returning a fresh token pair. Does not mutate
    /// `self.access_token`; the caller chooses what to do with the
    /// returned tokens (typically persist via `webvh_store`).
    ///
    /// Errors map to typed `AppError` variants so the route /
    /// operation layer can surface the right hint to the operator:
    ///
    /// - daemon 401 on `/api/auth/` → `Authentication` (caller's
    ///   VTA DID is probably not in the daemon's ACL),
    /// - daemon 4xx other than 401 → `Validation`,
    /// - daemon 5xx → `Internal`,
    /// - network/parse failures → `Internal`.
    pub async fn authenticate(
        &self,
        identity: &VtaSigningIdentity<'_>,
    ) -> Result<TokenData, AppError> {
        let challenge = self.fetch_challenge(identity.vta_did).await?;

        let jws = build_authenticate_message(
            identity,
            &ChallengeContext {
                session_id: &challenge.session_id,
                challenge: &challenge.data.challenge,
                server_did: &self.server_did,
            },
            unix_now_secs(),
        )?;

        let url = format!("{}/api/auth/", self.server_url);
        info!(method = "POST", %url, "webvh: authenticating");
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(jws)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh authenticate request failed: {e}")))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(self.map_auth_failure(status, &body, identity.vta_did));
        }
        let parsed: TokenResponseWire = serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh authenticate response parse error: {e} (body: {body})"
            ))
        })?;
        Ok(parsed.data)
    }

    /// Redeem a refresh token against the daemon. Returns the rotated
    /// token pair. The daemon always rotates refresh tokens on use, so
    /// the returned `refresh_token` differs from the input — callers
    /// must persist the new one immediately.
    pub async fn refresh(
        &self,
        identity: &VtaSigningIdentity<'_>,
        refresh_token: &str,
    ) -> Result<TokenData, AppError> {
        let jws =
            build_refresh_message(identity, &self.server_did, refresh_token, unix_now_secs())?;
        let url = format!("{}/api/auth/refresh", self.server_url);
        info!(method = "POST", %url, "webvh: refreshing token");
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(jws)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh refresh request failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // Refresh failure is normal at end-of-lifetime — return
            // a typed `Authentication` so the caller can fall back to
            // a full re-authenticate instead of bubbling a 500.
            warn!(
                status = %status,
                vta_did = %identity.vta_did,
                "webvh refresh rejected by daemon",
            );
            return Err(AppError::Authentication(format!(
                "webvh-server {} rejected refresh token (status {status}): {body}",
                self.server_did,
            )));
        }
        let parsed: TokenResponseWire = serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh refresh response parse error: {e} (body: {body})"
            ))
        })?;
        Ok(parsed.data)
    }

    async fn fetch_challenge(&self, vta_did: &str) -> Result<ChallengeResponseWire, AppError> {
        let url = format!("{}/api/auth/challenge", self.server_url);
        debug!(method = "POST", %url, "webvh: fetching challenge");
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "did": vta_did }))
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("webvh challenge request failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::Internal(format!(
                "webvh-server {} POST /api/auth/challenge failed (status {status}): {body}",
                self.server_did,
            )));
        }
        serde_json::from_str(&body).map_err(|e| {
            AppError::Internal(format!(
                "webvh challenge response parse error: {e} (body: {body})"
            ))
        })
    }

    /// Map a non-2xx response from `/api/auth/` to a typed `AppError`.
    /// 401 specifically usually means the VTA's DID isn't in the
    /// daemon's ACL — surface that hint so the operator doesn't see
    /// a flat "internal error".
    fn map_auth_failure(&self, status: reqwest::StatusCode, body: &str, vta_did: &str) -> AppError {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return AppError::Authentication(format!(
                "webvh-server {server_did} rejected authentication for VTA DID `{vta_did}`. \
                 The most likely cause is that the VTA's DID is not in the daemon's ACL — \
                 ensure `{vta_did}` is granted access on the daemon. Daemon response: {body}",
                server_did = self.server_did,
            ));
        }
        if status.is_client_error() {
            return AppError::Validation(format!(
                "webvh-server {} rejected authentication (status {status}): {body}",
                self.server_did,
            ));
        }
        AppError::Internal(format!(
            "webvh-server {} authentication failed (status {status}): {body}",
            self.server_did,
        ))
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
        let c = WebvhClient::new("https://daemon.example", "did:web:daemon.example")
            .expect("https must be accepted");
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn https_url_trailing_slash_is_normalised() {
        // Match the existing trim_end_matches('/') behaviour so callers
        // can format paths with a leading slash without producing `//`.
        let c = WebvhClient::new("https://daemon.example/", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "https://daemon.example");
    }

    #[test]
    fn http_to_non_loopback_is_rejected() {
        // The core invariant: bearer tokens and the signed JWS must
        // not be sent over plaintext to a network-reachable host.
        assert_validation_err(
            WebvhClient::new("http://daemon.example", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn http_to_localhost_is_accepted_for_dev() {
        // Local-dev escape hatch — operator's daemon on the same host.
        let c = WebvhClient::new("http://localhost:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://localhost:8530");
    }

    #[test]
    fn http_to_127_0_0_1_is_accepted() {
        let c = WebvhClient::new("http://127.0.0.1:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.1:8530");
    }

    #[test]
    fn http_to_127_0_0_x_subnet_is_accepted() {
        // We use the IPv4 `is_loopback()` predicate, which covers all
        // of `127.0.0.0/8` — including dev shims like 127.0.0.2 that
        // operators use to bind multiple local services.
        let c = WebvhClient::new("http://127.0.0.5:8530", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "http://127.0.0.5:8530");
    }

    #[test]
    fn http_to_ipv6_loopback_is_accepted() {
        let c = WebvhClient::new("http://[::1]:8530", "did:web:daemon.example").unwrap();
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
            WebvhClient::new("http://0.0.0.0:8530", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        assert_validation_err(
            WebvhClient::new("ftp://daemon.example/", "did:web:daemon.example"),
            "unsupported scheme",
        );
    }

    #[test]
    fn ws_scheme_is_rejected() {
        // WebSocket isn't a wire we serve daemon REST over —
        // a daemon DID advertising ws:// is a misconfiguration.
        assert_validation_err(
            WebvhClient::new("ws://daemon.example/", "did:web:daemon.example"),
            "unsupported scheme",
        );
    }

    #[test]
    fn malformed_url_is_rejected() {
        assert_validation_err(
            WebvhClient::new("not-a-url", "did:web:daemon.example"),
            "invalid webvh-server URL",
        );
    }

    #[test]
    fn empty_url_is_rejected() {
        assert_validation_err(
            WebvhClient::new("", "did:web:daemon.example"),
            "invalid webvh-server URL",
        );
    }

    #[test]
    fn https_to_loopback_is_also_accepted() {
        // Operators running a TLS-terminating proxy locally
        // (mkcert + nginx, mitmproxy) should still work.
        let c = WebvhClient::new("https://localhost:8443", "did:web:daemon.example").unwrap();
        assert_eq!(c.server_url, "https://localhost:8443");
    }

    #[test]
    fn http_to_hostname_resembling_localhost_is_rejected() {
        // `localhost.evil.com` resolves wherever the attacker wants —
        // accept only the literal `localhost`, not anything ending in it.
        assert_validation_err(
            WebvhClient::new("http://localhost.evil.example", "did:web:daemon.example"),
            "refusing to dial webvh-server",
        );
    }

    // ── HTTP-flow tests against a wiremock daemon ──────────────────
    //
    // wiremock spins up a real local server bound to 127.0.0.1:<random>;
    // our HTTPS policy admits loopback HTTP so no insecure-test knob is
    // needed. Each test scopes its `MockServer` so the port is freed
    // between tests.

    use crate::webvh_auth::VtaSigningIdentity;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn signing_identity() -> ([u8; 32], String, String) {
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vta_did = "did:webvh:test:vta".to_string();
        let kid = format!("{vta_did}#key-0");
        (sk.to_bytes(), vta_did, kid)
    }

    fn token_response_json() -> serde_json::Value {
        // Daemon's wire shape (camelCase): wrapped in {sessionId, data}.
        json!({
            "sessionId": "auth-session-1",
            "data": {
                "accessToken": "access-token-A",
                "accessExpiresAt": 9_999_999_999u64,
                "refreshToken": "refresh-token-A",
                "refreshExpiresAt": 9_999_999_999u64,
            }
        })
    }

    fn challenge_response_json() -> serde_json::Value {
        json!({
            "sessionId": "chal-session-1",
            "data": { "challenge": "deadbeef" },
        })
    }

    #[tokio::test]
    async fn authenticate_round_trips_against_mock_daemon() {
        // Happy path: challenge → JWS authenticate → tokens.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .and(header("Content-Type", "application/json"))
            // The JWS payload is base64url-encoded; we can't match on
            // its inner content here. The wire-shape correctness of
            // the JWS is verified by the unit tests in `webvh_auth`.
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response_json()))
            .expect(1)
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let tokens = client
            .authenticate(&identity)
            .await
            .expect("authenticate must succeed");
        assert_eq!(tokens.access_token, "access-token-A");
        assert_eq!(tokens.refresh_token, "refresh-token-A");
        assert_eq!(tokens.access_expires_at, 9_999_999_999);
    }

    #[tokio::test]
    async fn authenticate_401_yields_typed_auth_error_with_acl_hint() {
        // Operator footgun: daemon's ACL doesn't include the VTA DID.
        // The CLI should print a corrective hint rather than a generic
        // "internal error". We assert the typed variant + the hint
        // substring.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(401).set_body_string("ACL denied"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let err = client.authenticate(&identity).await.unwrap_err();
        match err {
            AppError::Authentication(msg) => {
                assert!(
                    msg.contains("not in the daemon's ACL"),
                    "auth error should suggest the fix; got: {msg}"
                );
                assert!(
                    msg.contains(&vta_did),
                    "should name the VTA DID; got: {msg}"
                );
            }
            other => panic!("expected Authentication, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_500_yields_internal_not_auth_error() {
        // A 5xx is a daemon-side problem, not an auth problem — must
        // not look like "ACL needs updating."
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge_response_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let err = client.authenticate(&identity).await.unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "5xx should map to Internal, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn refresh_returns_rotated_tokens() {
        // The daemon rotates the refresh token on use. The returned
        // refresh_token must be the daemon's new value, not echoed
        // from the input.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/refresh"))
            .and(header("Content-Type", "application/json"))
            // The old refresh token rides inside the JWS body; we
            // can't match on encoded contents from a wiremock matcher.
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sessionId": "refreshed-session",
                "data": {
                    "accessToken": "new-access",
                    "accessExpiresAt": 1_900_000_000u64,
                    "refreshToken": "rotated-refresh",
                    "refreshExpiresAt": 1_900_999_999u64,
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };

        let tokens = client
            .refresh(&identity, "old-refresh")
            .await
            .expect("refresh must succeed");
        assert_eq!(tokens.access_token, "new-access");
        assert_eq!(
            tokens.refresh_token, "rotated-refresh",
            "refresh must return rotated token, not echo input"
        );
    }

    #[tokio::test]
    async fn refresh_failure_yields_typed_authentication_error() {
        // End-of-lifetime case: refresh token expired or replayed.
        // Callers fall back to full re-auth; the typed variant tells
        // them to.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/refresh"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid refresh token"))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let err = client
            .refresh(&identity, "stale-refresh")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::Authentication(_)),
            "expired refresh must map to Authentication, got: {err:?}"
        );
    }

    #[test]
    fn token_data_debug_redacts_secret_fields() {
        // Same protection as `WebvhServerAuthRecord` — accidental
        // `tracing::error!(?tokens)` must not log the access or
        // refresh token bytes. Expiry timestamps stay visible (not
        // secret, useful for freshness diagnostics).
        let td = TokenData {
            access_token: "should-not-appear-XXXX".into(),
            access_expires_at: 1234,
            refresh_token: "also-secret-YYYY".into(),
            refresh_expires_at: 5678,
        };
        let dbg = format!("{td:?}");
        assert!(!dbg.contains("XXXX"), "access_token must not leak: {dbg}");
        assert!(!dbg.contains("YYYY"), "refresh_token must not leak: {dbg}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("1234"));
        assert!(dbg.contains("5678"));
    }

    #[tokio::test]
    async fn authenticate_uses_camelcase_sessionid_from_daemon() {
        // The daemon's `ChallengeResponse` has
        // `#[serde(rename_all = "camelCase")]` so the wire field is
        // `sessionId`. Regression guard: a future tweak that switched
        // our deserializer to snake_case-only would silently break
        // the auth handshake.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/challenge"))
            // Note: explicit camelCase `sessionId`, not snake_case.
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sessionId": "camel-id",
                "data": { "challenge": "cafebabe" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_response_json()))
            .mount(&server)
            .await;

        let (private, vta_did, kid) = signing_identity();
        let client = WebvhClient::new(&server.uri(), "did:web:daemon-mock.example").unwrap();
        let identity = VtaSigningIdentity {
            vta_did: &vta_did,
            signing_kid: &kid,
            private_key: &private,
        };
        let _ = client
            .authenticate(&identity)
            .await
            .expect("must accept camelCase sessionId");
    }
}
