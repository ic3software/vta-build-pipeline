use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vta_sdk::protocols::auth::{
    AuthenticateData, AuthenticateResponse, ChallengeData, ChallengeRequest, ChallengeResponse,
};

use crate::acl::{Role, check_acl, check_acl_full};
use crate::auth::session::{
    Session, SessionState, delete_session, get_session, get_session_by_refresh, list_sessions,
    now_epoch, store_refresh_index, store_session, update_session,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
use crate::server::AppState;
use tracing::{info, warn};

// ---------- POST /auth/challenge ----------

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // ACL enforcement: DID must be in the ACL to request a challenge
    let acl = state.acl_ks.clone();
    check_acl(&acl, &req.did).await?;

    let session_id = Uuid::new_v4().to_string();

    // Generate 32-byte random challenge as hex
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);

    let session = Session {
        session_id: session_id.clone(),
        did: req.did,
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        // VTC has no TEE attestation surface — always false here.
        tee_attested: false,
    };

    let sessions = state.sessions_ks.clone();
    store_session(&sessions, &session).await?;

    info!(did = %session.did, session_id = %session.session_id, "auth challenge issued");

    Ok(Json(ChallengeResponse {
        session_id,
        data: ChallengeData {
            challenge,
            tee_attestation: None,
        },
    }))
}

// ---------- POST /auth/ ----------

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    Ok(Json(authenticate_and_mint(&state, &body).await?))
}

/// Core authenticate + mint logic shared by `POST /v1/auth/` and
/// `POST /v1/auth/admin-login`. Both endpoints accept the same
/// DIDComm-packed authentication message; `admin-login`
/// additionally returns `Set-Cookie` headers so the admin SPA can
/// carry a cookie session beside the bearer token.
async fn authenticate_and_mint(
    state: &AppState,
    body: &str,
) -> Result<AuthenticateResponse, AppError> {
    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Authentication("ATM not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = atm
        .unpack(body)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.typ != "https://affinidi.com/atm/1.0/authenticate" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    // Extract challenge and session_id from body
    let challenge = msg.body["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?;
    let session_id = msg.body["session_id"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?;

    // Validate sender DID
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    // Look up session and validate
    let sessions = state.sessions_ks.clone();
    let mut session = get_session(&sessions, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::ChallengeSent {
        warn!(session_id, "authentication rejected: session replay");
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }
    if session.challenge != challenge {
        warn!(session_id, "authentication rejected: challenge mismatch");
        return Err(AppError::Authentication("challenge mismatch".into()));
    }
    // Match the DID (compare base DID, ignoring any fragment)
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);
    if session.did != sender_base {
        warn!(session_id, sender = %sender_base, expected = %session.did, "authentication rejected: DID mismatch");
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Check challenge TTL
    {
        let config = state.config.read().await;
        let challenge_ttl = config.auth.challenge_ttl;
        drop(config);
        if now_epoch().saturating_sub(session.created_at) > challenge_ttl {
            warn!(session_id, "authentication rejected: challenge expired");
            return Err(AppError::Authentication("challenge expired".into()));
        }
    }

    // Look up ACL entry to get role and allowed contexts for the token
    let acl = state.acl_ks.clone();
    let (role, allowed_contexts) = check_acl_full(&acl, &session.did).await?;

    // Generate tokens
    let config = state.config.read().await;
    let access_expiry = config.auth.access_token_expiry;
    let refresh_expiry = config.auth.refresh_token_expiry;
    drop(config);

    let claims = jwt_keys.new_claims(
        session.did.clone(),
        session.session_id.clone(),
        role.to_string(),
        allowed_contexts,
        access_expiry,
        false,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;

    // Update session to Authenticated
    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    update_session(&sessions, &session).await?;

    // Store reverse refresh index
    store_refresh_index(&sessions, &refresh_token, &session.session_id).await?;

    info!(did = %session.did, session_id = %session.session_id, "authentication successful");

    Ok(AuthenticateResponse {
        session_id: Some(session.session_id),
        data: AuthenticateData {
            access_token,
            access_expires_at,
            refresh_token: Some(refresh_token),
            refresh_expires_at: Some(refresh_expires_at),
        },
    })
}

// ---------- POST /auth/admin-login ----------

/// `POST /v1/auth/admin-login` (Phase 5 M5.2.3).
///
/// Same DIDComm-packed authentication flow as `POST /v1/auth/`,
/// but the response additionally carries `Set-Cookie` headers so
/// the admin SPA can drive subsequent requests via the cookie
/// session:
///
/// - `vtc_admin_session=<jwt>; Path=/admin; SameSite=Strict;
///   Secure; HttpOnly` — the access token JWT, scoped to the
///   admin UX path so public-website JS on the same origin can't
///   read it.
/// - `csrf=<random>; Path=/; SameSite=Strict; Secure` (HttpOnly:
///   **false** so SPA JS can mirror the value to the
///   `X-CSRF-Token` header for the double-submit check in
///   `routing::csrf`).
///
/// Programmatic clients (cnm-cli, DIDComm bridges) keep using
/// `POST /v1/auth/` — same JWT shape, no cookie side effects.
pub async fn admin_login(
    State(state): State<AppState>,
    body: String,
) -> Result<axum::response::Response, AppError> {
    use axum::http::HeaderValue;
    use axum::http::header::SET_COOKIE;
    use axum::response::IntoResponse;

    let resp = authenticate_and_mint(&state, &body).await?;

    let max_age = resp
        .data
        .access_expires_at
        .saturating_sub(now_epoch())
        .max(1);

    // Generate a 32-byte CSRF token, hex-encoded. The cookie is
    // JS-readable (HttpOnly off) so the SPA can echo it back via
    // the `X-CSRF-Token` header on mutating requests.
    use rand::RngExt;
    let mut csrf_bytes = [0u8; 32];
    rand::rng().fill(&mut csrf_bytes);
    let csrf = hex::encode(csrf_bytes);

    let session_cookie = build_session_cookie(&resp.data.access_token, max_age);
    let csrf_cookie = build_csrf_cookie(&csrf, max_age);

    let session_cookie_hv = HeaderValue::try_from(session_cookie)
        .map_err(|e| AppError::Internal(format!("invalid session cookie value: {e}")))?;
    let csrf_cookie_hv = HeaderValue::try_from(csrf_cookie)
        .map_err(|e| AppError::Internal(format!("invalid csrf cookie value: {e}")))?;

    let mut response = Json(resp).into_response();
    let headers = response.headers_mut();
    headers.append(SET_COOKIE, session_cookie_hv);
    headers.append(SET_COOKIE, csrf_cookie_hv);

    Ok(response)
}

/// Build the `vtc_admin_session` cookie value. Exposed as a pure
/// helper so cookie-isolation invariants (Path=/admin,
/// SameSite=Strict, Secure, HttpOnly) can be unit-tested
/// without standing up the full DIDComm authenticate flow.
fn build_session_cookie(access_token: &str, max_age: u64) -> String {
    format!(
        "{name}={access_token}; Path=/admin; Max-Age={max_age}; SameSite=Strict; Secure; HttpOnly",
        name = vti_common::auth::extractor::ADMIN_SESSION_COOKIE,
    )
}

/// Build the companion CSRF cookie. `HttpOnly` is intentionally
/// **not** set — the SPA needs to read this from
/// `document.cookie` and mirror its value into the
/// `X-CSRF-Token` header on every mutating request.
fn build_csrf_cookie(csrf: &str, max_age: u64) -> String {
    format!("csrf={csrf}; Path=/; Max-Age={max_age}; SameSite=Strict; Secure")
}

#[cfg(test)]
mod cookie_format_tests {
    use super::*;

    /// Phase 5 M5.3.1 cookie-scope isolation invariant — the
    /// admin session cookie MUST carry `Path=/admin` so public-
    /// website JS on the same origin cannot read it.
    #[test]
    fn session_cookie_path_is_admin() {
        let c = build_session_cookie("jwt.token.value", 900);
        assert!(c.contains("Path=/admin"), "got {c}");
        assert!(!c.contains("Path=/;"), "must not be root-scoped: {c}");
    }

    #[test]
    fn session_cookie_has_security_flags() {
        let c = build_session_cookie("jwt.token.value", 900);
        // All three flags are load-bearing — losing any one is
        // a CSRF / cookie-theft / TLS-stripping regression.
        assert!(c.contains("HttpOnly"), "got {c}");
        assert!(c.contains("Secure"), "got {c}");
        assert!(c.contains("SameSite=Strict"), "got {c}");
    }

    #[test]
    fn csrf_cookie_is_root_scoped_but_not_httponly() {
        let c = build_csrf_cookie("abc123", 900);
        // CSRF cookie is intentionally readable by JS so the
        // SPA can mirror it into `X-CSRF-Token`.
        assert!(c.contains("Path=/"), "got {c}");
        assert!(
            !c.contains("HttpOnly"),
            "CSRF cookie must be JS-readable: {c}"
        );
        assert!(c.contains("Secure"), "got {c}");
        assert!(c.contains("SameSite=Strict"), "got {c}");
    }

    #[test]
    fn session_cookie_uses_canonical_name() {
        let c = build_session_cookie("t", 1);
        assert!(
            c.starts_with(&format!(
                "{}=",
                vti_common::auth::extractor::ADMIN_SESSION_COOKIE
            )),
            "got {c}"
        );
    }
}

// ---------- POST /auth/refresh ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub session_id: String,
    pub data: RefreshData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshData {
    pub access_token: String,
    pub access_expires_at: u64,
}

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<RefreshResponse>, AppError> {
    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Authentication("ATM not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = atm
        .unpack(&body)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.typ != "https://affinidi.com/atm/1.0/authenticate/refresh" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    // Extract refresh_token from body
    let refresh_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?;

    // Look up session by refresh token
    let sessions = state.sessions_ks.clone();
    let session_id = get_session_by_refresh(&sessions, refresh_token)
        .await?
        .ok_or_else(|| AppError::Authentication("refresh token not found".into()))?;

    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("session not authenticated".into()));
    }

    // Verify refresh token hasn't expired
    if let Some(expires_at) = session.refresh_expires_at
        && now_epoch() > expires_at
    {
        return Err(AppError::Authentication("refresh token expired".into()));
    }

    // Look up current ACL role and contexts (propagates changes at refresh time)
    let acl = state.acl_ks.clone();
    let (role, allowed_contexts) = check_acl_full(&acl, &session.did).await?;

    // Generate new access token
    let config = state.config.read().await;
    let access_expiry = config.auth.access_token_expiry;
    drop(config);

    let claims = jwt_keys.new_claims(
        session.did.clone(),
        session.session_id.clone(),
        role.to_string(),
        allowed_contexts,
        access_expiry,
        false,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    info!(did = %session.did, session_id = %session.session_id, "token refreshed");

    Ok(Json(RefreshResponse {
        session_id: session.session_id,
        data: RefreshData {
            access_token,
            access_expires_at,
        },
    }))
}

// ---------- GET /auth/sessions ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub session_id: String,
    pub did: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_expires_at: Option<u64>,
}

impl From<Session> for SessionSummary {
    fn from(s: Session) -> Self {
        Self {
            session_id: s.session_id,
            did: s.did,
            state: s.state,
            created_at: s.created_at,
            refresh_expires_at: s.refresh_expires_at,
        }
    }
}

pub async fn session_list(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionSummary>>, AppError> {
    let sessions = state.sessions_ks.clone();
    let all = list_sessions(&sessions).await?;
    let summaries: Vec<SessionSummary> = all.into_iter().map(SessionSummary::from).collect();
    info!(caller = %_auth.0.did, count = summaries.len(), "sessions listed");
    Ok(Json(summaries))
}

// ---------- DELETE /auth/sessions/{session_id} ----------

pub async fn revoke_session(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let sessions = state.sessions_ks.clone();
    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("session not found: {session_id}")))?;

    // Allow if caller owns the session or is admin
    if session.did != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "cannot revoke another user's session".into(),
        ));
    }

    delete_session(&sessions, &session_id).await?;
    info!(caller = %auth.did, session_id = %session_id, "session revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /auth/sessions?did=X ----------

#[derive(Debug, Deserialize)]
pub struct RevokeByDidQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeByDidResponse {
    pub revoked: u64,
}

pub async fn revoke_sessions_by_did(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<RevokeByDidQuery>,
) -> Result<Json<RevokeByDidResponse>, AppError> {
    let sessions = state.sessions_ks.clone();
    let all = list_sessions(&sessions).await?;
    let mut revoked = 0u64;

    for session in all {
        if session.did == query.did {
            delete_session(&sessions, &session.session_id).await?;
            revoked += 1;
        }
    }

    info!(caller = %_auth.0.did, target_did = %query.did, revoked, "sessions revoked by DID");
    Ok(Json(RevokeByDidResponse { revoked }))
}
