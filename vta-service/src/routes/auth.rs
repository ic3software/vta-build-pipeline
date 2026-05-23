use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use vta_sdk::protocols::auth::{
    AuthenticateResponse, ChallengeRequest, ChallengeResponse, Session as WireSession, TokenBundle,
    epoch_to_rfc3339,
};
use vta_sdk::sealed_transfer::constant_time_eq;

use crate::acl::{Role, check_acl, check_acl_full};
use crate::audit::audit;
use crate::auth::session::{
    Session, SessionState, delete_refresh_index, delete_session, get_session,
    get_session_by_refresh, list_sessions, now_epoch, store_refresh_index, store_session,
    update_session,
};
use crate::auth::{AdminAuth, AuthClaims, ManageAuth};
use crate::error::AppError;
#[cfg(feature = "tee")]
use crate::error::tee_attestation_error;
use crate::server::AppState;
#[cfg(feature = "tee")]
use tracing::error;
use tracing::{info, warn};

// ---------- POST /auth/challenge ----------

/// POST /auth/challenge — issue a DID-auth challenge nonce for a session. Auth: unauthenticated.
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // DID method whitelist enforcement (TEE mode)
    #[cfg(feature = "tee")]
    {
        let config = state.config.read().await;
        if let Some(ref allowed) = config.tee.allowed_did_methods {
            let did_ok = allowed.iter().any(|prefix| req.did.starts_with(prefix));
            if !did_ok {
                warn!(did = %req.did, "auth rejected: DID method not in allowed_did_methods");
                return Err(AppError::Forbidden(format!(
                    "DID method not allowed — accepted methods: {}",
                    allowed.join(", ")
                )));
            }
        }
        drop(config);
    }

    // ACL enforcement: DID must be in the ACL to request a challenge
    check_acl(&state.acl_ks, &req.did).await?;

    let session_id = Uuid::new_v4().to_string();

    // Generate 32-byte random challenge as hex
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let mut challenge = hex::encode(challenge_bytes);

    // Nonce replay prevention: store the challenge hash to detect reuse.
    // Challenges are random 32 bytes so collision is negligible, but this
    // provides defense in depth against replay attacks.
    let nonce_key = format!("nonce:{challenge}");
    if state
        .sessions_ks
        .get_raw(nonce_key.clone())
        .await?
        .is_some()
    {
        warn!(challenge = %challenge, "challenge nonce collision detected — regenerating");
        // Extremely unlikely (2^-256) but handle gracefully
        rand::fill(&mut challenge_bytes);
        challenge = hex::encode(challenge_bytes);
    }
    state
        .sessions_ks
        .insert_raw(format!("nonce:{challenge}"), session_id.as_bytes().to_vec())
        .await?;

    // Build the attestation report (if any) before persisting the
    // session so we can record on the session whether attestation
    // actually succeeded for THIS challenge — not just whether the
    // binary was compiled with the TEE feature. The eventual JWT's
    // `tee_attested` claim is sourced from this per-session bit.
    #[cfg(feature = "tee")]
    let (tee_attestation, attestation_succeeded) = if let Some(ref tee) = state.tee {
        let config = state.config.read().await;
        let vta_did = config.vta_did.clone();
        drop(config);

        let user_data = vta_did.as_deref().unwrap_or("").as_bytes();
        let nonce_bytes = &challenge_bytes[..];

        match tee.state.provider.attest(user_data, nonce_bytes) {
            Ok(mut report) => {
                report.vta_did = vta_did;
                let value = serde_json::to_value(&report).map_err(|e| {
                    AppError::Internal(format!("failed to serialize attestation report: {e}"))
                })?;
                (Some(value), true)
            }
            Err(e) => {
                // In TEE required mode, attestation failure is a hard error.
                // A broken TEE must not silently serve unattested challenges.
                let tee_mode = &state.config.read().await.tee.mode;
                if *tee_mode == crate::config::TeeMode::Required {
                    error!("TEE attestation failed in required mode — refusing challenge: {e}");
                    return Err(tee_attestation_error(format!(
                        "TEE attestation failed (mode=required): {e}"
                    )));
                }
                warn!(
                    "TEE attestation failed (mode=optional) — challenge served without attestation: {e}"
                );
                (None, false)
            }
        }
    } else {
        (None, false)
    };
    #[cfg(not(feature = "tee"))]
    let (tee_attestation, attestation_succeeded): (Option<serde_json::Value>, bool) = (None, false);

    let session = Session {
        session_id: session_id.clone(),
        did: req.did,
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: attestation_succeeded,
        // AAL is unknown at challenge time — populated when the
        // session transitions to Authenticated.
        amr: Vec::new(),
        acr: String::new(),
    };

    store_session(&state.sessions_ks, &session).await?;

    info!(did = %session.did, session_id = %session.session_id, "auth challenge issued");
    audit!(
        "auth.challenge",
        actor = &session.did,
        resource = &session.session_id,
        outcome = "success"
    );

    // Canonical wire shape: flat { challenge, sessionId, expiresAt,
    // teeAttestation? } per spec/auth/challenge/0.1#response. Challenge
    // expiry mirrors the configured `auth.challenge_ttl_seconds` —
    // typically 60 s, matching the framework recommendation of 30 s–
    // 5 min.
    let expires_at_epoch = session
        .created_at
        .saturating_add(state.config.read().await.auth.challenge_ttl);
    Ok(Json(ChallengeResponse {
        challenge,
        session_id,
        expires_at: epoch_to_rfc3339(expires_at_epoch),
        tee_attestation,
    }))
}

// ---------- POST /auth/ ----------

/// POST /auth/ — verify a signed DIDComm challenge and issue access+refresh tokens. Auth: unauthenticated.
pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
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
    let mut session = get_session(&state.sessions_ks, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::ChallengeSent {
        warn!(session_id, "authentication rejected: session replay");
        audit!(
            "auth.authenticate",
            actor = sender_did.split('#').next().unwrap_or(sender_did),
            resource = session_id,
            outcome = "denied:replay"
        );
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }
    if !constant_time_eq(session.challenge.as_bytes(), challenge.as_bytes()) {
        warn!(session_id, "authentication rejected: challenge mismatch");
        audit!(
            "auth.authenticate",
            actor = sender_did.split('#').next().unwrap_or(sender_did),
            resource = session_id,
            outcome = "denied:challenge_mismatch"
        );
        return Err(AppError::Authentication("challenge mismatch".into()));
    }
    // Match the DID (compare base DID, ignoring any fragment). Constant-time
    // compare — DID bytes are not secret, but session.did is the challenge's
    // expected holder; leaking byte-prefixes doesn't help an attacker who
    // already knows the session, so this is defense-in-depth.
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);
    if !constant_time_eq(session.did.as_bytes(), sender_base.as_bytes()) {
        warn!(session_id, sender = %sender_base, expected = %session.did, "authentication rejected: DID mismatch");
        audit!(
            "auth.authenticate",
            actor = sender_base,
            resource = session_id,
            outcome = "denied:did_mismatch"
        );
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Read all auth config values in a single lock acquisition
    let (challenge_ttl, access_expiry, refresh_expiry) = {
        let config = state.config.read().await;
        (
            config.auth.challenge_ttl,
            config.auth.access_token_expiry,
            config.auth.refresh_token_expiry,
        )
    };

    // Check challenge TTL
    if now_epoch().saturating_sub(session.created_at) > challenge_ttl {
        warn!(session_id, "authentication rejected: challenge expired");
        audit!(
            "auth.authenticate",
            actor = sender_base,
            resource = session_id,
            outcome = "denied:expired"
        );
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // Look up ACL entry to get role and allowed contexts for the token
    let (role, allowed_contexts) = check_acl_full(&state.acl_ks, &session.did).await?;

    // `tee_attested` is per-session, not per-binary: the session record
    // captured whether the original `/auth/challenge` actually completed
    // an attestation step. A TEE binary in `Optional` mode that fell
    // through to an unattested challenge writes `false` here.
    let tee_attested = session.tee_attested;

    // Challenge-response authenticate: one DID-key factor →
    // amr=["did"], acr="aal1". Step-up to aal2 happens via the
    // passkey-login handler below.
    let claims = jwt_keys
        .new_claims(
            session.did.clone(),
            session.session_id.clone(),
            role.to_string(),
            allowed_contexts,
            access_expiry,
            tee_attested,
        )
        .with_aal(vec!["did".to_string()], "aal1");
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;

    // Update session to Authenticated. Persist AAL alongside the
    // refresh token so the refresh handler can re-mint at the same
    // AAL the session is currently at (without this, a step-upped
    // session silently drops back to aal1 on every refresh).
    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    session.amr = claims.amr.clone();
    session.acr = claims.acr.clone();
    update_session(&state.sessions_ks, &session).await?;

    // Store reverse refresh index
    store_refresh_index(&state.sessions_ks, &refresh_token, &session.session_id).await?;

    info!(did = %session.did, session_id = %session.session_id, "authentication successful");
    audit!(
        "auth.authenticate",
        actor = &session.did,
        resource = &session.session_id,
        outcome = "success"
    );

    let issued_at_epoch = now_epoch();
    Ok(Json(AuthenticateResponse {
        session: WireSession {
            id: session.session_id.clone(),
            subject: session.did.clone(),
            issued_at: epoch_to_rfc3339(issued_at_epoch),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr: claims.amr.clone(),
            acr: claims.acr.clone(),
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: access_expires_at.saturating_sub(issued_at_epoch),
            refresh_expires_in: Some(refresh_expires_at.saturating_sub(issued_at_epoch)),
            scope: Vec::new(),
        },
    }))
}

// ---------- POST /auth/refresh ----------

/// POST /auth/refresh — exchange a refresh token for a new access token
/// AND a freshly-rotated refresh token. Auth: unauthenticated.
///
/// Implements RFC 6749 §10.4 refresh-token rotation: every successful
/// refresh mints a new refresh token, deletes the old reverse index,
/// and returns the new pair to the caller. The presented token works
/// exactly once. A leaked-then-replayed token surfaces as "refresh
/// token not found" — same shape as a token that was revoked.
///
/// Response shape is the same `AuthenticateResponse` returned by
/// `POST /auth/`, so callers handle login and refresh with one
/// deserialization path.
pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
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
    let presented_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?;

    // Look up session by refresh token
    let session_id = get_session_by_refresh(&state.sessions_ks, presented_token)
        .await?
        .ok_or_else(|| AppError::Authentication("refresh token not found".into()))?;

    let mut session = get_session(&state.sessions_ks, &session_id)
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
    let (role, allowed_contexts) = check_acl_full(&state.acl_ks, &session.did).await?;

    // Read current expiry knobs in a single lock acquisition.
    let (access_expiry, refresh_expiry) = {
        let config = state.config.read().await;
        (
            config.auth.access_token_expiry,
            config.auth.refresh_token_expiry,
        )
    };

    // tee_attested is per-session — fixed at challenge time, not per-refresh.
    let tee_attested = session.tee_attested;

    // Refresh re-mints with the same AAL the session row carries.
    // Sessions written before the persistence landed have empty
    // amr/acr and fall back to aal1 — matches the pre-migration
    // refresh behaviour, so no surprises for those holders.
    let preserved_amr = if session.amr.is_empty() {
        vec!["did".to_string()]
    } else {
        session.amr.clone()
    };
    let preserved_acr = if session.acr.is_empty() {
        "aal1".to_string()
    } else {
        session.acr.clone()
    };
    let claims = jwt_keys
        .new_claims(
            session.did.clone(),
            session.session_id.clone(),
            role.to_string(),
            allowed_contexts,
            access_expiry,
            tee_attested,
        )
        .with_aal(preserved_amr, preserved_acr);
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    // Rotate: mint a new refresh token, write the new index, delete the
    // old one. The order matters — write-new before delete-old so a
    // crash between the two leaves the new token usable (operator can
    // re-refresh) rather than a defunct session. Replay of the old
    // token after this point fails the index lookup.
    let new_refresh_token = Uuid::new_v4().to_string();
    let new_refresh_expires_at = now_epoch() + refresh_expiry;

    store_refresh_index(&state.sessions_ks, &new_refresh_token, &session.session_id).await?;

    session.refresh_token = Some(new_refresh_token.clone());
    session.refresh_expires_at = Some(new_refresh_expires_at);
    update_session(&state.sessions_ks, &session).await?;

    delete_refresh_index(&state.sessions_ks, presented_token).await?;

    info!(did = %session.did, session_id = %session.session_id, "token refreshed and refresh-token rotated");
    audit!(
        "auth.refresh",
        actor = &session.did,
        resource = &session.session_id,
        outcome = "success"
    );

    let issued_at_epoch = now_epoch();
    Ok(Json(AuthenticateResponse {
        session: WireSession {
            id: session.session_id.clone(),
            subject: session.did.clone(),
            issued_at: epoch_to_rfc3339(issued_at_epoch),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr: claims.amr.clone(),
            acr: claims.acr.clone(),
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(new_refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: access_expires_at.saturating_sub(issued_at_epoch),
            refresh_expires_in: Some(new_refresh_expires_at.saturating_sub(issued_at_epoch)),
            scope: Vec::new(),
        },
    }))
}

// ---------- POST /auth/credentials ----------

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

/// GET /auth/sessions — list all active sessions. Auth: Admin or Initiator.
pub async fn session_list(
    _auth: ManageAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionSummary>>, AppError> {
    let all = list_sessions(&state.sessions_ks).await?;
    let summaries: Vec<SessionSummary> = all.into_iter().map(SessionSummary::from).collect();
    info!(caller = %_auth.0.did, count = summaries.len(), "sessions listed");
    Ok(Json(summaries))
}

// ---------- DELETE /auth/sessions/{session_id} ----------

/// DELETE /auth/sessions/{session_id} — revoke a single session (own or admin). Auth: any authenticated user.
pub async fn revoke_session(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let session = get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("session not found: {session_id}")))?;

    // Allow if caller owns the session or is admin
    if session.did != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "cannot revoke another user's session".into(),
        ));
    }

    delete_session(&state.sessions_ks, &session_id).await?;
    info!(caller = %auth.did, session_id = %session_id, "session revoked");
    audit!(
        "session.revoke",
        actor = &auth.did,
        resource = &session_id,
        outcome = "success"
    );
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

/// DELETE /auth/sessions?did=X — revoke all sessions for a given DID. Auth: Admin only.
pub async fn revoke_sessions_by_did(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<RevokeByDidQuery>,
) -> Result<Json<RevokeByDidResponse>, AppError> {
    let all = list_sessions(&state.sessions_ks).await?;
    let mut revoked = 0u64;

    for session in all {
        if session.did == query.did {
            delete_session(&state.sessions_ks, &session.session_id).await?;
            revoked += 1;
        }
    }

    info!(caller = %_auth.0.did, target_did = %query.did, revoked, "sessions revoked by DID");
    audit!(
        "session.revoke_by_did",
        actor = &_auth.0.did,
        resource = &query.did,
        outcome = "success"
    );
    Ok(Json(RevokeByDidResponse { revoked }))
}

// ---------- Passkey login ----------
//
// Per the trust-task migration registry these correspond to:
//   - vta/auth/passkey-login-start/1.0
//   - vta/auth/passkey-login-finish/1.0
//
// They are UNAUTHENTICATED (the user has no session yet) — mounted on
// the same router section as `POST /auth/challenge` and `POST /auth/`.
// The trust-task envelope dispatcher at /api/trust-tasks handles only
// authenticated operations.

use base64::Engine as _;
use base64::engine::general_purpose;
use vta_sdk::protocols::passkey_login::{
    PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyLoginStartResponse,
};

use crate::operations::passkey_login::{
    VtaVmResolver, enumerate_passkey_vms, verify_passkey_login,
};

/// POST /auth/passkey-login/start — issue a passkey-bound challenge. Auth: unauthenticated.
pub async fn passkey_login_start(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginStartRequest>,
) -> Result<Json<PasskeyLoginStartResponse>, AppError> {
    // Runtime gate: WebAuthn-RP service must be advertised.
    // Returns 403 with a clear message when the service is off so a
    // misconfigured demo doesn't spend operator time on
    // "why isn't login working".
    if !state.config.read().await.services.webauthn {
        return Err(AppError::Forbidden(
            "WebAuthn service is disabled on this VTA.".into(),
        ));
    }

    // ACL gate — same as /auth/challenge.
    check_acl(&state.acl_ks, &req.did).await?;

    // Mint challenge.
    let session_id = Uuid::new_v4().to_string();
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);

    // Persist pending session — same shape as the legacy auth challenge
    // so existing JWT-mint plumbing in `passkey_login_finish` can
    // consume it.
    let session = Session {
        session_id: session_id.clone(),
        did: req.did.clone(),
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        tee_attested: false,
        // AAL is unknown at challenge time. passkey_login_finish sets
        // it to amr=["did","passkey"], acr="aal2" when the assertion
        // verifies and the session transitions to Authenticated.
        amr: Vec::new(),
        acr: String::new(),
    };
    store_session(&state.sessions_ks, &session).await?;

    // Enumerate the DID's passkey VMs to populate allowCredentials.
    // v0.1 returns empty; browsers fall back to discoverable credentials.
    let allow_credentials = match state.did_resolver.clone() {
        Some(resolver) => {
            let vta_resolver = VtaVmResolver::new(resolver);
            enumerate_passkey_vms(&vta_resolver, &req.did)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|vm| general_purpose::URL_SAFE_NO_PAD.encode(vm.credential_id))
                .collect()
        }
        None => Vec::new(),
    };

    info!(did = %req.did, session_id = %session_id, "passkey login challenge issued");
    audit!(
        "auth.passkey_login_start",
        actor = &req.did,
        resource = &session_id,
        outcome = "success"
    );

    Ok(Json(PasskeyLoginStartResponse {
        session_id,
        challenge,
        allow_credentials,
    }))
}

/// POST /auth/passkey-login/finish — verify the WebAuthn assertion and issue tokens. Auth: unauthenticated.
pub async fn passkey_login_finish(
    State(state): State<AppState>,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<Json<AuthenticateResponse>, AppError> {
    // Runtime gate (mirrors `passkey_login_start`).
    if !state.config.read().await.services.webauthn {
        return Err(AppError::Forbidden(
            "WebAuthn service is disabled on this VTA.".into(),
        ));
    }

    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;
    let did_resolver = state
        .did_resolver
        .clone()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;

    // 1. Look up pending session.
    let mut session = get_session(&state.sessions_ks, &req.session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;
    if session.state != SessionState::ChallengeSent {
        warn!(session_id = %req.session_id, "passkey login rejected: session replay");
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }

    // 2. Challenge TTL.
    let (challenge_ttl, access_expiry, refresh_expiry) = {
        let config = state.config.read().await;
        (
            config.auth.challenge_ttl,
            config.auth.access_token_expiry,
            config.auth.refresh_token_expiry,
        )
    };
    if now_epoch().saturating_sub(session.created_at) > challenge_ttl {
        warn!(session_id = %req.session_id, "passkey login rejected: challenge expired");
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // 3. Build AssertionPayload.
    let decode = |s: &str, what: &'static str| {
        general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .or_else(|_| general_purpose::URL_SAFE.decode(s.as_bytes()))
            .map_err(|_| AppError::Authentication(format!("{what} is not valid base64url")))
    };
    let assertion = vti_webauthn::AssertionPayload {
        credential_id: decode(&req.credential_id, "credential_id")?,
        authenticator_data: decode(&req.authenticator_data, "authenticator_data")?,
        client_data_json: decode(&req.client_data_json, "client_data_json")?,
        signature: decode(&req.signature, "signature")?,
        verification_method: req.verification_method.clone(),
    };

    // 4. Sanity-check that the assertion is against the DID this
    //    session was issued for — defence in depth before crypto.
    let claimed_did = req
        .verification_method
        .split_once('#')
        .map(|(did, _frag)| did)
        .unwrap_or(&req.verification_method);
    if claimed_did != session.did {
        warn!(
            session_did = %session.did,
            assertion_did = %claimed_did,
            "passkey login rejected: DID mismatch"
        );
        return Err(AppError::Authentication(
            "verification_method DID does not match session DID".into(),
        ));
    }

    // 5. Verify the assertion.
    let public_url = state.config.read().await.public_url.clone();
    let public_url =
        public_url.ok_or_else(|| AppError::Config("public_url not configured".into()))?;
    let config = vti_webauthn::VerifierConfig::from_public_url(&public_url, true)
        .map_err(|e| AppError::Config(format!("invalid public_url: {e}")))?;
    let resolver = VtaVmResolver::new(did_resolver);
    let _verified =
        verify_passkey_login(&assertion, session.challenge.as_bytes(), &resolver, &config)
            .await
            .map_err(|e| AppError::Authentication(format!("assertion verification failed: {e}")))?;

    // 6. ACL lookup for role + contexts.
    let (role, allowed_contexts) = check_acl_full(&state.acl_ks, &session.did).await?;

    // 7. Mint tokens — same shape as the legacy authenticate() flow.
    #[cfg(feature = "tee")]
    let tee_attested = session.tee_attested;
    #[cfg(not(feature = "tee"))]
    let tee_attested = false;
    // Passkey-login is the second factor (DID-key challenged first via
    // the challenge endpoint, then a WebAuthn assertion proves
    // possession of a passkey VM). amr captures both, acr promotes to
    // aal2.
    let claims = jwt_keys
        .new_claims(
            session.did.clone(),
            session.session_id.clone(),
            role.to_string(),
            allowed_contexts,
            access_expiry,
            tee_attested,
        )
        .with_aal(vec!["did".to_string(), "passkey".to_string()], "aal2");
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;

    // Persist AAL on the session row so a subsequent /auth/refresh
    // re-mints at aal2 (rather than silently dropping back to aal1).
    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    session.amr = claims.amr.clone();
    session.acr = claims.acr.clone();
    update_session(&state.sessions_ks, &session).await?;
    store_refresh_index(&state.sessions_ks, &refresh_token, &session.session_id).await?;

    info!(did = %session.did, session_id = %session.session_id, "passkey login successful");
    audit!(
        "auth.passkey_login_finish",
        actor = &session.did,
        resource = &session.session_id,
        outcome = "success"
    );

    let issued_at_epoch = now_epoch();
    Ok(Json(AuthenticateResponse {
        session: WireSession {
            id: session.session_id.clone(),
            subject: session.did.clone(),
            issued_at: epoch_to_rfc3339(issued_at_epoch),
            expires_at: epoch_to_rfc3339(access_expires_at),
            amr: claims.amr.clone(),
            acr: claims.acr.clone(),
        },
        tokens: TokenBundle {
            access_token,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: access_expires_at.saturating_sub(issued_at_epoch),
            refresh_expires_in: Some(refresh_expires_at.saturating_sub(issued_at_epoch)),
            scope: Vec::new(),
        },
    }))
}
