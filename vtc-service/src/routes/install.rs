//! `POST /v1/install/claim/{start,finish}` — WebAuthn install
//! ceremony for the very first admin.
//!
//! Implements **M0.5.2** of the VTC MVP Phase 0 plan. The flow:
//!
//! ```text
//! operator  ──install_token──▶  start  ──ccr+did_binding_challenge──▶ operator
//! operator  ──finish(webauthn_response, did_binding_signature)──▶  finish
//! finish    ──admin_did + setup_session_token──▶  operator
//! ```
//!
//! - `start` verifies the install token, takes the install-keyspace
//!   ceremony lock (`InstallTokenStore::start_claim`), and returns a
//!   WebAuthn `CreationChallengeResponse` constrained to Ed25519 via
//!   `vtc_service::webauthn::start_eddsa_passkey_registration`. It
//!   also returns a server-issued 32-byte "DID-binding challenge"
//!   that the operator must sign with their newly-minted Ed25519 key.
//! - `finish` verifies the WebAuthn response, derives the candidate
//!   admin `did:key` from the credential's Ed25519 public key,
//!   verifies the DID-binding signature with that same key (proves
//!   single-key control over both signing paths — spec §4.2 third
//!   bullet), consumes the install token, persists the passkey,
//!   and mints a short-lived setup-session token consumed by M0.6's
//!   `/v1/admin/bootstrap`.
//!
//! The carve-out *stays open* until admin bootstrap; until then the
//! install token is consumed but the `InstallTokenStore::close_carveout`
//! call lives in M0.6. A second `start` on the same token after a
//! successful `finish` returns 401 because the state machine sees
//! `Consumed`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use vti_common::auth::passkey::store::{
    PasskeyUser, delete_registration_user, get_registration_user, store_credential_mapping,
    store_passkey_user, store_registration_state, store_registration_user, take_registration_state,
};
use vti_common::error::AppError;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, RegisterPublicKeyCredential, Webauthn,
};

use crate::install::{
    INSTALL_SESSION_DEFAULT_TTL_SECS, InstallTokenSigner, mint_install_session_token,
    parse_install_token,
};
use crate::server::AppState;
use crate::webauthn::{finish_eddsa_passkey_registration, start_eddsa_passkey_registration};

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ClaimStartRequest {
    pub install_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimStartResponse {
    /// Echoes the install token's `jti`. Consumer must pass this
    /// back to `claim/finish` so the server can index the stored
    /// registration state.
    pub registration_id: String,
    /// The WebAuthn `PublicKeyCredentialCreationOptions` payload —
    /// the operator's UA passes this to `navigator.credentials.create()`.
    pub options: CreationChallengeResponse,
    /// 32 random server bytes (base64url-no-pad). The operator
    /// signs these with the Ed25519 private key materialised inside
    /// their authenticator and returns the signature in
    /// `claim/finish` — proves the WebAuthn key and the candidate
    /// `did:key` are the same keypair.
    pub did_binding_challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimFinishRequest {
    pub install_token: String,
    pub registration_id: String,
    pub webauthn_response: RegisterPublicKeyCredential,
    /// Base64url-no-pad Ed25519 signature over the raw 32 bytes the
    /// server returned in `did_binding_challenge`.
    pub did_binding_signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimFinishResponse {
    pub admin_did: String,
    pub setup_session_token: String,
}

// ---------------------------------------------------------------------------
// Storage key helpers
// ---------------------------------------------------------------------------

fn did_binding_key(jti: &Uuid) -> Vec<u8> {
    format!("install_did_binding:{jti}").into_bytes()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn claim_start(
    State(state): State<AppState>,
    Json(req): Json<ClaimStartRequest>,
) -> Result<(StatusCode, Json<ClaimStartResponse>), AppError> {
    let signer = require_install_signer(&state)?;
    let webauthn = require_webauthn(&state)?;
    let store = &state.install_store;

    let claims = parse_install_token(signer, &req.install_token)?;
    let jti = parse_jti(&claims.jti)?;

    // Take the ceremony lock. `start_claim` validates `Issued`, not
    // expired, carve-out open; on success the `claimed_at` window is
    // set to "now" so a second concurrent start sees the lock.
    let _outcome = store.start_claim(&jti).await?;

    let user_uuid = jti;
    // `user_name` / `user_display_name` are operator-visible labels in
    // the authenticator's UI. The install URL only exists pre-bootstrap
    // — no real admin DID yet — so we use a stable, install-specific
    // placeholder. The label is overwritten when M0.6 bootstraps the
    // real admin DID.
    let user_label = format!("vtc-install-{jti}");
    let (ccr, reg_state) =
        start_eddsa_passkey_registration(webauthn, user_uuid, &user_label, &user_label, None)?;

    // Persist the registration state under `jti` so `claim_finish`
    // can complete the ceremony against the same challenge.
    store_registration_state(&state.passkey_ks, &jti.to_string(), &reg_state).await?;

    // Carry the user UUID forward so the M0.6 bootstrap can look up
    // the PasskeyUser by registration_id without re-deriving it.
    store_registration_user(&state.passkey_ks, &jti.to_string(), &user_uuid).await?;

    // 32 random bytes for the DID-binding challenge.
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    state
        .passkey_ks
        .insert_raw(did_binding_key(&jti), challenge_bytes.to_vec())
        .await?;

    info!(jti = %jti, "install claim ceremony started");

    Ok((
        StatusCode::OK,
        Json(ClaimStartResponse {
            registration_id: jti.to_string(),
            options: ccr,
            did_binding_challenge: B64.encode(challenge_bytes),
        }),
    ))
}

pub async fn claim_finish(
    State(state): State<AppState>,
    Json(req): Json<ClaimFinishRequest>,
) -> Result<(StatusCode, Json<ClaimFinishResponse>), AppError> {
    let signer = require_install_signer(&state)?;
    let webauthn = require_webauthn(&state)?;
    let store = &state.install_store;

    let claims = parse_install_token(signer, &req.install_token)?;
    let jti = parse_jti(&claims.jti)?;
    let reg_id = parse_jti(&req.registration_id)?;
    if reg_id != jti {
        return Err(AppError::Unauthorized(
            "registration_id does not match install token".into(),
        ));
    }

    let reg_state = take_registration_state(&state.passkey_ks, &jti.to_string())
        .await?
        .ok_or_else(|| {
            AppError::Unauthorized(
                "no registration in progress for this install token (start the ceremony first)"
                    .into(),
            )
        })?;

    let challenge_bytes = state
        .passkey_ks
        .get_raw(did_binding_key(&jti))
        .await?
        .ok_or_else(|| AppError::Internal("missing DID-binding challenge".into()))?;
    let challenge: [u8; 32] = challenge_bytes
        .try_into()
        .map_err(|_| AppError::Internal("DID-binding challenge malformed".into()))?;

    // Run the WebAuthn ceremony. EdDSA enforcement happens here and
    // is asserted twice — once by webauthn-rs against the rewritten
    // `credential_algorithms` list, once by
    // `finish_eddsa_passkey_registration` checking `cred_algorithm()`.
    let passkey = finish_eddsa_passkey_registration(webauthn, &req.webauthn_response, &reg_state)?;

    let ed25519_pub = extract_ed25519_public_key(&passkey)?;
    let admin_did = ed25519_pub_to_did_key(&ed25519_pub);

    // Verify the DID-binding signature: proves the operator can sign
    // raw bytes with the same Ed25519 key that the authenticator
    // generated. Without this an attacker who acquired only the
    // WebAuthn assertion couldn't reproduce the candidate did:key's
    // signing path.
    verify_did_binding(&ed25519_pub, &challenge, &req.did_binding_signature)?;

    // Consume the install token (Issued → Consumed). Carve-out stays
    // open until M0.6's bootstrap closes it.
    store.finish_claim(&jti).await?;

    // Drop the one-shot DID-binding challenge.
    state.passkey_ks.remove(did_binding_key(&jti)).await?;

    // Persist the passkey + credential mapping so M0.6's bootstrap
    // and subsequent passkey login can find the credential.
    let user_uuid = get_registration_user(&state.passkey_ks, &jti.to_string())
        .await?
        .ok_or_else(|| AppError::Internal("missing registration_user mapping".into()))?;
    delete_registration_user(&state.passkey_ks, &jti.to_string()).await?;
    let user = PasskeyUser {
        user_uuid,
        did: admin_did.clone(),
        display_name: admin_did.clone(),
        credentials: vec![passkey.clone()],
    };
    store_passkey_user(&state.passkey_ks, &user).await?;
    let cred_id_hex = hex::encode(passkey.cred_id().as_ref() as &[u8]);
    store_credential_mapping(&state.passkey_ks, &cred_id_hex, user_uuid).await?;

    let issuer_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "did:key:vtc-install-uninitialised".to_string());

    let setup_session_token = mint_install_session_token(
        signer,
        &issuer_did,
        &admin_did,
        INSTALL_SESSION_DEFAULT_TTL_SECS,
    )?;

    info!(jti = %jti, %admin_did, "install claim ceremony completed");

    Ok((
        StatusCode::OK,
        Json(ClaimFinishResponse {
            admin_did,
            setup_session_token,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_install_signer(state: &AppState) -> Result<&Arc<InstallTokenSigner>, AppError> {
    state
        .install_signer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "install signer not configured (run setup first)".into(),
        })
}

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "WebAuthn not configured (public_url required)".into(),
        })
}

fn parse_jti(s: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(s)
        .map_err(|_| AppError::Unauthorized("invalid install token (malformed jti)".into()))
}

/// Lift the raw 32-byte Ed25519 public key out of a registered
/// [`Passkey`]. webauthn-rs serialises the COSE key under
/// `cred.cred.key.EC_OKP.x` (base64url-no-pad string) in the current
/// shape; we serde-walk it rather than depend on the
/// `danger-credential-internals` feature.
fn extract_ed25519_public_key(passkey: &Passkey) -> Result<[u8; 32], AppError> {
    let value = serde_json::to_value(passkey)
        .map_err(|e| AppError::Internal(format!("passkey serialise: {e}")))?;
    let bytes = walk_eddsa_x(&value)
        .ok_or_else(|| AppError::Internal("passkey has no Ed25519 x coordinate".into()))?;
    bytes
        .try_into()
        .map_err(|_| AppError::Internal("Ed25519 x coordinate not 32 bytes".into()))
}

fn walk_eddsa_x(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(x) = map.get("x")
                && let Some(bytes) = decode_x_value(x)
            {
                return Some(bytes);
            }
            for v in map.values() {
                if let Some(found) = walk_eddsa_x(v) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(walk_eddsa_x),
        _ => None,
    }
}

fn decode_x_value(value: &serde_json::Value) -> Option<Vec<u8>> {
    if let Ok(bytes) = serde_json::from_value::<Vec<u8>>(value.clone())
        && bytes.len() == 32
    {
        return Some(bytes);
    }
    if let Some(s) = value.as_str()
        && let Ok(bytes) = B64.decode(s)
        && bytes.len() == 32
    {
        return Some(bytes);
    }
    None
}

/// Project a 32-byte Ed25519 public key into a `did:key`. Multicodec
/// prefix `0xed01` + raw key, multibase-encoded with `z` (base58btc).
fn ed25519_pub_to_did_key(pubkey: &[u8; 32]) -> String {
    format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(pubkey)
    )
}

/// Verify a base64url-no-pad Ed25519 signature over `challenge`
/// using `pubkey`.
fn verify_did_binding(
    pubkey: &[u8; 32],
    challenge: &[u8; 32],
    signature_b64u: &str,
) -> Result<(), AppError> {
    let sig_bytes = B64
        .decode(signature_b64u)
        .map_err(|_| AppError::Unauthorized("invalid DID-binding signature encoding".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppError::Unauthorized("DID-binding signature must be 64 bytes".into()))?;
    let verifying = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| AppError::Internal("malformed Ed25519 public key".into()))?;
    verifying
        .verify(challenge, &Signature::from_bytes(&sig_arr))
        .map_err(|_| AppError::Unauthorized("DID-binding signature does not verify".into()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn eddsa_alg_constant_matches_cose() {
        // Drift sentinel — if `EDDSA_ALG` ever changes the install
        // route's enforcement is no longer aligned with the rest of
        // the workspace.
        assert_eq!(crate::webauthn::EDDSA_ALG, -8);
    }

    #[test]
    fn did_key_round_trips_through_vta_sdk() {
        let pubkey = [0xAA; 32];
        let did = ed25519_pub_to_did_key(&pubkey);
        assert!(did.starts_with("did:key:z"));
        // Decode back via the SDK to confirm the same bytes survive.
        let mb = did.strip_prefix("did:key:").unwrap();
        let decoded = vta_sdk::did_key::decode_ed25519_public_key_multibase(mb).unwrap();
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn verify_did_binding_accepts_valid_signature() {
        let signing = SigningKey::from_bytes(&[0x11; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let challenge = [0x42u8; 32];
        let sig = signing.sign(&challenge).to_bytes();
        verify_did_binding(&pubkey, &challenge, &B64.encode(sig)).unwrap();
    }

    #[test]
    fn verify_did_binding_rejects_wrong_pubkey() {
        let signing = SigningKey::from_bytes(&[0x11; 32]);
        let other = SigningKey::from_bytes(&[0x22; 32]);
        let challenge = [0x42u8; 32];
        let sig = signing.sign(&challenge).to_bytes();
        let err = verify_did_binding(
            &other.verifying_key().to_bytes(),
            &challenge,
            &B64.encode(sig),
        )
        .expect_err("must reject");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn verify_did_binding_rejects_tampered_challenge() {
        let signing = SigningKey::from_bytes(&[0x11; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let challenge = [0x42u8; 32];
        let sig = signing.sign(&challenge).to_bytes();
        let mut tampered = challenge;
        tampered[0] ^= 0x01;
        let err =
            verify_did_binding(&pubkey, &tampered, &B64.encode(sig)).expect_err("must reject");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn verify_did_binding_rejects_short_signature() {
        let pubkey = [0u8; 32];
        let err = verify_did_binding(&pubkey, &[0u8; 32], &B64.encode([0u8; 16]))
            .expect_err("must reject");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }
}
