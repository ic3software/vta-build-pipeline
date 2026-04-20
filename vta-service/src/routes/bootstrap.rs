//! `POST /bootstrap/request` — TEE first-boot sealed-bootstrap endpoint.
//!
//! This endpoint only handles **Mode B**: a fresh TEE VTA that has no admin
//! yet. The server generates an attestation quote committing to the client
//! pubkey, nonce, and its own ephemeral producer pubkey, mints an Admin
//! credential, and closes the first-boot carve-out permanently. The bundle's
//! assertion is `Attested(quote)` so the consumer can verify end-to-end
//! without any prior shared secret.
//!
//! The former Mode A (token-gated online bootstrap for non-TEE VTAs) was
//! removed: non-TEE clients now use `pnm setup`'s unified temp-did:key
//! flow (client mints locally, admin grants via `vta acl create`, PNM
//! rotates on first authenticated connect).

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

#[cfg(feature = "tee")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tee")]
use tracing::info;
#[cfg(feature = "tee")]
use vta_sdk::credentials::CredentialBundle;
#[cfg(feature = "tee")]
use vta_sdk::sealed_transfer::{
    AssertionProof, AttestationQuoteAssertion, ProducerAssertion, SealedPayloadV1, armor,
    bundle_digest, generate_keypair, seal_payload,
};

#[cfg(feature = "tee")]
use crate::acl::store_acl_entry;
#[cfg(feature = "tee")]
use crate::acl::{AclEntry, Role};
#[cfg(feature = "tee")]
use crate::audit::audit;
use crate::auth::session::now_epoch;
use crate::error::AppError;
#[cfg(feature = "tee")]
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::server::AppState;

/// Request body. `#[serde(deny_unknown_fields)]` so a client cannot smuggle
/// in `requested_role` / `allowed_contexts` — minting parameters are
/// determined entirely by attestation policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequestBody {
    /// Wire-format version. Currently 1.
    pub version: u8,
    /// Consumer's ephemeral X25519 public key (32 bytes), base64url-no-pad.
    pub client_pubkey: String,
    /// Random 16-byte nonce, base64url-no-pad. Becomes the bundle_id.
    pub nonce: String,
    /// Optional human-readable label (operator-visible only). Echoed into
    /// server-side audit logs. Wire field stays present on non-TEE builds so
    /// older clients keep deserializing; the value is only consumed by the
    /// TEE first-boot path.
    #[serde(default)]
    #[cfg_attr(not(feature = "tee"), allow(dead_code))]
    pub label: Option<String>,
}

/// Response body — a single armored sealed bundle as UTF-8 text, plus the
/// canonical SHA-256 digest so clients can optionally anchor on it.
#[derive(Debug, Serialize)]
pub struct BootstrapResponseBody {
    pub bundle: String,
    pub digest: String,
}

/// `POST /bootstrap/request`
pub async fn request(
    State(state): State<AppState>,
    Json(req): Json<BootstrapRequestBody>,
) -> Result<Json<BootstrapResponseBody>, AppError> {
    if req.version != 1 {
        return Err(AppError::Validation(format!(
            "unsupported bootstrap request version: {}",
            req.version
        )));
    }

    let client_pubkey = decode_pubkey(&req.client_pubkey)?;
    let bundle_id = decode_nonce(&req.nonce)?;
    let now = now_epoch();

    #[cfg(feature = "tee")]
    let bundle = mint_mode_b(&state, &client_pubkey, bundle_id, now).await?;

    #[cfg(not(feature = "tee"))]
    {
        let _ = (state, client_pubkey, bundle_id, now);
        return Err(AppError::Forbidden(
            "bootstrap request requires TEE first-boot attestation, which is not available on \
             this VTA build. Non-TEE VTAs use the `pnm setup` temp-did:key + ACL flow instead."
                .into(),
        ));
    }

    #[cfg(feature = "tee")]
    {
        let digest = bundle_digest(&bundle);
        let armored = armor::encode(&bundle);

        info!(client_label = ?req.label, "TEE first-boot bootstrap completed");
        audit!(
            "bootstrap.swap",
            actor = "bootstrap-endpoint",
            resource = "bootstrap",
            outcome = "success"
        );
        let _ = crate::audit::record(
            &state.audit_ks,
            "bootstrap.swap",
            "bootstrap-endpoint",
            None,
            "success",
            Some("rest"),
            None,
        )
        .await;

        Ok(Json(BootstrapResponseBody {
            bundle: armored,
            digest,
        }))
    }
}

/// Mode B: TEE first-boot sealed bootstrap. No token; the attestation quote
/// is the sole authorization anchor.
///
/// On success, closes the first-boot carve-out permanently by writing the
/// `BOOTSTRAP_CARVEOUT_CLOSED_KEY` sentinel. Any subsequent request is
/// rejected.
#[cfg(feature = "tee")]
async fn mint_mode_b(
    state: &AppState,
    client_pubkey: &[u8; 32],
    bundle_id: [u8; 16],
    now: u64,
) -> Result<vta_sdk::sealed_transfer::SealedBundle, AppError> {
    use crate::tee::admin_bootstrap::{BOOTSTRAP_CARVEOUT_CLOSED_KEY, LEGACY_ADMIN_CREDENTIAL_KEY};

    let tee_state =
        state.tee.as_ref().map(|tc| &tc.state).ok_or_else(|| {
            AppError::Forbidden("TEE first-boot is not available on this VTA".into())
        })?;

    // Carve-out active ⇔ neither the closed-sentinel nor the legacy
    // admin-credential row is present. (The latter is a transitional case —
    // startup migration rewrites it into the closed-sentinel before this
    // handler ever runs, but we check here too to keep the handler correct
    // even without startup migration.)
    if state
        .keys_ks
        .get_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY)
        .await?
        .is_some()
        || state
            .keys_ks
            .get_raw(LEGACY_ADMIN_CREDENTIAL_KEY)
            .await?
            .is_some()
    {
        return Err(AppError::Forbidden(
            "TEE first-boot carve-out has already been used".into(),
        ));
    }

    let cfg = state.config.read().await;
    let vta_did = cfg
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = cfg.public_url.clone();
    drop(cfg);

    // Per-request ephemeral producer pubkey. The attestation quote binds
    // it into `user_data` alongside the client-provided pubkey and nonce,
    // so the consumer can recompute and verify on open.
    let (_producer_sk, producer_pk) = generate_keypair();

    let mut hasher = Sha256::new();
    hasher.update(client_pubkey);
    hasher.update(&bundle_id);
    hasher.update(&producer_pk);
    let user_data = hasher.finalize();

    // Attestation nonce: reuse the client nonce for freshness.
    let report = tee_state
        .provider
        .attest(user_data.as_slice(), &bundle_id)
        .map_err(|e| AppError::Internal(format!("tee attest failed: {e}")))?;

    // Mint admin credential and insert ACL entry. Carve-out closes atomically
    // with the sentinel write below.
    let (did, private_key_multibase) = crate::auth::credentials::generate_did_key();
    let entry = AclEntry {
        did: did.clone(),
        role: Role::Admin,
        label: Some("TEE first-boot admin".to_string()),
        allowed_contexts: vec![],
        created_at: now,
        created_by: "tee:mode-b".to_string(),
        expires_at: None,
    };
    store_acl_entry(&state.acl_ks, &entry).await?;

    state
        .keys_ks
        .insert_raw(BOOTSTRAP_CARVEOUT_CLOSED_KEY, did.as_bytes().to_vec())
        .await?;

    let credential = CredentialBundle {
        did,
        private_key_multibase,
        vta_did,
        vta_url,
    };

    let assertion = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::Attested(AttestationQuoteAssertion {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        }),
    };

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let payload = SealedPayloadV1::AdminCredential(Box::new(credential));
    let bundle = seal_payload(client_pubkey, bundle_id, assertion, &payload, &nonce_store)
        .await
        .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    info!("TEE first-boot carve-out consumed — closed for good");
    Ok(bundle)
}

fn decode_pubkey(s: &str) -> Result<[u8; 32], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid client_pubkey base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("client_pubkey must be 32 bytes".into()))
}

fn decode_nonce(s: &str) -> Result<[u8; 16], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid nonce base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("nonce must be 16 bytes".into()))
}

impl IntoResponse for BootstrapResponseBody {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}
