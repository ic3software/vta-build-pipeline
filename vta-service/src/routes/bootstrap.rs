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
#[cfg(feature = "tee")]
use base64::Engine;
#[cfg(feature = "tee")]
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
    bundle_digest, generate_ed25519_keypair, seal_payload,
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
    /// Consumer's ephemeral `did:key` (Ed25519). The server derives the
    /// X25519 pubkey from this for the HPKE seal.
    pub client_did: String,
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

    let client_ed25519_pub = decode_client_did(&req.client_did)?;
    let bundle_id = decode_nonce(&req.nonce)?;
    let now = now_epoch();

    #[cfg(feature = "tee")]
    let bundle = mint_mode_b(&state, &client_ed25519_pub, bundle_id, now).await?;

    #[cfg(not(feature = "tee"))]
    {
        let _ = (state, client_ed25519_pub, bundle_id, now);
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
    client_ed25519_pub: &[u8; 32],
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

    // Per-request ephemeral producer Ed25519 keypair. The did:key bytes are
    // bound into the attestation `user_data` alongside the client's did:key
    // bytes + nonce so the consumer can recompute against DID-visible data.
    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);

    // Attestation user_data binds DID-layer bytes end-to-end:
    //   SHA256(client_ed25519 || bundle_id || producer_ed25519)
    // Both halves match what the consumer sees via the `client_did` it sent
    // and the `producer_did` in the returned `ProducerAssertion`.
    let mut hasher = Sha256::new();
    hasher.update(client_ed25519_pub);
    hasher.update(bundle_id);
    hasher.update(producer_ed_pub);
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
        producer_did,
        proof: AssertionProof::Attested(AttestationQuoteAssertion {
            format: format!("{}", report.tee_type),
            quote_b64: report.evidence,
        }),
    };

    // HPKE targets the consumer's derived X25519 pubkey; the DID layer is
    // invisible to the cipher. Any decoding error here should be impossible
    // (the handler already validated `client_did`), so surface as 500.
    let client_x25519_pub =
        affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(client_ed25519_pub)
            .map_err(|e| AppError::Internal(format!("client_did X25519 derivation: {e}")))?;

    let nonce_store = PersistentNonceStore::new(state.sealed_nonces_ks.clone());
    let payload = SealedPayloadV1::AdminCredential(Box::new(credential));
    let bundle = seal_payload(
        &client_x25519_pub,
        bundle_id,
        assertion,
        &payload,
        &nonce_store,
    )
    .await
    .map_err(|e| AppError::Internal(format!("sealed-transfer seal failed: {e}")))?;
    info!("TEE first-boot carve-out consumed — closed for good");
    Ok(bundle)
}

/// Decode the consumer's `did:key` (Ed25519) to its raw 32-byte pubkey.
/// X25519 derivation happens inside `mint_mode_b` where HPKE is actually
/// invoked; the Ed25519 pubkey is separately bound into the attestation
/// `user_data` so the consumer can verify against did:key-visible bytes.
fn decode_client_did(did: &str) -> Result<[u8; 32], AppError> {
    affinidi_crypto::did_key::did_key_to_ed25519_pub(did)
        .map_err(|e| AppError::Validation(format!("invalid client_did: {e}")))
}

#[cfg(feature = "tee")]
fn decode_nonce(s: &str) -> Result<[u8; 16], AppError> {
    let raw = B64URL
        .decode(s)
        .map_err(|e| AppError::Validation(format!("invalid nonce base64: {e}")))?;
    raw.try_into()
        .map_err(|_| AppError::Validation("nonce must be 16 bytes".into()))
}

#[cfg(not(feature = "tee"))]
fn decode_nonce(_s: &str) -> Result<[u8; 16], AppError> {
    // Non-TEE builds never reach the seal path; the handler returns Forbidden
    // before calling this. Keep a stub with the right signature so the
    // top-level handler compiles without ballooning the conditional code.
    Err(AppError::Forbidden(
        "bootstrap request requires TEE first-boot attestation".into(),
    ))
}

impl IntoResponse for BootstrapResponseBody {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────
// POST /bootstrap/provision-integration
// ─────────────────────────────────────────────────────────────────────
//
// Authenticated counterpart to the offline `vta bootstrap
// provision-integration` CLI. The same shared library fn under
// `operations::provision_integration` backs both; only the I/O differs.

#[cfg(feature = "webvh")]
pub use provision::provision_integration;

#[cfg(feature = "webvh")]
mod provision {
    use axum::Json;
    use axum::extract::State;
    use serde::{Deserialize, Serialize};

    use crate::auth::AdminAuth;
    use crate::error::AppError;
    use crate::operations::provision_integration::{
        AssertionMode, ProvisionIntegrationParams,
        provision_integration as provision_integration_lib,
    };
    use crate::server::AppState;
    use vta_sdk::provision_integration::BootstrapRequest;

    /// Request body for `POST /bootstrap/provision-integration`.
    #[derive(Debug, Deserialize)]
    pub struct ProvisionIntegrationRequestBody {
        /// The integration's VP-framed bootstrap request (signed by its
        /// ephemeral `client_did`).
        pub request: BootstrapRequest,
        /// VTA context to provision into. See library-fn docs for
        /// context-hint reconciliation rules.
        pub context: String,
        /// Optional — default `DidSigned`. Rejected unless the assertion
        /// mode is one the server is happy to sign (pinned-only is
        /// accepted on the HTTP surface because dev/test HTTP use is
        /// legitimate).
        #[serde(default)]
        pub assertion: Option<AssertionModeWire>,
        /// Optional override for the VC's validity window, in seconds.
        /// Omit for the 1-hour default.
        #[serde(default)]
        pub vc_validity_seconds: Option<i64>,
    }

    /// Wire-form enum for `assertion` (camelCase-serialised via
    /// `#[serde(rename_all = ...)]`).
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AssertionModeWire {
        DidSigned,
        PinnedOnly,
    }

    impl From<AssertionModeWire> for AssertionMode {
        fn from(m: AssertionModeWire) -> Self {
            match m {
                AssertionModeWire::DidSigned => AssertionMode::DidSigned,
                AssertionModeWire::PinnedOnly => AssertionMode::PinnedOnly,
            }
        }
    }

    /// Response body.
    #[derive(Debug, Serialize)]
    pub struct ProvisionIntegrationResponseBody {
        /// Armored sealed bundle (PGP-style BEGIN/END blocks).
        pub bundle: String,
        /// SHA-256 digest of the sealed ciphertext (lowercase hex).
        pub digest: String,
        /// Operator-readable summary.
        pub summary: ProvisionSummaryWire,
    }

    #[derive(Debug, Serialize)]
    pub struct ProvisionSummaryWire {
        pub client_did: String,
        pub admin_did: String,
        pub admin_rolled_over: bool,
        pub integration_did: String,
        pub template_name: String,
        pub template_kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub admin_template_name: Option<String>,
        pub bundle_id_hex: String,
        pub secret_count: usize,
        pub output_count: usize,
    }

    /// Handler. Gated by `AdminAuth` — the caller must have admin role
    /// and the target context in `allowed_contexts` (enforced inside
    /// the library fn's preconditions). Super-admin passes through.
    pub async fn provision_integration(
        auth: AdminAuth,
        State(state): State<AppState>,
        Json(req): Json<ProvisionIntegrationRequestBody>,
    ) -> Result<Json<ProvisionIntegrationResponseBody>, AppError> {
        let verified = req
            .request
            .verify()
            .map_err(|e| AppError::Validation(format!("verify BootstrapRequest: {e}")))?;

        let assertion_mode = req.assertion.map(AssertionMode::from).unwrap_or_default();

        let vc_validity = req.vc_validity_seconds.map(chrono::Duration::seconds);

        let deps = crate::operations::provision_integration::ProvisionIntegrationDeps::from(&state);
        let output = provision_integration_lib(
            &deps,
            &auth.0,
            ProvisionIntegrationParams {
                request: verified,
                context: req.context,
                assertion_mode,
                vc_validity,
            },
        )
        .await?;

        Ok(Json(ProvisionIntegrationResponseBody {
            bundle: output.armored,
            digest: output.digest,
            summary: ProvisionSummaryWire {
                client_did: output.summary.client_did,
                admin_did: output.summary.admin_did,
                admin_rolled_over: output.summary.admin_rolled_over,
                integration_did: output.summary.integration_did,
                template_name: output.summary.template_name,
                template_kind: output.summary.template_kind,
                admin_template_name: output.summary.admin_template_name,
                bundle_id_hex: output.summary.bundle_id_hex,
                secret_count: output.summary.secret_count,
                output_count: output.summary.output_count,
            },
        }))
    }
}
