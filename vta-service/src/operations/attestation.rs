use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::tee::TeeState;
use crate::tee::provider::StructuralCheckOutcome;
use crate::tee::types::{AttestationReport, TeeStatus};

/// Get the cached TEE detection status.
pub fn get_tee_status(tee_state: &TeeState) -> TeeStatus {
    tee_state.status.clone()
}

/// Generate a fresh attestation report binding the VTA DID and client nonce.
///
/// The server-side structural smoke-check is logged but **not** returned
/// on the wire — there is no honest way for a producer to claim its own
/// attestation is valid in a way the consumer should trust. Consumers
/// must verify via `vta_sdk::attestation::verify_nitro_assertion`
/// (gated behind the `attest-verify` feature) against the vendor root
/// of trust.
pub async fn generate_attestation_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
    nonce: &str,
) -> Result<AttestationReport, AppError> {
    // Validate nonce: must be hex-encoded, 1-64 bytes
    let nonce_bytes = hex::decode(nonce)
        .map_err(|e| AppError::Validation(format!("nonce must be hex-encoded: {e}")))?;
    if nonce_bytes.is_empty() || nonce_bytes.len() > 64 {
        return Err(AppError::Validation(
            "nonce must be 1-64 bytes (2-128 hex chars)".into(),
        ));
    }

    // Read VTA DID from config
    let vta_did = config.read().await.vta_did.clone();
    let user_data = vta_did.as_deref().unwrap_or("").as_bytes();

    debug!(
        nonce_len = nonce_bytes.len(),
        "generating attestation report"
    );

    // Generate the report via the platform provider
    let mut report = tee_state.provider.attest(user_data, &nonce_bytes)?;
    report.vta_did = vta_did;

    // Structural smoke-check — NOT full cryptographic verification. The
    // remote verifier is responsible for checking the vendor cert chain,
    // signature, and PCR values. We log the outcome so a malformed
    // evidence blob is visible in the producer's traces; we do NOT
    // expose it on the wire (per typestate discipline — see CLAUDE.md).
    match tee_state.provider.smoke_check_structure(&report)? {
        StructuralCheckOutcome::StructurallyValid => {}
        StructuralCheckOutcome::Malformed => {
            warn!(
                tee_type = %report.tee_type,
                "attestation evidence failed structural smoke-check — \
                 returning anyway, consumer must verify cryptographically"
            );
        }
    }

    Ok(report)
}

/// Get a cached attestation report (no client nonce — uses a timestamp-based nonce).
pub async fn get_cached_report(
    tee_state: &TeeState,
    config: &Arc<RwLock<AppConfig>>,
) -> Result<AttestationReport, AppError> {
    // Use a deterministic nonce derived from the current time bucket
    let cache_ttl = {
        #[cfg(feature = "tee")]
        {
            config.read().await.tee.attestation_cache_ttl
        }
        #[cfg(not(feature = "tee"))]
        {
            let _ = config;
            300u64
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_bucket = now / cache_ttl;
    let nonce = hex::encode(time_bucket.to_be_bytes());

    generate_attestation_report(tee_state, config, &nonce).await
}
