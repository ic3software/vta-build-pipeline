//! `vtc admin emergency-bootstrap` — destructive operator recovery.
//!
//! Implements **M0.10** of the VTC MVP Phase 0 plan (spec §4.5).
//! Used when every admin passkey is lost: the operator runs this
//! subcommand on a **stopped daemon**, the CLI reopens the install
//! carve-out exactly once, and a new admin can bootstrap via the
//! normal install URL.
//!
//! ## Why a mnemonic gate
//!
//! Without the mnemonic check, a filesystem-level attacker could
//! stop the daemon and run `emergency-bootstrap` to reset the
//! admin. The 24-word BIP-39 mnemonic is the operator-held secret
//! that — by construction — only a legitimate operator possesses,
//! so the carve-out reopen requires it. The check is constant-time
//! against the seed material the secret store already holds.
//!
//! ## What gets cleared
//!
//! - `install:carveout:closed` marker (so a fresh claim can run).
//! - Every `Role::Admin` ACL entry (the recovery flow installs a
//!   *new* admin; the old one is presumed compromised or
//!   inaccessible).
//! - Every `admin:<did>` sister record (M0.6.1 metadata).
//! - The full set of `PasskeyUser` + credential mapping records
//!   for admin DIDs (so stale credentials can't somehow resurface).
//!
//! ## What persists
//!
//! - The community profile (§5.1) — emergency bootstrap recovers
//!   admin access; it doesn't reset the community identity.
//! - The audit log — emergency bootstrap is itself audited via the
//!   pending marker; you can't quietly erase tracks.
//! - The `vtc_did` + key material — those are the community.

use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use vti_common::acl::{Role, delete_acl_entry, list_acl_entries};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::Store;

use crate::acl::admin::list_admin_entries;
use crate::config::AppConfig;
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenStore,
    PendingEmergencyBootstrap, mint_install_token,
};
use crate::keys::seed_store::{SecretStore, create_secret_store};

/// CLI args. `mnemonic` is `Option<String>` so the interactive
/// caller can omit it and let the dialoguer prompt fill it in;
/// automated callers (and tests) can pass it directly.
pub struct EmergencyBootstrapArgs {
    pub config_path: Option<PathBuf>,
    pub mnemonic: Option<String>,
}

/// Outcome of a successful run. The CLI's job is to print
/// `install_url` to the operator; tests assert on the structured
/// fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBootstrapOutcome {
    /// Fully-formed install URL `{public_url}/install?token={jwt}`,
    /// or a `vtc://install?token=...` placeholder when
    /// `public_url` isn't set in the config.
    pub install_url: String,
    /// Number of admin ACL entries cleared during recovery.
    pub admin_entries_cleared: usize,
    /// Number of admin sister records (`admin:<did>`) cleared.
    pub admin_records_cleared: usize,
}

/// The CLI subcommand's entry point. Loads the config + opens the
/// fjall store (which fails with a clear error if the daemon is
/// still holding the directory lock) + drives the cleanup +
/// reopens the carve-out + mints a fresh install token.
pub async fn run_emergency_bootstrap(
    args: EmergencyBootstrapArgs,
) -> Result<EmergencyBootstrapOutcome, AppError> {
    let mnemonic = args
        .mnemonic
        .ok_or_else(|| AppError::Validation("mnemonic is required".into()))?;

    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })
    .map_err(|e| {
        AppError::Config(format!(
            "failed to open fjall store at '{}': {e}. Is the daemon still running? \
             Stop it before running emergency-bootstrap.",
            config.store.data_dir.display()
        ))
    })?;
    let secret_store = create_secret_store(&config)
        .map_err(|e| AppError::Config(format!("failed to construct secret store: {e}")))?;

    run_emergency_bootstrap_with_store(mnemonic, &config, &store, secret_store.as_ref()).await
}

/// Inner driver split from [`run_emergency_bootstrap`] so tests
/// can compose their own `Store` + `SecretStore` without touching
/// the filesystem.
pub async fn run_emergency_bootstrap_with_store(
    mnemonic: String,
    config: &AppConfig,
    store: &Store,
    secret_store: &dyn SecretStore,
) -> Result<EmergencyBootstrapOutcome, AppError> {
    let stored_seed = secret_store
        .get()
        .await
        .map_err(|e| AppError::SecretStore(e.to_string()))?
        .ok_or_else(|| {
            AppError::Config(
                "no key material in the secret store — has this VTC ever been set up?".into(),
            )
        })?;

    verify_mnemonic_matches_stored_seed(&mnemonic, &stored_seed)?;

    let acl_ks = store.keyspace("acl")?;
    let passkey_ks = store.keyspace("passkey")?;
    let install_ks = store.keyspace("install")?;
    let install_store = InstallTokenStore::new(install_ks);

    // --- destructive cleanup ----------------------------------------
    let mut admin_entries_cleared = 0;
    for entry in list_acl_entries(&acl_ks).await? {
        if entry.role == Role::Admin {
            delete_acl_entry(&acl_ks, &entry.did).await?;
            admin_entries_cleared += 1;
        }
    }

    let admin_records = list_admin_entries(&passkey_ks).await?;
    let admin_records_cleared = admin_records.len();
    for entry in admin_records {
        passkey_ks
            .remove(format!("admin:{}", entry.did).into_bytes())
            .await?;
        // Also drop the PasskeyUser + credential-mapping records for
        // this DID so stale credentials can't be reused. M0.5.0's
        // soft authenticator can't tell PasskeyUsers apart from
        // their credentials, so a partial cleanup would leave
        // dangling `pk_cred:<id>` rows.
        if let Some(user) =
            vti_common::auth::passkey::store::get_passkey_user_by_did(&passkey_ks, &entry.did)
                .await?
        {
            passkey_ks
                .remove(format!("pk_user:{}", user.user_uuid).into_bytes())
                .await?;
            passkey_ks
                .remove(format!("pk_did:{}", entry.did).into_bytes())
                .await?;
            for cred in user.credentials {
                let cred_id_hex = hex::encode(<_ as AsRef<[u8]>>::as_ref(cred.cred_id()));
                passkey_ks
                    .remove(format!("pk_cred:{cred_id_hex}").into_bytes())
                    .await?;
            }
        }
    }

    // --- reopen the carve-out ---------------------------------------
    install_store.reopen_carveout().await?;

    // --- mint a fresh install token ---------------------------------
    let signer = InstallTokenSigner::from_master_seed(&stored_seed)?;
    let issuer = config
        .vtc_did
        .clone()
        .unwrap_or_else(|| "did:key:vtc-emergency".into());
    let minted = mint_install_token(&signer, &issuer, INSTALL_TOKEN_DEFAULT_TTL_SECS)?;
    let exp = Utc::now() + chrono::Duration::seconds(INSTALL_TOKEN_DEFAULT_TTL_SECS as i64);
    install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
        )
        .await?;

    // --- pending audit marker ---------------------------------------
    let operator_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    install_store
        .mark_emergency_pending(PendingEmergencyBootstrap {
            operator_hostname: operator_hostname.clone(),
            invoked_at: Utc::now(),
        })
        .await?;

    // --- install URL ------------------------------------------------
    let install_url = match &config.public_url {
        Some(base) => format!(
            "{}/install?token={}",
            base.trim_end_matches('/'),
            minted.jwt
        ),
        None => format!("vtc://install?token={}", minted.jwt),
    };

    info!(
        operator_hostname = %operator_hostname,
        admin_entries_cleared,
        admin_records_cleared,
        "emergency bootstrap completed; install URL minted"
    );
    if admin_entries_cleared == 0 {
        warn!(
            "emergency bootstrap cleared no admin entries — was the daemon already in a \
             fresh-install state?"
        );
    }

    Ok(EmergencyBootstrapOutcome {
        install_url,
        admin_entries_cleared,
        admin_records_cleared,
    })
}

/// Reject the mnemonic if it doesn't BIP-39-derive the same seed
/// the secret store holds. Uses constant-time comparison so a
/// length-tuned probe leaks no information.
///
/// Spec §4.5: the mnemonic verification is what prevents a
/// filesystem-level attacker from triggering a reset by stopping
/// the process. We refuse loud + early before any state mutation.
fn verify_mnemonic_matches_stored_seed(mnemonic: &str, stored: &[u8]) -> Result<(), AppError> {
    let m = bip39::Mnemonic::parse(mnemonic.trim())
        .map_err(|e| AppError::Validation(format!("invalid BIP-39 mnemonic: {e}")))?;
    let derived = m.to_seed("");
    if !constant_time_eq(stored, derived.as_slice()) {
        return Err(AppError::Unauthorized(
            "mnemonic does not derive the stored master seed; refusing to mutate state".into(),
        ));
    }
    Ok(())
}

/// Defence against length-based timing attacks. We never accept a
/// shorter user-supplied seed than the stored one — but check via
/// constant time anyway.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_short_circuits_on_length_mismatch() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(!constant_time_eq(&[], &[0]));
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(constant_time_eq(&[], &[]));
    }

    fn mnemonic_from_entropy(seed: u8) -> bip39::Mnemonic {
        // 32 bytes of entropy → 24-word mnemonic. Tests use a single
        // sentinel byte so the seed → mnemonic round-trip is
        // deterministic for the test name.
        bip39::Mnemonic::from_entropy(&[seed; 32]).unwrap()
    }

    #[test]
    fn mnemonic_round_trip_verifies() {
        let mnemonic = mnemonic_from_entropy(0xAA);
        let seed = mnemonic.to_seed("");
        verify_mnemonic_matches_stored_seed(&mnemonic.to_string(), &seed).unwrap();
    }

    #[test]
    fn mnemonic_mismatch_rejected() {
        let a = mnemonic_from_entropy(0xAA);
        let b = mnemonic_from_entropy(0xBB);
        let err = verify_mnemonic_matches_stored_seed(&a.to_string(), &b.to_seed(""))
            .expect_err("different mnemonics must not match");
        assert!(matches!(err, AppError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn invalid_mnemonic_rejected_as_validation_error() {
        let err = verify_mnemonic_matches_stored_seed("this is not a mnemonic", &[0u8; 64])
            .expect_err("garbage mnemonic must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }
}
