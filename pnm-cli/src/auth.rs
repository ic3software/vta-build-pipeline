use vta_sdk::session::{SessionStore, TokenStatus};

pub use vta_sdk::session::SessionInfo;

const SERVICE_NAME: &str = "pnm-cli";

fn store() -> SessionStore {
    SessionStore::new(
        SERVICE_NAME,
        crate::config::config_dir().expect("could not determine config directory"),
    )
}

/// Store a session directly in the keyring without performing auth.
///
/// Used by the TEE setup flow where the admin identity is a stable key baked
/// into the enclave config and must not be rotated.
///
/// Pass `vta_url: None` to force runtime endpoint resolution from the VTA
/// DID; pass `Some(url)` only to pin an explicit URL.
pub fn store_session(
    keyring_key: &str,
    did: &str,
    private_key: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_direct(keyring_key, did, private_key, vta_did, vta_url)
}

/// Park a phase-1 ephemeral identity with no VTA DID bound yet.
///
/// Used by the deferred-VTA-DID `pnm setup` flow. Phase 2
/// (`pnm setup continue <slug>`) lifts the entry into a
/// `PendingRotation` session via [`bind_vta_did`].
pub fn store_pending_vta_binding(
    keyring_key: &str,
    did: &str,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_pending_vta_binding(keyring_key, did, private_key)
}

/// Lift a `PendingVtaBinding` entry into a `PendingRotation` session.
pub fn bind_vta_did(
    keyring_key: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    store().bind_vta_did(keyring_key, vta_did, vta_url)
}

/// Report whether `keyring_key` identifies a `PendingVtaBinding` session.
pub fn has_pending_vta_binding(keyring_key: &str) -> bool {
    store().has_pending_vta_binding(keyring_key)
}

/// Clear stored credentials and cached tokens.
pub fn logout(keyring_key: &str) {
    store().logout(keyring_key);
    println!("Logged out. Credentials and tokens removed.");
}

/// Load the stored session for diagnostics.
pub fn loaded_session(keyring_key: &str) -> Option<SessionInfo> {
    store().loaded_session(keyring_key)
}

/// Return current session status (for health diagnostics).
pub fn session_status(keyring_key: &str) -> Option<vta_sdk::session::SessionStatus> {
    store().session_status(keyring_key)
}

/// Show current authentication status.
///
/// The VTA's REST URL isn't shown here — it's derived from the VTA DID
/// at runtime, not stored by PNM. Use `pnm health` or `pnm vta info` to
/// see the resolved URL.
pub fn status(keyring_key: &str) {
    match store().session_status(keyring_key) {
        Some(status) => {
            println!("Client DID: {}", status.client_did);
            println!(
                "VTA DID:    {}",
                status.vta_did.as_deref().unwrap_or("(pending setup)")
            );
            match status.token_status {
                TokenStatus::Valid { expires_in_secs } => {
                    println!("Token:      valid (expires in {expires_in_secs}s)");
                }
                TokenStatus::Expired => {
                    println!("Token:      expired");
                }
                TokenStatus::None => {
                    println!("Token:      none (will authenticate on next request)");
                }
            }
        }
        None => {
            println!("Not authenticated.");
            println!("\nRun `pnm setup` to provision an admin identity for a VTA.");
        }
    }
}

/// Ensure we have a valid access token. Returns the token string.
pub async fn ensure_authenticated(
    base_url: &str,
    keyring_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    store().ensure_authenticated(base_url, keyring_key).await
}

/// Connect to the VTA using the preferred transport (DIDComm or REST).
///
/// If `url_override` is provided, always uses REST.
/// Otherwise resolves the VTA DID and prefers DIDComm when available.
pub async fn connect(
    url_override: Option<&str>,
    keyring_key: &str,
) -> Result<vta_sdk::client::VtaClient, Box<dyn std::error::Error>> {
    store().connect(keyring_key, url_override).await
}
