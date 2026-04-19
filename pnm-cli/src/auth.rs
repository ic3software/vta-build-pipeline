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
pub fn store_session(
    keyring_key: &str,
    did: &str,
    private_key: &str,
    vta_did: &str,
    vta_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_direct(keyring_key, did, private_key, vta_did, vta_url)
}

/// Store a session flagged for rotation on first successful authentication.
///
/// Used by `pnm setup` for the non-TEE flow: the did:key is handed to an
/// admin out-of-band to be added to the ACL, and PNM rotates it out as soon
/// as it can authenticate (see `SessionStore::ensure_authenticated` in vta-sdk).
pub fn store_session_pending_rotation(
    keyring_key: &str,
    did: &str,
    private_key: &str,
    vta_did: &str,
    vta_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    store().store_pending_rotation(keyring_key, did, private_key, vta_did, vta_url)
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
pub fn status(keyring_key: &str) {
    match store().session_status(keyring_key) {
        Some(status) => {
            println!("Client DID: {}", status.client_did);
            println!("VTA DID:    {}", status.vta_did);
            println!(
                "VTA URL:    {}",
                status.vta_url.as_deref().unwrap_or("(not set)")
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
