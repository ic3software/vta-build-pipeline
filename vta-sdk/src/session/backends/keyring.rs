//! OS-native keyring backend for [`SessionBackend`].
//!
//! Built on `keyring-core` 1.0; the SDK feature flag `keyring` pulls
//! in the per-platform store crates (Apple Keychain on macOS, Windows
//! Credential Manager on Windows, DBus Secret Service on Linux). The
//! consuming binary registers the platform store at startup via
//! [`crate::keyring_init::install_default_store`].

use crate::session::SessionBackend;

pub(crate) struct KeyringBackend {
    pub(crate) service_name: String,
}

impl SessionBackend for KeyringBackend {
    fn load(&self, key: &str) -> Option<String> {
        let entry = match keyring_core::Entry::new(&self.service_name, key) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("keyring entry creation failed for '{key}': {e}");
                return None;
            }
        };
        match entry.get_password() {
            Ok(v) => Some(v),
            Err(keyring_core::Error::NoEntry) => None,
            Err(e) => {
                tracing::warn!("keyring read error for '{key}': {e}");
                None
            }
        }
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = keyring_core::Entry::new(&self.service_name, key)
            .map_err(|e| format!("keyring entry error: {e}"))?;
        entry
            .set_password(value)
            .map_err(|e| format!("failed to store session in keyring: {e}"))?;
        Ok(())
    }

    fn clear(&self, key: &str) {
        match keyring_core::Entry::new(&self.service_name, key) {
            Ok(entry) => {
                if let Err(e) = entry.delete_credential() {
                    tracing::debug!("keyring clear for '{key}': {e}");
                }
            }
            Err(e) => {
                tracing::debug!("keyring entry creation failed during clear for '{key}': {e}")
            }
        }
    }
}
