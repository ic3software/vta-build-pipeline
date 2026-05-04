//! Built-in [`SessionBackend`](super::SessionBackend) implementations.
//!
//! Each backend is feature-gated to its respective dependency:
//! - [`KeyringBackend`] (`keyring` feature) — OS-native keyring via
//!   `keyring-core` (Apple Keychain / Windows Credential Manager /
//!   DBus Secret Service).
//! - [`AzureBackend`] (`azure-secrets` without `keyring`) — Azure
//!   Key Vault, isolated through a side thread to avoid nesting tokio
//!   runtimes.
//! - [`FileBackend`] — plaintext on-disk JSON. Always compiled; used
//!   either via the explicit `config-session` feature or as the silent
//!   fallback when no other backend is enabled.
//!
//! [`default_backend`] picks among them based on compiled features,
//! preserving the priority order keyring → azure → config-session →
//! plaintext-fallback that the SDK has always used.

use std::path::PathBuf;

use super::SessionBackend;

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
mod azure;
mod file;
#[cfg(feature = "keyring")]
mod keyring;

#[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
pub(super) use azure::AzureBackend;
pub(super) use file::FileBackend;
#[cfg(feature = "keyring")]
pub(super) use keyring::KeyringBackend;

/// Create the default session backend based on compiled features.
///
/// Priority: keyring → azure-secrets → config-session → plaintext fallback.
pub(super) fn default_backend(
    service_name: &str,
    sessions_dir: PathBuf,
) -> Box<dyn SessionBackend> {
    let _ = service_name;
    let _ = &sessions_dir;

    #[cfg(feature = "keyring")]
    {
        return Box::new(KeyringBackend {
            service_name: service_name.to_string(),
        });
    }

    #[cfg(all(feature = "azure-secrets", not(feature = "keyring")))]
    {
        return Box::new(AzureBackend {
            vault_url: std::env::var("AZURE_KEYVAULT_URL").unwrap_or_default(),
            secret_prefix: service_name.to_string(),
        });
    }

    #[cfg(all(
        feature = "config-session",
        not(feature = "keyring"),
        not(feature = "azure-secrets")
    ))]
    {
        return Box::new(FileBackend {
            sessions_dir,
            warn: false,
        });
    }

    #[allow(unreachable_code)]
    Box::new(FileBackend {
        sessions_dir,
        warn: true,
    })
}
