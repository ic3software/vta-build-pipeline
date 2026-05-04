//! Register the platform-native credential store as keyring-core's
//! global default.
//!
//! `keyring-core` 1.0 split the Entry API from the backend stores. Every
//! binary that uses the OS keyring must register a store at startup before
//! constructing any `keyring_core::Entry`. Call [`install_default_store`]
//! once from `main()` before opening a session store, seed store, or
//! anything else that touches `Entry::new`.

/// Register the OS-native credential store as the keyring-core default.
///
/// - macOS → Keychain
/// - Linux → DBus Secret Service (GNOME Keyring / KWallet / KeePassXC)
/// - Windows → Windows Credential Manager
///
/// The keyring feature is unsupported on other platforms; enabling it
/// there is a build error.
#[cfg(target_os = "macos")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = apple_native_keyring_store::keychain::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = dbus_secret_service_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install_default_store() -> keyring_core::Result<()> {
    let store = windows_native_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
compile_error!(
    "vta-sdk `keyring` feature requires target_os in (macos, linux, windows). \
     Disable the feature or build for a supported OS."
);
