//! Test-support types for [`SessionBackend`](super::SessionBackend).
//!
//! Compiled under `#[cfg(any(test, feature = "test-support"))]`. Downstream
//! crates that want to exercise `SessionStore`-backed flows in their own
//! integration tests (notably `pnm-cli/tests/`) enable the `test-support`
//! feature in `[dev-dependencies]`:
//!
//! ```toml
//! [dev-dependencies]
//! vta-sdk = { path = "../vta-sdk", features = ["test-support"] }
//! ```
//!
//! The backend is pure in-memory — no keyring, no file IO, no prompts. Safe
//! for CI without macOS Keychain prompts or a running Linux Secret Service.

use std::collections::HashMap;
use std::sync::Mutex;

use super::SessionBackend;

/// In-memory [`SessionBackend`] for unit and integration tests.
///
/// Defaults to empty; use [`SessionStore::with_backend`](super::SessionStore::with_backend)
/// to plug it in.
#[derive(Default)]
pub struct InMemorySessionBackend {
    data: Mutex<HashMap<String, String>>,
}

impl InMemorySessionBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionBackend for InMemorySessionBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn clear(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}
