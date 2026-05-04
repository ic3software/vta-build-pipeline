//! Plaintext on-disk JSON [`SessionBackend`] for development / config-
//! managed deployments where the OS keyring is not available.
//!
//! Sessions live at `<sessions_dir>/sessions.json`. The `warn` flag
//! emits a runtime warning on every access — used when the file
//! backend was selected as the silent fallback rather than the
//! explicit `config-session` feature.

use std::path::PathBuf;

use crate::session::SessionBackend;

pub(crate) struct FileBackend {
    pub(crate) sessions_dir: PathBuf,
    pub(crate) warn: bool,
}

impl FileBackend {
    fn sessions_path(&self) -> PathBuf {
        self.sessions_dir.join("sessions.json")
    }

    fn load_map(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let path = self.sessions_path();
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::collections::HashMap::new();
            }
            Err(e) => {
                tracing::warn!("failed to read sessions file {}: {e}", path.display());
                return std::collections::HashMap::new();
            }
        };
        match serde_json::from_str(&data) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!("failed to parse sessions file {}: {e}", path.display());
                std::collections::HashMap::new()
            }
        }
    }

    fn save_map(
        &self,
        map: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.sessions_path();
        let json = serde_json::to_string_pretty(map)?;
        std::fs::write(&path, json)?;
        Ok(())
    }
}

impl SessionBackend for FileBackend {
    fn load(&self, key: &str) -> Option<String> {
        if self.warn {
            eprintln!("WARNING: No secure session store — using plaintext file storage");
        }
        let map = self.load_map();
        map.get(key).map(|v| v.to_string())
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.warn {
            eprintln!("WARNING: No secure session store — using plaintext file storage");
        }
        if let Some(parent) = self.sessions_dir.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("failed to create sessions parent dir: {e}");
        }
        if let Err(e) = std::fs::create_dir_all(&self.sessions_dir) {
            tracing::warn!("failed to create sessions dir: {e}");
        }
        let mut map = self.load_map();
        let parsed: serde_json::Value = serde_json::from_str(value)?;
        map.insert(key.to_string(), parsed);
        self.save_map(&map)
    }

    fn clear(&self, key: &str) {
        let mut map = self.load_map();
        map.remove(key);
        let _ = self.save_map(&map);
    }
}
