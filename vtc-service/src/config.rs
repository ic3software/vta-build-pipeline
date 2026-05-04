use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vtc_did: Option<String>,
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vtc_name: Option<String>,
    #[serde(alias = "community_description")]
    pub vtc_description: Option<String>,
    pub public_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Hex-encoded VTC key material (config-secret feature)
    pub secret: Option<String>,
    /// AWS Secrets Manager secret name (aws-secrets feature)
    pub aws_secret_name: Option<String>,
    /// AWS region override (aws-secrets feature)
    pub aws_region: Option<String>,
    /// GCP project ID (gcp-secrets feature)
    pub gcp_project: Option<String>,
    /// GCP secret name (gcp-secrets feature)
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault URL (azure-secrets feature)
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name (azure-secrets feature)
    pub azure_secret_name: Option<String>,
    /// OS keyring service name (keyring feature).
    /// Change this to run multiple VTC instances on the same machine.
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
}

fn default_keyring_service() -> String {
    "vtc".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            secret: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8200
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vtc"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTC_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
        let mut config = toml::from_str::<AppConfig>(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();

        // Apply env var overrides
        if let Ok(vtc_did) = std::env::var("VTC_DID") {
            config.vtc_did = Some(vtc_did);
        }
        if let Ok(vta_did) = std::env::var("VTC_VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTC_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTC_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTC_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTC_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTC_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTC_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTC_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Messaging env var overrides
        match (
            std::env::var("VTC_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTC_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                    mediator_host: None,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets env var overrides
        if let Ok(secret) = std::env::var("VTC_SECRETS_SECRET") {
            config.secrets.secret = Some(secret);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTC_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTC_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTC_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTC_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTC_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }

        // Auth env var overrides
        if let Ok(expiry) = std::env::var("VTC_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTC_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTC_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTC_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTC_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTC_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTC_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }

        Ok(config)
    }

    pub fn save(&self) -> Result<(), AppError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parse contract ──────────────────────────────────────────────
    //
    // These tests guard the on-disk config shape. A rename or a
    // missing #[serde(default)] here breaks every operator's
    // config.toml on upgrade.

    #[test]
    fn empty_toml_parses_with_all_defaults() {
        let config: AppConfig = toml::from_str("").expect("empty TOML must parse");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8200, "VTC default port is 8200");
        assert!(config.vtc_did.is_none());
        assert!(config.vta_did.is_none());
        assert!(config.messaging.is_none());
    }

    #[test]
    fn minimal_toml_parses() {
        let toml_src = r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("minimal TOML must parse");
        assert_eq!(config.vtc_did.as_deref(), Some("did:key:zVTC"));
        assert_eq!(config.vta_did.as_deref(), Some("did:key:zVTA"));
    }

    #[test]
    fn community_name_alias_is_accepted() {
        // Backward-compat: older configs used `community_name` before
        // the rename to `vtc_name`. The serde alias preserves their
        // configs. Breaking this breaks existing operators.
        let toml_src = r#"
            community_name = "Alpha Community"
            community_description = "First VTC"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("alias must parse");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha Community"));
        assert_eq!(config.vtc_description.as_deref(), Some("First VTC"));
    }

    #[test]
    fn vtc_name_canonical_field_is_accepted() {
        let toml_src = r#"
            vtc_name = "Alpha"
            vtc_description = "Canonical"
        "#;
        let config: AppConfig = toml::from_str(toml_src).expect("canonical name parses");
        assert_eq!(config.vtc_name.as_deref(), Some("Alpha"));
    }

    #[test]
    fn invalid_toml_produces_config_error() {
        let err = toml::from_str::<AppConfig>("server.port = \"not-a-number\"")
            .expect_err("invalid port type must fail parse");
        let msg = format!("{err}");
        assert!(msg.contains("port"), "error must name the field: {msg}");
    }

    #[test]
    fn server_port_bounds() {
        // u16 range enforced by serde — 70000 must fail.
        let toml_src = r#"
            [server]
            port = 70000
        "#;
        let err =
            toml::from_str::<AppConfig>(toml_src).expect_err("out-of-range port must not parse");
        assert!(format!("{err}").contains("port"), "got {err}");
    }

    #[test]
    fn secrets_config_keyring_service_defaults_to_vtc() {
        // Keyring service name is per-service — VTC uses "vtc" so it
        // doesn't collide with a VTA running on the same host.
        let empty: AppConfig = toml::from_str("").unwrap();
        assert_eq!(empty.secrets.keyring_service, "vtc");
    }

    #[test]
    fn config_round_trip_preserves_fields() {
        // Serialize then parse — catches field additions that break
        // serialization symmetry (e.g. a serialize-only field that
        // can't parse back).
        let original: AppConfig = toml::from_str(
            r#"
            vtc_did = "did:key:zVTC"
            vta_did = "did:key:zVTA"
            vtc_name = "Round Trip"
            public_url = "https://vtc.example.com"
        "#,
        )
        .unwrap();

        let serialized = toml::to_string_pretty(&original).expect("serialize ok");
        let parsed: AppConfig = toml::from_str(&serialized).expect("re-parse ok");
        assert_eq!(parsed.vtc_did, original.vtc_did);
        assert_eq!(parsed.vta_did, original.vta_did);
        assert_eq!(parsed.vtc_name, original.vtc_name);
        assert_eq!(parsed.public_url, original.public_url);
    }
}
