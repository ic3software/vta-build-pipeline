#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "azure-secrets")]
mod azure;
#[cfg(feature = "config-seed")]
mod config;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "keyring")]
mod keyring;
#[cfg(feature = "tee")]
pub mod kms_tee;
mod plaintext;
#[cfg(feature = "vault-secrets")]
mod vault;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSeedStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureSeedStore;
#[cfg(feature = "config-seed")]
pub use config::ConfigSeedStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSeedStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSeedStore;
#[cfg(feature = "tee")]
pub use kms_tee::KmsTeeSeedStore;
pub use plaintext::PlaintextSeedStore;
#[cfg(feature = "vault-secrets")]
pub use vault::{VaultSeedStore, from_config as vault_from_config};

#[cfg(feature = "tee")]
use std::future::Future;
#[cfg(feature = "tee")]
use std::pin::Pin;

use crate::config::AppConfig;
use crate::error::AppError;

pub use vti_common::seed_store::SeedStore;

/// Local boxed-future alias mirroring `vti_common::seed_store::BoxFuture`,
/// used by the in-crate `kms_tee` backend's trait impl. Only compiled when
/// the `tee` feature pulls in that backend.
#[cfg(feature = "tee")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Create a seed store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `secrets.azure_vault_url` set)
/// 4. HashiCorp Vault (if `vault-secrets` compiled + `secrets.vault_addr` set)
/// 5. Config file seed (if `config-seed` compiled + `secrets.seed` set)
/// 6. OS keyring (if `keyring` compiled — the default)
/// 7. Plaintext file (always available — NOT secure)
///
/// `unused_variables` allowed: `config` is only read under specific
/// feature flags; a build with none of the cloud/keyring/config-seed
/// features compiled leaves it unused, which is fine — we fall through
/// to the plaintext backend. rustc's dead-code lint can't see through
/// the cfg-gated early returns.
#[allow(unused_variables)]
pub fn create_seed_store(config: &AppConfig) -> Result<Box<dyn SeedStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSeedStore::new(
            config.secrets.aws_secret_name.clone().unwrap(),
            config.secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if config.secrets.gcp_secret_name.is_some() {
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSeedStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "azure-secrets")]
    if config.secrets.azure_vault_url.is_some() {
        let vault_url = config.secrets.azure_vault_url.clone().unwrap();
        let secret_name = config
            .secrets
            .azure_secret_name
            .clone()
            .unwrap_or_else(|| "vta-master-seed".to_string());
        let store = AzureSeedStore::new(vault_url, secret_name);
        return Ok(Box::new(store));
    }

    #[cfg(feature = "vault-secrets")]
    if config.secrets.vault_addr.is_some() {
        let store = vault::from_config(&config.secrets)?;
        return Ok(Box::new(store));
    }

    #[cfg(feature = "config-seed")]
    if config.secrets.seed.is_some() {
        let store = ConfigSeedStore::new(config.secrets.seed.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSeedStore::new(&config.secrets.keyring_service, "master_seed");
        return Ok(Box::new(store));
    }

    // `unreachable_code` allowed: each of the `return Ok(...)` branches above
    // is `cfg(feature = ...)`-gated, so with every secure-backend feature
    // enabled (or none of them), this tail is or isn't actually reached.
    // Rustc can't resolve the combined cfg math — the allow is load-bearing
    // only when `keyring` is the selected feature.
    #[allow(unreachable_code)]
    {
        tracing::warn!(
            "no secure seed store backend available — falling back to plaintext file storage"
        );
        let store = PlaintextSeedStore::new(&config.store.data_dir);
        Ok(Box::new(store))
    }
}
