use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use bip39::Mnemonic;
use chrono::Utc;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::config::{
    AppConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, SecretsConfig, ServerConfig,
    ServicesConfig, StoreConfig,
};
use crate::contexts::{self, ContextRecord, store_context};
use crate::keys::seed_store::{SeedStore, create_seed_store};
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::store::{KeyspaceHandle, Store};
use crate::webvh_cli::cli_super_admin;

/// Create a seed application context and store it.
async fn create_seed_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    contexts::create_context(contexts_ks, id, name).await
}

/// Prompt the user to select which services to enable.
///
/// Returns `(rest_enabled, didcomm_enabled)`. At least one must be selected.
fn prompt_services() -> Result<(bool, bool), Box<dyn std::error::Error>> {
    let items = vec!["REST API", "DIDComm Messaging"];
    loop {
        let selected = MultiSelect::new()
            .with_prompt("Services to enable (select at least one)")
            .items(&items)
            .defaults(&[true, true])
            .interact()?;

        if selected.is_empty() {
            eprintln!("\x1b[31mPlease select at least one service.\x1b[0m");
            continue;
        }

        let rest = selected.contains(&0);
        let didcomm = selected.contains(&1);
        return Ok((rest, didcomm));
    }
}

/// Prompt for seed store backend configuration based on compiled features.
///
/// Dynamically builds a list of available backends and lets the user choose
/// when more than one is compiled. Supported backends:
/// - **aws-secrets**: AWS Secrets Manager
/// - **gcp-secrets**: GCP Secret Manager
/// - **config-seed**: hex-encoded seed stored in config.toml
/// - **keyring**: OS keyring (the default)
async fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();

    #[cfg(feature = "aws-secrets")]
    {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }

    #[cfg(feature = "gcp-secrets")]
    {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }

    #[cfg(feature = "azure-secrets")]
    {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }

    #[cfg(feature = "config-seed")]
    {
        labels.push("Config file (hex-encoded seed in config.toml)");
        tags.push("config");
    }

    #[cfg(feature = "keyring")]
    {
        labels.push("OS keyring");
        tags.push("keyring");
    }

    labels.push("Plaintext file (NOT recommended)");
    tags.push("plaintext");

    // If only one backend is compiled, use it without prompting
    let choice = if labels.len() == 1 {
        0
    } else {
        Select::new()
            .with_prompt("Seed storage backend")
            .items(&labels)
            .default(0)
            .interact()?
    };

    let tag = tags[choice];

    #[cfg(feature = "aws-secrets")]
    if tag == "aws" {
        return prompt_aws_secrets().await;
    }

    #[cfg(feature = "gcp-secrets")]
    if tag == "gcp" {
        return prompt_gcp_secrets().await;
    }

    #[cfg(feature = "azure-secrets")]
    if tag == "azure" {
        return prompt_azure_secrets().await;
    }

    #[cfg(feature = "config-seed")]
    if tag == "config" {
        // Marker: seed field will be populated with hex after mnemonic derivation
        return Ok(SecretsConfig {
            seed: Some(String::new()),
            ..Default::default()
        });
    }

    #[cfg(feature = "keyring")]
    if tag == "keyring" {
        return prompt_keyring_service(SecretsConfig::default());
    }

    if tag == "plaintext" {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
        eprintln!("║  Seeds will be stored in a plaintext file on disk.       ║");
        eprintln!("║  Use only for development or testing.                    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        return Ok(SecretsConfig::default());
    }

    // All compiled backends are covered above; this is truly unreachable
    unreachable!("selected backend tag does not match any compiled feature")
}

/// Prompt for the OS keyring service name.
///
/// Each VTA instance needs a unique keyring service name to store its seed
/// separately. The default is "vta".
#[cfg(feature = "keyring")]
fn prompt_keyring_service(
    mut config: SecretsConfig,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let service: String = Input::new()
        .with_prompt("Keyring service name (use a unique name per VTA instance)")
        .default("vta".into())
        .interact_text()?;
    config.keyring_service = service;
    Ok(config)
}

#[cfg(feature = "aws-secrets")]
async fn prompt_aws_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    // Prompt for region first so we can list secrets from that region
    let region: String = Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    // Try to list existing secrets
    let secret_name = match list_aws_secrets(region.as_deref()).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("AWS Secrets Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        aws_secret_name: Some(secret_name),
        aws_region: region,
        ..Default::default()
    })
}

/// List secret names from AWS Secrets Manager (single page).
#[cfg(feature = "aws-secrets")]
async fn list_aws_secrets(region: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut config_loader = aws_config::from_env();
    if let Some(region) = region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_owned()));
    }
    let sdk_config = config_loader.load().await;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

    let output = client.list_secrets().send().await?;
    let names: Vec<String> = output
        .secret_list()
        .iter()
        .filter_map(|entry| entry.name().map(String::from))
        .collect();
    Ok(names)
}

#[cfg(feature = "gcp-secrets")]
async fn prompt_gcp_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;

    // Try to list existing secrets
    let secret_name = match list_gcp_secrets(&project).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("GCP Secret Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        gcp_project: Some(project),
        gcp_secret_name: Some(secret_name),
        ..Default::default()
    })
}

/// List secret names from GCP Secret Manager (single page).
#[cfg(feature = "gcp-secrets")]
async fn list_gcp_secrets(project: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
        .build()
        .await?;
    let response = client
        .list_secrets()
        .set_parent(format!("projects/{project}"))
        .send()
        .await?;

    let prefix = format!("projects/{project}/secrets/");
    let names: Vec<String> = response
        .secrets
        .iter()
        .map(|s| s.name.strip_prefix(&prefix).unwrap_or(&s.name).to_owned())
        .collect();
    Ok(names)
}

#[cfg(feature = "azure-secrets")]
async fn prompt_azure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let vault_url: String = Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;

    let secret_name: String = Input::new()
        .with_prompt("Azure Key Vault secret name")
        .default("vta-master-seed".into())
        .interact_text()?;

    Ok(SecretsConfig {
        azure_vault_url: Some(vault_url),
        azure_secret_name: Some(secret_name),
        ..Default::default()
    })
}

pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTA setup wizard.\n");

    // 1. Config file path
    let default_path = config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path: String = Input::new()
        .with_prompt("Config file path")
        .default(default_path)
        .interact_text()?;
    let config_path = PathBuf::from(&config_path);

    if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. VTA name
    let vta_name: String = Input::new()
        .with_prompt("VTA name (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vta_name = if vta_name.is_empty() {
        None
    } else {
        Some(vta_name)
    };

    // 3. Services to enable
    let (enable_rest, enable_didcomm) = prompt_services()?;

    // 4. Public URL, host, port (only when REST is enabled)
    let (public_url, host, port) = if enable_rest {
        let public_url: String = Input::new()
            .with_prompt("Public URL for this VTA (leave empty to skip)")
            .allow_empty(true)
            .interact_text()?;
        let public_url = if public_url.is_empty() {
            None
        } else {
            Some(public_url)
        };

        let host: String = Input::new()
            .with_prompt("Server host")
            .default("0.0.0.0".into())
            .interact_text()?;

        let port: u16 = Input::new()
            .with_prompt("Server port")
            .default(8100u16)
            .interact_text()?;

        (public_url, host, port)
    } else {
        (
            None,
            ServerConfig::default().host,
            ServerConfig::default().port,
        )
    };

    // 6. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 7. Log format
    let log_format_items = &["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_format_items)
        .default(0)
        .interact()?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 8. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vta".into())
        .interact_text()?;

    // 9. If data directory already exists, offer to delete and start fresh
    let data_path = PathBuf::from(&data_dir);
    if data_path.exists() {
        let delete = Confirm::new()
            .with_prompt(format!(
                "Data directory \"{}\" already exists. Delete and start fresh?",
                data_dir
            ))
            .default(false)
            .interact()?;
        if delete {
            std::fs::remove_dir_all(&data_path)?;
            eprintln!("  Deleted existing data directory.");
        } else {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 10. Open the store so we can persist key records during DID creation
    let store = Store::open(&StoreConfig {
        data_dir: PathBuf::from(&data_dir),
    })?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_templates_ks = store.keyspace("did_templates")?;

    // Create seed application contexts
    let mut vta_ctx = create_seed_context(&contexts_ks, "vta", "Verifiable Trust Agent").await?;
    eprintln!("  Created application context: vta");

    // 10. BIP-39 mnemonic. Always generated — operator-supplied mnemonics
    // were removed because pasting one into a terminal exposes it to shell
    // history, scrollback, and clipboard. Use `vta keys rotate-seed
    // --mnemonic <phrase>` after setup if you need a specific seed.
    let mnemonic = generate_mnemonic_with_confirmation()?;

    // Prompt for seed store backend configuration
    let mut secrets_config = configure_secrets().await?;

    // Derive BIP-39 seed
    let seed = mnemonic.to_seed("");

    // Store seed via the configured backend
    if secrets_config.seed.is_some() {
        // config-seed backend: hex-encode seed into the config (persisted when config is saved)
        secrets_config.seed = Some(hex::encode(seed));
    } else {
        // All other backends: store via the seed store
        let seed_store = create_seed_store(&AppConfig {
            vta_did: None,
            vta_name: None,
            public_url: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: PathBuf::from("data/vta"),
            },
            services: ServicesConfig::default(),
            messaging: None,
            auth: AuthConfig::default(),
            audit: Default::default(),
            secrets: secrets_config.clone(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            resolver_url: None,
            config_path: config_path.clone(),
        })
        .map_err(|e| format!("{e}"))?;
        seed_store.set(&seed).await.map_err(|e| format!("{e}"))?;
    }

    // Create initial seed record (generation 0)
    let initial_seed_record = SeedRecord {
        id: 0,
        seed_hex: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(&keys_ks, &initial_seed_record).await?;
    set_active_seed_id(&keys_ks, 0).await?;

    // 11. Generate random JWT signing key
    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // Create a temporary AppConfig for the seed store (config hasn't been saved yet)
    let wizard_config = AppConfig {
        vta_did: None,
        vta_name: None,
        public_url: public_url.clone(),
        server: ServerConfig {
            host: host.clone(),
            port,
        },
        log: LogConfig::default(),
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
        },
        services: ServicesConfig::default(),
        messaging: None,
        auth: AuthConfig::default(),
        audit: Default::default(),
        secrets: secrets_config.clone(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: config_path.clone(),
    };
    let wizard_seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&wizard_config).map_err(|e| format!("{e}"))?);

    // 12. DIDComm messaging
    let messaging = if enable_didcomm {
        configure_messaging(
            &keys_ks,
            &imported_ks,
            &contexts_ks,
            &webvh_ks,
            &did_templates_ks,
            &*wizard_seed_store,
            &wizard_config,
        )
        .await?
    } else {
        None
    };

    // 13. VTA DID (after mediator so we can embed it as a service endpoint)
    let vta_did = create_vta_did(
        messaging.as_ref(),
        &public_url,
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &did_templates_ks,
        &*wizard_seed_store,
        &wizard_config,
    )
    .await?;

    // Update VTA context with the DID
    if let Some(ref did) = vta_did {
        vta_ctx.did = Some(did.clone());
        vta_ctx.updated_at = Utc::now();
        store_context(&contexts_ks, &vta_ctx)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // The VTA ACL starts empty. Admins add themselves via `pnm setup` (which
    // mints a temp did:key, asks the operator to grant it via `vta import-did`,
    // and auto-rotates on first connect). See the "What to do next" section
    // printed at the end of this wizard.
    let _ = &seed;

    // Flush all store writes to disk before exiting
    store.persist().await?;

    // 15. Save config
    let config = AppConfig {
        vta_did,
        vta_name,
        public_url: public_url.clone(),
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(data_dir),
        },
        services: ServicesConfig {
            rest: enable_rest,
            didcomm: enable_didcomm,
        },
        messaging,
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        audit: Default::default(),
        secrets: secrets_config,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: config_path.clone(),
    };
    config.save()?;

    // 16. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Seed stored in configured backend");
    // Print which seed backend was chosen
    {
        let mut _printed = false;
        #[cfg(feature = "aws-secrets")]
        if let Some(ref name) = config.secrets.aws_secret_name {
            let region = config
                .secrets
                .aws_region
                .as_deref()
                .unwrap_or("SDK default");
            eprintln!("  Seed backend: AWS Secrets Manager ({name} in {region})");
            _printed = true;
        }
        #[cfg(feature = "gcp-secrets")]
        if !_printed && let Some(ref name) = config.secrets.gcp_secret_name {
            let project = config.secrets.gcp_project.as_deref().unwrap_or("unknown");
            eprintln!("  Seed backend: GCP Secret Manager ({project}/{name})");
            _printed = true;
        }
        #[cfg(feature = "azure-secrets")]
        if !_printed && let Some(ref url) = config.secrets.azure_vault_url {
            let name = config
                .secrets
                .azure_secret_name
                .as_deref()
                .unwrap_or("vta-master-seed");
            eprintln!("  Seed backend: Azure Key Vault ({url}/{name})");
            _printed = true;
        }
        if !_printed && config.secrets.seed.is_some() {
            eprintln!("  Seed backend: config file (hex-encoded in config.toml)");
            _printed = true;
        }
        #[cfg(feature = "keyring")]
        if !_printed {
            eprintln!(
                "  Seed backend: OS keyring (service: \"{}\")",
                config.secrets.keyring_service
            );
        }
    }
    if let Some(name) = &config.vta_name {
        eprintln!("  VTA Name: {name}");
    }
    if let Some(url) = &config.public_url {
        eprintln!("  Public URL: {url}");
    }
    if let Some(did) = &config.vta_did {
        eprintln!("  VTA DID: {did}");
    }
    let mut svc_list = Vec::new();
    if config.services.rest {
        svc_list.push("REST");
    }
    if config.services.didcomm {
        svc_list.push("DIDComm");
    }
    eprintln!("  Services: {}", svc_list.join(", "));
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);
    if let Some(msg) = &config.messaging {
        eprintln!("  Mediator DID: {}", msg.mediator_did);
        if !msg.mediator_url.is_empty() {
            eprintln!("  Mediator URL: {}", msg.mediator_url);
        }
    }
    eprintln!("  Contexts: vta ({})", vta_ctx.base_path);
    eprintln!();
    eprintln!("\x1b[1;36m── What to do next ──\x1b[0m");
    eprintln!();
    eprintln!("  1. On your operator workstation (with the VTA still stopped),");
    eprintln!("     run `pnm setup` and choose \"Connect to an existing non-TEE");
    eprintln!("     VTA\". When it asks for the VTA DID, enter:");
    eprintln!();
    if let Some(did) = &config.vta_did {
        eprintln!("       \x1b[1m{did}\x1b[0m");
    } else {
        eprintln!("       (the VTA DID shown above)");
    }
    eprintln!();
    eprintln!("     `pnm setup` mints a temp did:key and prints an");
    eprintln!("     `vta import-did` command.");
    eprintln!();
    eprintln!("  2. Back on this host, run the `vta import-did` command pnm");
    eprintln!("     printed. This grants admin access to the temp did:key by");
    eprintln!("     writing to the local store — no network call, no running VTA");
    eprintln!("     required.");
    eprintln!();
    eprintln!("  3. Start the VTA:");
    eprintln!(
        "       \x1b[1mvta --config {}\x1b[0m",
        config_path.display()
    );
    eprintln!();
    eprintln!("     On the operator workstation's first authenticated command");
    eprintln!("     (e.g. `pnm health`), PNM rotates to a fresh long-lived");
    eprintln!("     did:key and removes the temp from the ACL.");
    eprintln!();
    eprintln!("  4. (Optional) To bootstrap additional admins, repeat steps 1–2");
    eprintln!("     on each operator's workstation before or after starting the");
    eprintln!("     VTA — `vta import-did` takes a store-level lock and must not");
    eprintln!("     run while the VTA process is holding the store open.");
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared DID creation helper
// ---------------------------------------------------------------------------

/// Interactive did:webvh creation using the operations layer.
///
/// Prompts for URL, offers simple/advanced mode, builds params, calls
/// `operations::create_did_webvh()`, and saves did.jsonl. Private keys stay
/// in the VTA's key store; consumers fetch them at runtime via
/// `GET /keys/{id}/secret`, not from a setup-time export.
///
/// `additional_services` lets callers inject custom services (e.g. mediator endpoints).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn build_wizard_did(
    label: &str,
    context_id: &str,
    additional_services: Option<Vec<serde_json::Value>>,
    add_mediator_service: bool,
    template: Option<String>,
    template_vars: std::collections::HashMap<String, serde_json::Value>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL
    let webvh_url = prompt_webvh_url(label)?;
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    // Simple vs advanced toggle
    let mode_options = &[
        "Simple — VTA creates keys and document (recommended)",
        "Advanced — provide your own document, keys, or pre-signed log",
    ];
    let mode_choice = Select::new()
        .with_prompt("DID creation mode")
        .items(mode_options)
        .default(0)
        .interact()?;

    let (did_document, did_log, signing_key_id, ka_key_id) = if mode_choice == 1 {
        // Advanced mode
        let adv_options = &[
            "Provide a DID Document template (VTA signs it)",
            "Import a pre-signed did.jsonl",
            "Use existing imported keys",
        ];
        let adv_choice = Select::new()
            .with_prompt("Advanced option")
            .items(adv_options)
            .default(0)
            .interact()?;

        match adv_choice {
            0 => {
                // Template mode
                let path: String = Input::new()
                    .with_prompt("Path to DID Document JSON file")
                    .interact_text()?;
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                let doc: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| format!("invalid JSON in {path}: {e}"))?;
                (Some(doc), None, None, None)
            }
            1 => {
                // Final mode
                let path: String = Input::new()
                    .with_prompt("Path to did.jsonl file")
                    .interact_text()?;
                let log = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                (None, Some(log), None, None)
            }
            _ => {
                // User-specified keys
                let signing: String = Input::new()
                    .with_prompt("Signing key ID (Ed25519)")
                    .interact_text()?;
                let ka: String = Input::new()
                    .with_prompt("Key-agreement key ID (X25519, leave empty to skip)")
                    .allow_empty(true)
                    .interact_text()?;
                let ka_id = if ka.is_empty() { None } else { Some(ka) };
                (None, None, Some(signing), ka_id)
            }
        }
    } else {
        (None, None, None, None)
    };

    // Portability (skip for final mode — document is already signed)
    let portable = if did_log.is_none() {
        Confirm::new()
            .with_prompt("Make this DID portable (can move to a different domain later)?")
            .default(true)
            .interact()?
    } else {
        true
    };

    // Pre-rotation count (skip for final mode)
    let pre_rotation_count = if did_log.is_none() {
        eprintln!();
        eprintln!("  \x1b[2mPre-rotation protects against key compromise by publishing hashes");
        eprintln!("  of future keys now. Recommended: 1-3 keys.\x1b[0m");
        Input::new()
            .with_prompt("Number of pre-rotation keys")
            .default(1u32)
            .interact_text()?
    } else {
        0
    };

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());

    let params = CreateDidWebvhParams {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(url_str.clone()),
        path: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document,
        did_log,
        set_primary: true,
        signing_key_id,
        ka_key_id,
        template,
        template_context: None,
        template_vars,
    };

    let result = operations::did_webvh::create_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        did_templates_ks,
        seed_store,
        config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "setup",
    )
    .await
    .map_err(|e| format!("{e}"))?;

    let final_did = result.did.clone();
    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Save did.jsonl (serverless mode returns it in the response)
    if let Some(ref log_entry) = result.log_entry {
        let default_file = format!("{label}-did.jsonl");
        let did_file: String = Input::new()
            .with_prompt("Save DID log to file")
            .default(default_file)
            .interact_text()?;

        std::fs::write(&did_file, log_entry)?;
        eprintln!("  DID log saved to: {did_file}");
        eprintln!();
        eprintln!("  \x1b[2mTo self-host this DID, upload {did_file} to:");
        eprintln!("  {url_str}\x1b[0m");
    }

    // DID secrets live in the VTA's key store and are fetched by consumers
    // (applications, mediators, the VTA itself) via `GET /keys/{id}/secret`
    // or the DIDComm equivalent at runtime. No setup-time export — the
    // setup wizard's output is the DID itself, not its secrets.
    Ok(final_did)
}

// ---------------------------------------------------------------------------
// DID creation steps
// ---------------------------------------------------------------------------

/// Guide the user through creating (or entering) a did:webvh DID for the VTA.
///
/// Uses the operations layer via `build_wizard_did()` with simple/advanced toggle.
///
/// Returns `Some(did_string)` or `None` if skipped.
#[allow(clippy::too_many_arguments)]
async fn create_vta_did(
    messaging: Option<&MessagingConfig>,
    public_url: &Option<String>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_options = &[
        "Create a new did:webvh DID",
        "Enter an existing DID",
        "Skip (no VTA DID for now)",
    ];
    let choice = Select::new()
        .with_prompt("VTA DID")
        .items(did_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            // Build additional services based on config
            let mut additional_services = Vec::new();
            let add_mediator = messaging.is_some();

            // Add VTA REST service endpoint if public URL is configured
            if let Some(url) = public_url {
                additional_services.push(json!({
                    "id": "{DID}#vta-rest",
                    "type": "VTARest",
                    "serviceEndpoint": url
                }));
            }

            let services = if additional_services.is_empty() {
                None
            } else {
                Some(additional_services)
            };

            let did = build_wizard_did(
                "VTA",
                "vta",
                services,
                add_mediator,
                None,
                std::collections::HashMap::new(),
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                did_templates_ks,
                seed_store,
                config,
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did: String = Input::new().with_prompt("VTA DID").interact_text()?;

            Ok(Some(did))
        }
        _ => Ok(None),
    }
}

/// Guide the user through DIDComm messaging configuration.
///
/// Offers three choices:
/// 1. Use an existing mediator DID (no URL needed — ATM resolves endpoints from the DID document)
/// 2. Create a new did:webvh mediator DID (creates a "mediator" context for key storage)
/// 3. Skip DIDComm messaging entirely
///
/// Returns `None` when the user chooses to skip.
#[allow(clippy::too_many_arguments)]
async fn configure_messaging(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<MessagingConfig>, Box<dyn std::error::Error>> {
    let options = &[
        "Use an existing mediator DID",
        "Create a new mediator DID (did:webvh)",
        "Do not use DIDComm messaging",
    ];
    let choice = Select::new()
        .with_prompt("DIDComm messaging")
        .items(options)
        .default(0)
        .interact()?;

    match choice {
        // Existing DID — no local keys or context needed
        0 => {
            let did: String = Input::new()
                .with_prompt("Mediator DID")
                .validate_with(|input: &String| -> Result<(), String> {
                    if input.starts_with("did:") {
                        Ok(())
                    } else {
                        Err("DID must start with 'did:' (e.g. did:webvh:... or did:key:...)".into())
                    }
                })
                .interact_text()?;

            Ok(Some(MessagingConfig {
                mediator_url: String::new(),
                mediator_did: did,
                mediator_host: None,
            }))
        }
        // Create new did:webvh — needs a mediator context
        1 => {
            // The mediator DID lives inside a trust context so its keys slot
            // into the normal context-scoped key hierarchy. Default id is
            // "mediator" but operators running more than one mediator on the
            // same VTA can differentiate (e.g. "mediator-eu", "mediator-us").
            let mediator_context: String = Input::new()
                .with_prompt("Trust context for the mediator DID")
                .default("mediator".to_string())
                .interact_text()?;
            let mediator_context = mediator_context.trim().to_string();
            if mediator_context.is_empty() {
                return Err("mediator context id cannot be empty".into());
            }

            let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;

            // Create mediator context
            let _med_ctx =
                create_seed_context(contexts_ks, &mediator_context, "DIDComm Messaging Mediator")
                    .await?;

            // Use the built-in `didcomm-mediator` template — a single
            // source of truth for the mediator DID document shape. Operators
            // who need a different shape can fork it via
            // `pnm did-templates init mediator > custom.json`, edit, and
            // upload to global or context scope. Resolution order is
            // context → global → builtin, so a stored `didcomm-mediator`
            // override at either scope shadows this built-in automatically.
            let mut template_vars: std::collections::HashMap<String, serde_json::Value> =
                std::collections::HashMap::new();
            template_vars.insert("URL".into(), json!(mediator_url));

            let mediator_did = build_wizard_did(
                &mediator_context,
                &mediator_context,
                None,
                false,
                Some("didcomm-mediator".into()),
                template_vars,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                did_templates_ks,
                seed_store,
                config,
            )
            .await?;

            Ok(Some(MessagingConfig {
                mediator_url,
                mediator_did,
                mediator_host: None,
            }))
        }
        // Skip DIDComm
        _ => Ok(None),
    }
}

/// Generate a fresh 24-word BIP-39 mnemonic, display it, and require the
/// operator to confirm they have saved it before returning. Used by the
/// interactive wizard.
///
/// The non-interactive (`--from <file>`) path uses
/// [`generate_mnemonic_silent`] instead — no display, no confirm, on the
/// assumption that the operator will run `pnm backup export` after the
/// first admin connects to capture the seed in an encrypted backup.
fn generate_mnemonic_with_confirmation() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let m = generate_mnemonic_silent()?;
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: Write down your mnemonic phrase and store it   ║");
    eprintln!("║  securely. It is the ONLY way to recover your keys.      ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("\x1b[1m{}\x1b[0m", m);
    eprintln!();

    let confirmed = Confirm::new()
        .with_prompt("I have saved my mnemonic phrase")
        .default(false)
        .interact()?;
    if !confirmed {
        return Err("Setup cancelled — please save your mnemonic before proceeding.".into());
    }
    Ok(m)
}

fn generate_mnemonic_silent() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    Ok(Mnemonic::from_entropy(&entropy)?)
}

/// Prompt the user for a URL (e.g. `https://example.com/dids/vta`) and convert
/// it to a [`WebVHURL`].  Re-prompts on invalid input.
pub(crate) fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Non-interactive setup (`vta setup --from <file>`)
// ---------------------------------------------------------------------------
//
// `WizardInputs` is the canonical schema for the TOML file consumed by
// `vta setup --from`. Field-level doc-comments are the source of truth for
// the schema — there is no separate spec doc, by design.
//
// Design choices:
// - Mnemonic input is intentionally absent. Setup always generates fresh.
//   Operators who need a known seed should run `vta keys rotate-seed
//   --mnemonic <phrase>` post-setup.
// - VTA DID and mediator DID creation only support "simple mode"
//   (operations layer with VTA-managed keys). The interactive wizard's
//   advanced options (template-from-file, pre-signed log import,
//   user-specified key IDs) are out of scope here — operators who need
//   those should use interactive setup.
// - `admin_did`, when set, runs the same logic as `vta bootstrap-admin`
//   at the end of apply: writes a super-admin ACL row and seals the VTA
//   atomically with the rest of setup.

/// TOML schema for `vta setup --from <file>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardInputs {
    /// Output path for the generated `config.toml`. The setup wizard refuses
    /// to overwrite an existing file; delete it first if you want to re-run.
    pub config_path: PathBuf,

    /// Optional human-readable name for this VTA. Surfaced in `vta config
    /// show` and `pnm setup`.
    #[serde(default)]
    pub vta_name: Option<String>,

    /// Public URL the VTA will advertise (e.g. `https://trust.example.com`).
    /// Used as the `VTARest` service endpoint when minting the VTA's DID.
    /// Optional — omit if this VTA is DIDComm-only or behind a private
    /// network.
    #[serde(default)]
    pub public_url: Option<String>,

    /// Where the on-disk fjall store lives.
    pub data_dir: PathBuf,

    /// What to do if `data_dir` already exists. Defaults to `error` (fail
    /// fast); set to `delete` for CI re-run patterns.
    #[serde(default)]
    pub data_dir_exists: ExistingDataDirPolicy,

    /// Which services to enable. Defaults to both REST and DIDComm.
    #[serde(default = "default_services")]
    pub services: ServicesConfig,

    /// HTTP server bind. Defaults to `0.0.0.0:8100`.
    #[serde(default)]
    pub server: ServerConfig,

    /// Logging. Defaults to text format at info level.
    #[serde(default)]
    pub log: LogConfig,

    /// Seed-store backend. Required — there is no implicit default because
    /// the choice is security-sensitive (each backend has different threat
    /// model and durability guarantees).
    pub secrets: SecretsBackendInput,

    /// DIDComm mediator configuration. Defaults to `skip`. Only meaningful
    /// when `services.didcomm = true`.
    #[serde(default)]
    pub messaging: MessagingInput,

    /// VTA DID configuration. Defaults to `skip`. A VTA without a DID can
    /// still serve REST traffic but cannot participate in DIDComm or sign
    /// VCs.
    #[serde(default)]
    pub vta_did: VtaDidInput,

    /// If set, after base setup completes the wizard runs the equivalent of
    /// `vta bootstrap-admin --did <X>` — writes a super-admin ACL row and
    /// seals the VTA atomically. Failure here aborts setup before declaring
    /// success.
    #[serde(default)]
    pub admin_did: Option<String>,

    /// Optional label attached to the seeded admin's ACL row.
    #[serde(default)]
    pub admin_label: Option<String>,
}

fn default_services() -> ServicesConfig {
    ServicesConfig {
        rest: true,
        didcomm: true,
    }
}

#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExistingDataDirPolicy {
    /// Refuse to proceed if `data_dir` already exists.
    #[default]
    Error,
    /// Recursively delete `data_dir` before initializing the store.
    Delete,
}

/// Per-backend seed-store config. The `backend` discriminator selects the
/// variant; required fields per variant are validated at deserialization
/// time via `serde(deny_unknown_fields)`.
#[derive(Debug, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretsBackendInput {
    /// OS keyring (libsecret / Keychain / Credential Vault). The
    /// `service` field defaults to `"vta"` but should be unique per VTA
    /// instance running on the same host.
    Keyring {
        #[serde(default = "default_keyring_service")]
        service: String,
    },
    /// Hex-encoded seed embedded in `config.toml`. **Not recommended** —
    /// the config file becomes a secret. Compiled in only when the
    /// `config-seed` feature is enabled.
    ConfigSeed,
    /// AWS Secrets Manager. `region` defaults to the SDK's default
    /// resolution chain.
    Aws {
        #[serde(default)]
        region: Option<String>,
        secret_name: String,
    },
    /// GCP Secret Manager.
    Gcp {
        project: String,
        secret_name: String,
    },
    /// Azure Key Vault.
    Azure {
        vault_url: String,
        secret_name: String,
    },
    /// Plaintext file under `data_dir`. **Not recommended** — for dev only.
    Plaintext,
}

fn default_keyring_service() -> String {
    "vta".into()
}

#[derive(Debug, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagingInput {
    /// No DIDComm mediator. The VTA will not participate in DIDComm flows.
    #[default]
    Skip,
    /// Point at a mediator DID that already exists. ATM resolves the
    /// endpoint from the DID document.
    Existing { did: String },
    /// Mint a new mediator DID using the built-in `didcomm-mediator`
    /// template. The mediator gets its own trust context (default name
    /// `"mediator"`).
    CreateMediator {
        #[serde(default = "default_mediator_context")]
        context: String,
        url: String,
    },
}

fn default_mediator_context() -> String {
    "mediator".into()
}

#[derive(Debug, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VtaDidInput {
    /// No VTA DID. REST works; DIDComm and VC issuance do not.
    #[default]
    Skip,
    /// Use a DID that already exists.
    Existing { did: String },
    /// Mint a new `did:webvh` for the VTA. Always uses the operations
    /// layer's "simple mode" (VTA generates keys + document).
    CreateWebvh {
        /// Hosting URL for the DID document, e.g.
        /// `https://trust.example.com/dids/vta`.
        url: String,
        /// Whether the DID is portable (can move to a different domain
        /// later). Default true.
        #[serde(default = "default_true")]
        portable: bool,
        /// Number of pre-rotation keys to publish (defence against key
        /// compromise). Default 1; recommended 1–3.
        #[serde(default = "default_pre_rotation_count")]
        pre_rotation_count: u32,
    },
}

fn default_true() -> bool {
    true
}

fn default_pre_rotation_count() -> u32 {
    1
}

/// Entry point for `vta setup --from <file>`.
pub async fn run_setup_from_file(file_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("read setup file {}: {e}", file_path.display()))?;
    let inputs: WizardInputs = toml::from_str(&raw)
        .map_err(|e| format!("parse setup file {}: {e}", file_path.display()))?;

    eprintln!(
        "Running non-interactive setup from {} ...",
        file_path.display()
    );
    apply_inputs(inputs).await
}

/// Run the setup wizard non-interactively from a deserialized
/// [`WizardInputs`]. Mirrors [`run_setup_wizard`] step-for-step but with
/// no prompts and no display of generated key material.
pub async fn apply_inputs(inputs: WizardInputs) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Refuse to overwrite an existing config — same stance as the
    //    interactive wizard. Operators who want a re-run can delete the
    //    file first.
    if inputs.config_path.exists() {
        return Err(format!(
            "config file {} already exists — delete it first to re-run setup",
            inputs.config_path.display()
        )
        .into());
    }

    // 2. Validate cross-field constraints. `messaging.create_mediator`
    //    needs `services.didcomm = true`, and so on.
    validate_inputs(&inputs)?;

    // 3. Handle data_dir conflict per policy.
    if inputs.data_dir.exists() {
        match inputs.data_dir_exists {
            ExistingDataDirPolicy::Error => {
                return Err(format!(
                    "data directory {} already exists — set data_dir_exists = \"delete\" to wipe and re-init",
                    inputs.data_dir.display()
                )
                .into());
            }
            ExistingDataDirPolicy::Delete => {
                std::fs::remove_dir_all(&inputs.data_dir)
                    .map_err(|e| format!("delete {}: {e}", inputs.data_dir.display()))?;
                eprintln!("  Deleted existing data directory.");
            }
        }
    }

    // 4. Open store + seed contexts.
    let store = Store::open(&StoreConfig {
        data_dir: inputs.data_dir.clone(),
    })?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_templates_ks = store.keyspace("did_templates")?;

    let mut vta_ctx = create_seed_context(&contexts_ks, "vta", "Verifiable Trust Agent").await?;
    eprintln!("  Created application context: vta");

    // 5. Mnemonic — silent generate, never displayed. Operator captures via
    //    `pnm backup export` after first admin connects.
    let mnemonic = generate_mnemonic_silent()?;
    let seed = mnemonic.to_seed("");

    // 6. Translate the typed backend choice into a SecretsConfig the
    //    seed-store factory can consume.
    let mut secrets_config = secrets_config_from_input(&inputs.secrets)?;

    // 7. Persist seed via the chosen backend.
    if matches!(inputs.secrets, SecretsBackendInput::ConfigSeed) {
        // config-seed backend: hex-encode seed into the config struct so
        // it gets written to config.toml at save time.
        secrets_config.seed = Some(hex::encode(seed));
    } else {
        let scratch_config = scratch_config_for_seed_store(
            inputs.data_dir.clone(),
            secrets_config.clone(),
            inputs.config_path.clone(),
        );
        let seed_store = create_seed_store(&scratch_config).map_err(|e| format!("{e}"))?;
        seed_store.set(&seed).await.map_err(|e| format!("{e}"))?;
    }

    // 8. Initial seed record + JWT signing key.
    let initial_seed_record = SeedRecord {
        id: 0,
        seed_hex: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(&keys_ks, &initial_seed_record).await?;
    set_active_seed_id(&keys_ks, 0).await?;

    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // 9. Build a scratch AppConfig the messaging/DID builders can use to
    //    open the seed store. The real AppConfig is constructed at the end
    //    once we have the VTA DID.
    let wizard_config = scratch_config_for_seed_store(
        inputs.data_dir.clone(),
        secrets_config.clone(),
        inputs.config_path.clone(),
    );
    let wizard_seed_store: Arc<dyn SeedStore> =
        Arc::from(create_seed_store(&wizard_config).map_err(|e| format!("{e}"))?);

    // 10. Messaging.
    let messaging = match &inputs.messaging {
        MessagingInput::Skip => None,
        MessagingInput::Existing { did } => Some(MessagingConfig {
            mediator_url: String::new(),
            mediator_did: did.clone(),
            mediator_host: None,
        }),
        MessagingInput::CreateMediator { context, url } => {
            let _med_ctx =
                create_seed_context(&contexts_ks, context, "DIDComm Messaging Mediator").await?;
            let mut template_vars: HashMap<String, serde_json::Value> = HashMap::new();
            template_vars.insert("URL".into(), json!(url));

            let mediator_did = create_simple_webvh_did(
                context,
                context,
                url,
                /* portable */ true,
                /* pre_rotation_count */ 1,
                /* additional_services */ None,
                /* add_mediator_service */ false,
                /* template */ Some("didcomm-mediator".into()),
                template_vars,
                &keys_ks,
                &imported_ks,
                &contexts_ks,
                &webvh_ks,
                &did_templates_ks,
                &*wizard_seed_store,
                &wizard_config,
            )
            .await?;

            Some(MessagingConfig {
                mediator_url: url.clone(),
                mediator_did,
                mediator_host: None,
            })
        }
    };

    // 11. VTA DID.
    let vta_did = match &inputs.vta_did {
        VtaDidInput::Skip => None,
        VtaDidInput::Existing { did } => Some(did.clone()),
        VtaDidInput::CreateWebvh {
            url,
            portable,
            pre_rotation_count,
        } => {
            let mut additional_services = Vec::new();
            if let Some(public_url) = &inputs.public_url {
                additional_services.push(json!({
                    "id": "{DID}#vta-rest",
                    "type": "VTARest",
                    "serviceEndpoint": public_url
                }));
            }
            let services = if additional_services.is_empty() {
                None
            } else {
                Some(additional_services)
            };
            let did = create_simple_webvh_did(
                "VTA",
                "vta",
                url,
                *portable,
                *pre_rotation_count,
                services,
                /* add_mediator_service */ messaging.is_some(),
                /* template */ None,
                HashMap::new(),
                &keys_ks,
                &imported_ks,
                &contexts_ks,
                &webvh_ks,
                &did_templates_ks,
                &*wizard_seed_store,
                &wizard_config,
            )
            .await?;
            Some(did)
        }
    };

    if let Some(ref did) = vta_did {
        vta_ctx.did = Some(did.clone());
        vta_ctx.updated_at = Utc::now();
        store_context(&contexts_ks, &vta_ctx)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // 12. Flush store and release the directory lock before any later step
    //     that re-opens it. fjall holds an exclusive lock per data dir, so
    //     the admin-seeding step (which reopens the store) would deadlock
    //     if these handles were still alive.
    store.persist().await?;
    drop(wizard_seed_store);
    drop(keys_ks);
    drop(imported_ks);
    drop(contexts_ks);
    drop(webvh_ks);
    drop(did_templates_ks);
    drop(store);

    // 13. Save AppConfig.
    let config = AppConfig {
        vta_did: vta_did.clone(),
        vta_name: inputs.vta_name.clone(),
        public_url: inputs.public_url.clone(),
        server: inputs.server.clone(),
        log: inputs.log.clone(),
        store: StoreConfig {
            data_dir: inputs.data_dir.clone(),
        },
        services: inputs.services.clone(),
        messaging: messaging.clone(),
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        audit: Default::default(),
        secrets: secrets_config,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: inputs.config_path.clone(),
    };
    config.save()?;

    // 14. Optional admin seeding + seal. Atomic from the operator's
    //    perspective — if seeding fails, setup as a whole fails (config is
    //    on disk but the VTA is not declared "ready").
    if let Some(ref admin_did) = inputs.admin_did {
        seed_initial_admin(&inputs.data_dir, admin_did, inputs.admin_label.clone()).await?;
    }

    // 15. Summary.
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete.\x1b[0m");
    eprintln!("  Config:   {}", config.config_path.display());
    eprintln!("  Data dir: {}", config.store.data_dir.display());
    if let Some(ref name) = config.vta_name {
        eprintln!("  Name:     {name}");
    }
    if let Some(ref url) = config.public_url {
        eprintln!("  URL:      {url}");
    }
    if let Some(ref did) = config.vta_did {
        eprintln!("  VTA DID:  {did}");
    }
    if let Some(ref msg) = config.messaging {
        eprintln!("  Mediator: {}", msg.mediator_did);
    }
    if let Some(admin) = &inputs.admin_did {
        eprintln!("  Admin:    {admin} (sealed)");
    } else {
        eprintln!();
        eprintln!("  ACL is empty. Seed the first admin with:");
        eprintln!("    vta bootstrap-admin --did <did:...> [--label <name>]");
    }
    eprintln!();
    eprintln!("  Mnemonic was generated and stored in the configured backend.");
    eprintln!("  Capture an encrypted backup after the first admin connects:");
    eprintln!("    pnm backup export --output vta-backup.vtabak");
    eprintln!();

    Ok(())
}

fn validate_inputs(inputs: &WizardInputs) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors: Vec<String> = Vec::new();

    if matches!(inputs.messaging, MessagingInput::CreateMediator { .. }) && !inputs.services.didcomm
    {
        errors.push("messaging.kind = \"create_mediator\" requires services.didcomm = true".into());
    }
    if matches!(inputs.messaging, MessagingInput::Existing { .. }) && !inputs.services.didcomm {
        errors.push("messaging.kind = \"existing\" requires services.didcomm = true".into());
    }
    if let MessagingInput::CreateMediator { context, .. } = &inputs.messaging
        && context.trim().is_empty()
    {
        errors.push("messaging.context cannot be empty".into());
    }
    if let VtaDidInput::CreateWebvh {
        pre_rotation_count, ..
    } = &inputs.vta_did
        && *pre_rotation_count > 32
    {
        errors.push(format!(
            "vta_did.pre_rotation_count = {pre_rotation_count} is unreasonably large (max 32)"
        ));
    }
    if let Some(did) = &inputs.admin_did
        && !did.starts_with("did:")
    {
        errors.push(format!(
            "admin_did = {did:?} must be a DID (starts with `did:`)"
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "setup file has {} validation error(s):\n  - {}",
            errors.len(),
            errors.join("\n  - ")
        )
        .into())
    }
}

fn secrets_config_from_input(
    input: &SecretsBackendInput,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    Ok(match input {
        SecretsBackendInput::Keyring { service } => {
            #[cfg(not(feature = "keyring"))]
            {
                let _ = service;
                return Err(
                    "keyring backend requested but vta-service was built without the `keyring` feature"
                        .into(),
                );
            }
            #[cfg(feature = "keyring")]
            {
                SecretsConfig {
                    keyring_service: service.clone(),
                    ..SecretsConfig::default()
                }
            }
        }
        SecretsBackendInput::ConfigSeed => {
            #[cfg(not(feature = "config-seed"))]
            {
                return Err(
                    "config_seed backend requested but vta-service was built without the `config-seed` feature"
                        .into(),
                );
            }
            #[cfg(feature = "config-seed")]
            {
                SecretsConfig {
                    seed: Some(String::new()), // populated with hex(seed) by caller
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Aws {
            region,
            secret_name,
        } => {
            #[cfg(not(feature = "aws-secrets"))]
            {
                let _ = (region, secret_name);
                return Err(
                    "aws backend requested but vta-service was built without the `aws-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "aws-secrets")]
            {
                SecretsConfig {
                    aws_secret_name: Some(secret_name.clone()),
                    aws_region: region.clone(),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Gcp {
            project,
            secret_name,
        } => {
            #[cfg(not(feature = "gcp-secrets"))]
            {
                let _ = (project, secret_name);
                return Err(
                    "gcp backend requested but vta-service was built without the `gcp-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "gcp-secrets")]
            {
                SecretsConfig {
                    gcp_project: Some(project.clone()),
                    gcp_secret_name: Some(secret_name.clone()),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Azure {
            vault_url,
            secret_name,
        } => {
            #[cfg(not(feature = "azure-secrets"))]
            {
                let _ = (vault_url, secret_name);
                return Err(
                    "azure backend requested but vta-service was built without the `azure-secrets` feature"
                        .into(),
                );
            }
            #[cfg(feature = "azure-secrets")]
            {
                SecretsConfig {
                    azure_vault_url: Some(vault_url.clone()),
                    azure_secret_name: Some(secret_name.clone()),
                    ..Default::default()
                }
            }
        }
        SecretsBackendInput::Plaintext => {
            eprintln!();
            eprintln!(
                "\x1b[1;33mWARNING: plaintext seed storage selected. NOT for production.\x1b[0m"
            );
            eprintln!();
            SecretsConfig::default()
        }
    })
}

fn scratch_config_for_seed_store(
    data_dir: PathBuf,
    secrets: SecretsConfig,
    config_path: PathBuf,
) -> AppConfig {
    AppConfig {
        vta_did: None,
        vta_name: None,
        public_url: None,
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: StoreConfig { data_dir },
        services: ServicesConfig::default(),
        messaging: None,
        auth: AuthConfig::default(),
        audit: Default::default(),
        secrets,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path,
    }
}

/// Mint a `did:webvh` via the operations layer with no interactive
/// prompts. Equivalent to the interactive `build_wizard_did` in "simple
/// mode" with all advanced options off.
#[allow(clippy::too_many_arguments)]
async fn create_simple_webvh_did(
    label: &str,
    context_id: &str,
    url: &str,
    portable: bool,
    pre_rotation_count: u32,
    additional_services: Option<Vec<serde_json::Value>>,
    add_mediator_service: bool,
    template: Option<String>,
    template_vars: HashMap<String, serde_json::Value>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    did_templates_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &AppConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = Url::parse(url).map_err(|e| format!("invalid DID URL {url:?}: {e}"))?;
    let webvh_url =
        WebVHURL::parse_url(&parsed).map_err(|e| format!("invalid webvh URL {url:?}: {e}"))?;
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::placeholder());

    let params = CreateDidWebvhParams {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(url_str),
        path: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template,
        template_context: None,
        template_vars,
    };

    let result = operations::did_webvh::create_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        did_templates_ks,
        seed_store,
        config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "setup",
    )
    .await
    .map_err(|e| format!("{e}"))?;

    let final_did = result.did.clone();
    eprintln!("  Created DID: {final_did}");

    // Save did.jsonl alongside other VTA data so operators can re-publish or
    // audit later. Single canonical location — no per-DID prompt as in the
    // interactive wizard.
    if let Some(ref log_entry) = result.log_entry {
        let log_dir = config.store.data_dir.join("did-logs");
        std::fs::create_dir_all(&log_dir)?;
        let log_path = log_dir.join(format!("{label}-did.jsonl"));
        std::fs::write(&log_path, log_entry)?;
        eprintln!("  DID log:     {}", log_path.display());
    }

    Ok(final_did)
}

/// Seed the first super-admin and seal the VTA. Library counterpart to
/// `vta bootstrap-admin --did <X>`.
///
/// Refuses to proceed if a seal or any super-admin already exists — for the
/// non-interactive setup flow this should never trip (we just initialised
/// the store), and tripping it indicates a bug or a corrupt re-run.
async fn seed_initial_admin(
    data_dir: &Path,
    did: &str,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::{acl, seal};

    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    let acl_ks = store.keyspace("acl")?;

    if let Some(existing) = seal::get_seal(&acl_ks).await? {
        return Err(format!(
            "VTA is already sealed (by {} on {}); cannot seed admin during setup",
            existing.sealed_by, existing.sealed_at
        )
        .into());
    }

    let entries = acl::list_acl_entries(&acl_ks).await?;
    let existing_super_admins: Vec<_> = entries
        .iter()
        .filter(|e| e.role == acl::Role::Admin && e.allowed_contexts.is_empty())
        .collect();
    if !existing_super_admins.is_empty() {
        return Err(format!(
            "found {} existing super admin(s); refusing to seed another during setup",
            existing_super_admins.len()
        )
        .into());
    }

    let entry = acl::AclEntry {
        did: did.to_string(),
        role: acl::Role::Admin,
        label,
        allowed_contexts: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        created_by: "cli:setup-from-file".into(),
        expires_at: None,
    };
    acl::store_acl_entry(&acl_ks, &entry).await?;
    let _seal_record = seal::seal(&acl_ks, did).await?;
    store.persist().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> Result<WizardInputs, Box<dyn std::error::Error>> {
        Ok(toml::from_str::<WizardInputs>(toml_str)?)
    }

    #[test]
    fn minimal_keyring_inputs_round_trip() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("minimal inputs should parse");
        assert!(matches!(
            inputs.secrets,
            SecretsBackendInput::Keyring { .. }
        ));
        assert!(matches!(inputs.messaging, MessagingInput::Skip));
        assert!(matches!(inputs.vta_did, VtaDidInput::Skip));
        assert!(inputs.admin_did.is_none());
    }

    #[test]
    fn unknown_field_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            bogus_field = "no"

            [secrets]
            backend = "keyring"
        "#;
        let err = parse(raw).expect_err("unknown top-level field should fail");
        assert!(err.to_string().contains("bogus_field"), "got: {err}");
    }

    #[test]
    fn create_mediator_without_didcomm_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"

            [messaging]
            kind = "create_mediator"
            url  = "http://localhost:8000"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        assert!(
            err.to_string().contains("services.didcomm = true"),
            "got: {err}"
        );
    }

    #[test]
    fn admin_did_validation_rejects_non_did() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            admin_did   = "not-a-did"

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        assert!(err.to_string().contains("admin_did"), "got: {err}");
    }

    #[test]
    fn full_inputs_parse() {
        let raw = r#"
            config_path = "/srv/vta/config.toml"
            data_dir    = "/srv/vta/data"
            vta_name    = "trust-prod-1"
            public_url  = "https://trust.example.com"
            admin_did   = "did:key:z6MkABC"
            admin_label = "ops-bootstrap"

            [services]
            rest    = true
            didcomm = true

            [server]
            host = "0.0.0.0"
            port = 7080

            [log]
            level  = "info"
            format = "json"

            [secrets]
            backend     = "aws"
            region      = "us-east-1"
            secret_name = "vta/prod/seed"

            [messaging]
            kind    = "create_mediator"
            context = "mediator"
            url     = "https://mediator.example.com"

            [vta_did]
            kind               = "create_webvh"
            url                = "https://trust.example.com/dids/vta"
            portable           = true
            pre_rotation_count = 2
        "#;
        let inputs = parse(raw).expect("full inputs should parse");
        assert_eq!(inputs.vta_name.as_deref(), Some("trust-prod-1"));
        assert!(matches!(inputs.secrets, SecretsBackendInput::Aws { .. }));
        validate_inputs(&inputs).expect("full inputs should validate");
    }
}
