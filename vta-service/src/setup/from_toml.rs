//! Non-interactive setup (`vta setup --from <file>`).
//!
//! [`WizardInputs`] is the canonical TOML schema. Field-level doc
//! comments are the source of truth for the schema — there is no
//! separate spec doc, by design. [`run_setup_from_file`] reads a TOML
//! file into `WizardInputs` and hands off to [`apply_inputs`], which
//! mirrors [`super::interactive::run_setup_wizard`] step-for-step but
//! with no prompts and no display of generated key material.
//!
//! Design choices (stable; change with care):
//! - Mnemonic input is intentionally absent. Setup always generates
//!   fresh. Operators who need a known seed should run
//!   `vta keys rotate-seed --mnemonic <phrase>` post-setup.
//! - VTA DID and mediator DID creation only support "simple mode"
//!   (operations layer with VTA-managed keys). The interactive
//!   wizard's advanced options (template-from-file, pre-signed log
//!   import, user-specified key IDs) are out of scope here —
//!   operators who need those should use interactive setup.
//! - `admin_did`, when set, runs the same logic as `vta
//!   bootstrap-admin` at the end of apply: writes a super-admin ACL
//!   row and seals the VTA atomically with the rest of setup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::config::{
    AppConfig, AuthConfig, LogConfig, MessagingConfig, SecretsConfig, ServerConfig, ServicesConfig,
    StoreConfig,
};
use crate::contexts::store_context;
use crate::keys::seed_store::{SeedStore, create_seed_store};
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::store::{KeyspaceHandle, Store};
use crate::webvh_cli::cli_super_admin;

use super::{create_seed_context, generate_mnemonic_silent};

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
    /// Mint a new `did:key` for the VTA. Uses BIP-32-derived Ed25519
    /// keys from the active seed — same derivation scheme as `did:webvh`
    /// but no external hosting needed. Ideal for local development and
    /// deployments that don't need webvh's portability/rotation.
    CreateDidKey,
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
/// [`WizardInputs`]. Mirrors [`super::interactive::run_setup_wizard`]
/// step-for-step but with no prompts and no display of generated key
/// material.
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
    let mut wizard_config = scratch_config_for_seed_store(
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
                /* is_vta_identity */ false,
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

    // Propagate the resolved mediator into the scratch config so the VTA DID
    // builder can embed `DIDCommMessaging` in the DID document. Without this,
    // `build_did_document_inner` sees `config.messaging == None` and silently
    // drops the service even when `add_mediator_service == true`.
    wizard_config.messaging = messaging.clone();

    // 11. VTA DID.
    let vta_did = match &inputs.vta_did {
        VtaDidInput::Skip => None,
        VtaDidInput::Existing { did } => Some(did.clone()),
        VtaDidInput::CreateDidKey => {
            let did =
                create_vta_did_key("vta", &keys_ks, &contexts_ks, &*wizard_seed_store).await?;
            Some(did)
        }
        VtaDidInput::CreateWebvh {
            url,
            portable,
            pre_rotation_count,
        } => {
            let services = super::build_vta_additional_services(
                &inputs.services,
                inputs.public_url.as_deref(),
            );
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
                /* is_vta_identity */ true,
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
        eprintln!("  ACL is empty. Seed the first admin:");
        eprintln!();
        eprintln!("    Option A (recommended, reversible) — grant admin access to an");
        eprintln!("    existing DID without sealing the VTA. Lets you add more admins");
        eprintln!("    later and re-run offline CLI commands:");
        eprintln!("      vta import-did --did <did:...> --role admin [--label <name>]");
        eprintln!();
        eprintln!("    Option B (one-time, seals the VTA) — for immutable-image");
        eprintln!("    deployments that should refuse any further offline CLI writes");
        eprintln!("    after first admin. Disables `acl`, `keys`, `import-did`,");
        eprintln!("    `export-admin` until you run `vta unseal`:");
        eprintln!("      vta bootstrap-admin --did <did:...> [--label <name>]");
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
    // REST requires a public URL — without it the VTA DID document
    // ends up with no `VTARest` service entry, leaving downstream
    // resolvers no way to reach the REST API. The interactive wizard
    // blocks this at prompt time; this rule does the same for the
    // `--from <toml>` path.
    if inputs.services.rest && inputs.public_url.as_deref().is_none_or(str::is_empty) {
        errors.push(
            "services.rest = true requires `public_url` to be set (e.g. \
             `public_url = \"https://vta.example.com\"`); without it the VTA DID \
             document has no REST service endpoint to publish"
                .into(),
        );
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

/// Mint a `did:key` for the VTA identity using a BIP-32-derived Ed25519
/// key from the active seed. Stores only the Ed25519 signing record at
/// `{did}#key-0`; the X25519 key-agreement secret is curve-converted
/// from Ed25519 at runtime (per the `did:key` spec) so a separate
/// `#key-1` record would be a misleading second source of truth. No
/// external hosting needed — `did:key` is self-resolving.
async fn create_vta_did_key(
    context_id: &str,
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
) -> Result<String, Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};

    use crate::keys;
    use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
    use vta_sdk::keys::KeyType as SdkKeyType;

    let active_seed_id = get_active_seed_id(keys_ks).await?;
    let seed = load_seed_bytes(keys_ks, seed_store, Some(active_seed_id)).await?;

    // Load context to get base derivation path
    let ctx = crate::contexts::get_context(contexts_ks, context_id)
        .await
        .map_err(|e| format!("{e}"))?
        .ok_or_else(|| format!("context '{context_id}' not found"))?;

    // Allocate a single BIP-32 path for the Ed25519 signing key. Unlike
    // did:webvh we do NOT allocate a second path for X25519 — it is
    // derived from the Ed25519 key at runtime.
    let signing_path = keys::paths::allocate_path(keys_ks, &ctx.base_path)
        .await
        .map_err(|e| format!("{e}"))?;

    let root = ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;
    let derivation_path: DerivationPath = signing_path
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;
    let derived = root
        .derive(&derivation_path)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    let signing_secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));
    let signing_pub = signing_secret
        .get_public_keymultibase()
        .map_err(|e| format!("{e}"))?;

    let did = format!("did:key:{signing_pub}");

    keys::save_key_record(
        keys_ks,
        &format!("{did}#key-0"),
        &signing_path,
        SdkKeyType::Ed25519,
        &signing_pub,
        "VTA signing key",
        Some(context_id),
        Some(active_seed_id),
    )
    .await?;

    // Derive and store sealed-transfer key for bootstrap assertions
    let st = keys::derive_sealed_transfer_key(
        &seed,
        &ctx.base_path,
        "VTA sealed-transfer producer-assertion key",
        keys_ks,
    )
    .await?;
    keys::save_sealed_transfer_key_record(
        &did,
        &st,
        keys_ks,
        Some(context_id),
        Some(active_seed_id),
    )
    .await?;

    eprintln!("  Created DID: {did}");

    Ok(did)
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
    is_vta_identity: bool,
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
        is_vta_identity,
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
    fn services_rest_without_public_url_rejected() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("validation should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("services.rest = true requires `public_url`"),
            "got: {err}"
        );
    }

    #[test]
    fn services_rest_with_empty_public_url_rejected() {
        // Operators sometimes leave the value as an empty string rather
        // than removing the key entirely; treat that as not-set.
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = ""

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        let err = validate_inputs(&inputs).expect_err("empty public_url must be rejected");
        assert!(
            err.to_string()
                .contains("services.rest = true requires `public_url`"),
            "got: {err}"
        );
    }

    #[test]
    fn services_rest_with_public_url_passes() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"
            public_url  = "https://vta.example.com"

            [services]
            rest    = true
            didcomm = false

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        validate_inputs(&inputs).expect("rest + public_url should pass");
    }

    #[test]
    fn services_rest_disabled_does_not_require_public_url() {
        let raw = r#"
            config_path = "/tmp/vta-test/config.toml"
            data_dir    = "/tmp/vta-test/data"

            [services]
            rest    = false
            didcomm = true

            [secrets]
            backend = "keyring"
        "#;
        let inputs = parse(raw).expect("parses");
        validate_inputs(&inputs).expect("rest disabled means public_url is optional");
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

    /// Catch drift between `WizardInputs` and the operator-facing example
    /// file at `docs/02-operating/examples/vta-setup.example.toml`. If you
    /// change the schema and forget to update the example, this test fails.
    #[test]
    fn shipped_example_parses() {
        let raw = include_str!("../../../docs/02-operating/examples/vta-setup.example.toml");
        let inputs = parse(raw).expect(
            "docs/02-operating/examples/vta-setup.example.toml must be valid against WizardInputs",
        );
        validate_inputs(&inputs).expect(
            "docs/02-operating/examples/vta-setup.example.toml must pass cross-field validation",
        );
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
