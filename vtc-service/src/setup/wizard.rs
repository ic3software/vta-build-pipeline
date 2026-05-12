//! `vtc setup` interactive wizard.
//!
//! Drives the VTA-provisioned bootstrap of a fresh VTC daemon per
//! `tasks/vtc-mvp/vta-driven-keys.md` §3:
//!
//! 1. Prompt the operator for the five configuration knobs (config
//!    path, VTC URL, admin UX URL, VTA URL, VTA DID, context).
//! 2. Mint an ephemeral `did:key` for the round-trip.
//! 3. Pause for the operator to authorize the ephemeral DID at the
//!    VTA (`pnm acl create --did <…> --role admin --contexts <ctx>`).
//! 4. Drive `vta_sdk::provision_client::run_provision` with
//!    `VtaIntent::FullSetup` + `ProvisionAsk::for_template
//!    ("vtc-host", { URL, ADMIN_UX_URL }, ctx)`.
//! 5. Open the sealed bundle; extract the `DidKeyMaterial` into a
//!    [`crate::setup::VtcKeyBundle`].
//! 6. Write the bundle into the chosen secret-store backend; the
//!    `did.jsonl` to `<data_dir>/did/<scid>.jsonl`; the config to
//!    `config.toml`. Mint an install token, print the URL.
//!
//! Refuses to re-run on an already-set-up daemon (config or seed
//! present).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use dialoguer::{Confirm, Input};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;
use tracing::warn;
use vta_sdk::provision_client::{
    EphemeralSetupKey, OperatorMessages, ProvisionAsk, ProvisionResult, VtaIntent, VtaReply,
    run_provision,
};

use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::setup::secrets_prompt::{
    AvailableBackends, BackendResolvers, SecretsBackendChoice, SecretsPromptError,
    configure_secrets,
};
use vti_common::store::Store;

use crate::config::{AppConfig, AuthConfig, LogConfig, SecretsConfig};
use crate::install::{
    INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenSigner, InstallTokenStore, mint_install_token,
};
use crate::keys::seed_store::create_secret_store;
use crate::setup::VtcKeyBundle;

/// Entry point bound to `Commands::Setup` in `main.rs`.
pub async fn run_setup_wizard(config_path: Option<PathBuf>) -> Result<(), AppError> {
    intro_banner();

    let config_path = prompt_config_path(config_path)?;
    refuse_if_already_set_up(&config_path)?;

    let inputs = prompt_inputs()?;

    // 1. Mint the ephemeral DID first so we can show it to the
    //    operator before they pick a secret-store backend (the
    //    pause for the ACL step is the slow part — get the
    //    decision-needed-from-the-operator instructions on screen
    //    before asking them anything else).
    let setup_key = EphemeralSetupKey::generate()
        .map_err(|e| AppError::Internal(format!("failed to generate ephemeral setup key: {e}")))?;
    print_acl_step(&inputs, &setup_key);
    if !Confirm::new()
        .with_prompt("Has the ACL grant been created at the VTA?")
        .default(false)
        .interact()
        .map_err(prompt_err)?
    {
        return Err(AppError::Validation("setup aborted".into()));
    }

    // 2. Pick a secrets-store backend. We delay this until after
    //    the ACL pause because the operator may want to interrupt
    //    setup at this point (e.g. realise they typed the VTA URL
    //    wrong); resolving the keyring path before the VTA
    //    round-trip avoids burning a useful slot at the storage
    //    layer.
    let secrets = prompt_secrets_config()?;

    // 3. Drive the provision-integration round-trip. Capture and
    //    discard event traffic so the wizard's UX stays terse —
    //    long-form progress UX is for `pnm`, not the daemon setup
    //    flow.
    let provision = run_provision_quietly(&inputs, &setup_key).await?;
    let integration_did = provision
        .integration_did()
        .ok_or_else(|| {
            AppError::Internal(
                "VTA returned a bundle with no integration DID — vtc-host template should mint \
                 one"
                .into(),
            )
        })?
        .to_string();
    let integration_key = provision.integration_key().ok_or_else(|| {
        AppError::Internal(
            "VTA returned a bundle with no integration key material — vtc-host bundle is \
             malformed"
                .into(),
        )
    })?;
    let bundle = VtcKeyBundle::from_did_key_material(integration_did.clone(), integration_key);

    // 4. Persist the did.jsonl log so the daemon's `GET
    //    /v1/{scid}/did.jsonl` route can serve it after restart.
    let did_log = provision.webvh_log().ok_or_else(|| {
        AppError::Internal(
            "vtc-host template did not produce a did.jsonl output — the VTC must be a did:webvh"
                .into(),
        )
    })?;
    let data_dir = default_data_dir_for(&config_path);
    let scid = extract_scid_or_err(&integration_did)?;
    write_did_log(&data_dir, &scid, did_log)?;

    // 5. Materialise the config + write it to disk so
    //    `create_secret_store` sees the chosen backend.
    let app_config = build_app_config(
        config_path.clone(),
        integration_did.clone(),
        inputs.vta_did.clone(),
        inputs.vtc_url.clone(),
        data_dir.clone(),
        secrets,
    )?;
    write_config_toml(&config_path, &app_config)?;

    // 6. Write the bundle into the secret store.
    let secret_store = create_secret_store(&app_config)
        .map_err(|e| AppError::Config(format!("failed to construct secret store: {e}")))?;
    let bundle_bytes = bundle.to_secret_store_bytes()?;
    secret_store
        .set(&bundle_bytes)
        .await
        .map_err(|e| AppError::SecretStore(format!("failed to store VTC key bundle: {e}")))?;

    // 7. Materialise the keyspaces so a `vtc` start doesn't have
    //    to pay the partition-create cost.
    open_keyspaces(&app_config)?;

    // 8. Mint a one-shot install token. The operator uses this to
    //    claim their admin passkey on the running daemon.
    let install_url = mint_initial_install_token(&app_config, &bundle, &inputs.vtc_url).await?;

    println!();
    println!("\x1b[1;32m✅ VTC setup complete.\x1b[0m");
    println!();
    println!("VTC DID:     {integration_did}");
    println!("Config:      {}", config_path.display());
    println!("Data dir:    {}", data_dir.display());
    println!();
    println!("\x1b[1mInstall URL (one-shot, 15 min TTL):\x1b[0m");
    println!("  {install_url}");
    println!();
    println!("Next steps:");
    println!("  1. Run `vtc` to start the daemon.");
    println!("  2. Open the install URL in your browser to claim your admin passkey.");
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Input collection
// ---------------------------------------------------------------------------

struct WizardInputs {
    vtc_url: String,
    admin_ux_url: String,
    vta_url: String,
    vta_did: String,
    context: String,
}

fn prompt_config_path(initial: Option<PathBuf>) -> Result<PathBuf, AppError> {
    let default = initial
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| std::env::var("VTC_CONFIG_PATH").ok())
        .unwrap_or_else(|| "config.toml".into());
    let path: String = Input::new()
        .with_prompt("Config file path")
        .default(default)
        .interact_text()
        .map_err(prompt_err)?;
    Ok(PathBuf::from(path))
}

fn refuse_if_already_set_up(config_path: &std::path::Path) -> Result<(), AppError> {
    if !config_path.exists() {
        return Ok(());
    }
    // Try parsing — if vtc_did is set, the VTC is already configured.
    if let Ok(existing) = AppConfig::load(Some(config_path.to_path_buf()))
        && existing.vtc_did.is_some()
    {
        return Err(AppError::Config(format!(
            "VTC already configured at {} (vtc_did = {:?}). \
             Move the config aside or pass `--config <other-path>` to set up a fresh community.",
            config_path.display(),
            existing.vtc_did
        )));
    }
    Ok(())
}

fn prompt_inputs() -> Result<WizardInputs, AppError> {
    println!();
    println!("Provisioning a fresh VTC requires four URLs and the VTA's DID + context.");
    println!();
    let vtc_url: String = Input::new()
        .with_prompt("VTC URL (e.g. https://vtc.example.com/v1)")
        .interact_text()
        .map_err(prompt_err)?;
    let admin_ux_url: String = Input::new()
        .with_prompt("Admin UX URL (e.g. https://admin.vtc.example.com)")
        .interact_text()
        .map_err(prompt_err)?;
    let vta_url: String = Input::new()
        .with_prompt("VTA URL (e.g. https://vta.example.com)")
        .interact_text()
        .map_err(prompt_err)?;
    let vta_did: String = Input::new()
        .with_prompt("VTA DID (e.g. did:webvh:vta.example.com:abc)")
        .interact_text()
        .map_err(prompt_err)?;
    let context: String = Input::new()
        .with_prompt("Context name at the VTA for this community")
        .default("default".into())
        .interact_text()
        .map_err(prompt_err)?;
    Ok(WizardInputs {
        vtc_url,
        admin_ux_url,
        vta_url,
        vta_did,
        context,
    })
}

fn prompt_secrets_config() -> Result<SecretsConfig, AppError> {
    let choice = configure_secrets(
        &AvailableBackends {
            keyring: cfg!(feature = "keyring"),
            aws: cfg!(feature = "aws-secrets"),
            gcp: cfg!(feature = "gcp-secrets"),
            azure: cfg!(feature = "azure-secrets"),
            inline_config: cfg!(feature = "config-secret"),
            plaintext: true,
        },
        "vtc",
        BackendResolvers::empty(),
    )
    .map_err(secrets_prompt_err)?;
    Ok(secrets_choice_to_config(choice))
}

fn secrets_choice_to_config(choice: SecretsBackendChoice) -> SecretsConfig {
    let mut config = SecretsConfig::default();
    match choice {
        SecretsBackendChoice::Keyring { service } => config.keyring_service = service,
        SecretsBackendChoice::Aws {
            secret_name,
            region,
        } => {
            config.aws_secret_name = Some(secret_name);
            config.aws_region = region;
        }
        SecretsBackendChoice::Gcp {
            project,
            secret_name,
        } => {
            config.gcp_project = Some(project);
            config.gcp_secret_name = Some(secret_name);
        }
        SecretsBackendChoice::Azure {
            vault_url,
            secret_name,
        } => {
            config.azure_vault_url = Some(vault_url);
            config.azure_secret_name = Some(secret_name);
        }
        SecretsBackendChoice::InlineConfig => {
            // The bundle bytes go into `secret` via the
            // `inline_secret:` wrapper on first `set`.
            config.secret = Some(String::new());
        }
        SecretsBackendChoice::Plaintext => {
            // No fields to populate — the plaintext store reads
            // from `store.data_dir`.
        }
    }
    config
}

// ---------------------------------------------------------------------------
// Provision-integration drive
// ---------------------------------------------------------------------------

async fn run_provision_quietly(
    inputs: &WizardInputs,
    setup_key: &EphemeralSetupKey,
) -> Result<ProvisionResult, AppError> {
    let mut vars = BTreeMap::new();
    vars.insert("URL".to_string(), JsonValue::String(inputs.vtc_url.clone()));
    vars.insert(
        "ADMIN_UX_URL".to_string(),
        JsonValue::String(inputs.admin_ux_url.clone()),
    );
    let ask = ProvisionAsk::for_template("vtc-host", vars, inputs.context.clone())
        .with_label("vtc-host integration");

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let drain_task = tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

    let reply = run_provision(
        VtaIntent::FullSetup,
        inputs.vta_did.clone(),
        setup_key.did.clone(),
        setup_key.private_key_multibase().to_string(),
        ask,
        None,
        Arc::new(VtcHostMessages),
        event_tx,
    )
    .await
    .map_err(|e| {
        AppError::Internal(format!(
            "VTA provisioning failed: {e}. Double-check the VTA URL/DID and that the \
             ephemeral DID was authorized via `pnm acl create`."
        ))
    })?;
    drain_task.abort();

    match reply {
        VtaReply::Full(result) => Ok(*result),
        VtaReply::AdminOnly(_) => Err(AppError::Internal(
            "VTA returned an admin-only reply but the vtc-host template requires a \
             FullSetup reply"
                .into(),
        )),
    }
}

/// `OperatorMessages` impl for the vtc-host integration kind.
struct VtcHostMessages;

impl OperatorMessages for VtcHostMessages {
    fn integration_label(&self) -> &str {
        "VTC"
    }
    fn integration_label_lower(&self) -> &str {
        "vtc"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm acl create --did {setup_did} --role admin --contexts {context_id} \\\n  \
             --expires 1h"
        )
    }
}

// ---------------------------------------------------------------------------
// Side outputs
// ---------------------------------------------------------------------------

fn write_did_log(data_dir: &std::path::Path, scid: &str, content: &str) -> Result<(), AppError> {
    let did_dir = data_dir.join("did");
    std::fs::create_dir_all(&did_dir).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("create did dir {}: {e}", did_dir.display()),
        ))
    })?;
    let path = did_dir.join(format!("{scid}.jsonl"));
    std::fs::write(&path, content).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("write did log {}: {e}", path.display()),
        ))
    })?;
    Ok(())
}

fn build_app_config(
    config_path: PathBuf,
    vtc_did: String,
    vta_did: String,
    public_url: String,
    data_dir: PathBuf,
    secrets: SecretsConfig,
) -> Result<AppConfig, AppError> {
    let toml_skeleton = format!(
        r#"
vtc_did = "{vtc_did}"
vta_did = "{vta_did}"
public_url = "{public_url}"

[store]
data_dir = "{}"
"#,
        data_dir.display(),
    );
    let mut config: AppConfig =
        toml::from_str(&toml_skeleton).map_err(|e| AppError::Config(format!("config: {e}")))?;
    config.secrets = secrets;
    config.auth = AuthConfig {
        jwt_signing_key: Some(generate_jwt_signing_key()),
        ..AuthConfig::default()
    };
    config.log = LogConfig::default();
    config.config_path = config_path;
    Ok(config)
}

fn generate_jwt_signing_key() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn write_config_toml(path: &std::path::Path, config: &AppConfig) -> Result<(), AppError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError::Io(std::io::Error::new(
                e.kind(),
                format!("create config dir {}: {e}", parent.display()),
            ))
        })?;
    }
    let serialised = toml::to_string_pretty(config)
        .map_err(|e| AppError::Config(format!("config serialise: {e}")))?;
    std::fs::write(path, serialised).map_err(|e| {
        AppError::Io(std::io::Error::new(
            e.kind(),
            format!("write config {}: {e}", path.display()),
        ))
    })?;
    Ok(())
}

fn open_keyspaces(config: &AppConfig) -> Result<(), AppError> {
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })?;
    for ks in [
        "sessions",
        "acl",
        "community",
        "config",
        "passkey",
        "install",
        "audit",
        "audit_key",
    ] {
        let _ = store.keyspace(ks)?;
    }
    Ok(())
}

async fn mint_initial_install_token(
    config: &AppConfig,
    bundle: &VtcKeyBundle,
    vtc_url: &str,
) -> Result<String, AppError> {
    let ed25519 = bundle.ed25519_private_bytes()?;
    let signer = InstallTokenSigner::from_master_seed(&*ed25519)?;
    let minted = mint_install_token(
        &signer,
        &bundle.integration_did,
        INSTALL_TOKEN_DEFAULT_TTL_SECS,
    )?;

    // Open the install keyspace to record the token. Open + close
    // in this short scope; the daemon opens its own at boot.
    let store = Store::open(&StoreConfig {
        data_dir: config.store.data_dir.clone(),
    })?;
    let install_ks = store.keyspace("install")?;
    let install_store = InstallTokenStore::new(install_ks);
    let exp = Utc::now() + ChronoDuration::seconds(INSTALL_TOKEN_DEFAULT_TTL_SECS as i64);
    install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
        )
        .await?;

    Ok(format!(
        "{}/install?token={}",
        vtc_url.trim_end_matches('/'),
        minted.jwt
    ))
}

// ---------------------------------------------------------------------------
// UX helpers
// ---------------------------------------------------------------------------

fn intro_banner() {
    println!();
    println!("\x1b[1;36m`vtc setup` — provision a fresh Verifiable Trust Community.\x1b[0m");
    println!();
    println!(
        "This wizard provisions the VTC's DID + keys against a running VTA, then writes the\n\
         daemon's config and the one-shot URL you'll use to claim your admin passkey."
    );
    println!();
}

fn print_acl_step(inputs: &WizardInputs, setup_key: &EphemeralSetupKey) {
    println!();
    println!("\x1b[1;33m── Operator action required ──\x1b[0m");
    println!();
    println!("Authorize this ephemeral DID at the VTA before continuing:");
    println!();
    println!("  DID:      {}", setup_key.did);
    println!("  Context:  {}", inputs.context);
    println!();
    println!(
        "Run on a machine with PNM admin access to {}:",
        inputs.vta_url
    );
    println!();
    println!(
        "  pnm acl create --did {} \\\n    --role admin --contexts {} --expires 1h",
        setup_key.did, inputs.context,
    );
    println!();
}

fn default_data_dir_for(config_path: &std::path::Path) -> PathBuf {
    config_path
        .parent()
        .map(|p| p.join("data"))
        .unwrap_or_else(|| PathBuf::from("data"))
}

fn extract_scid_or_err(did: &str) -> Result<String, AppError> {
    did.strip_prefix("did:webvh:")
        .and_then(|suffix| suffix.split(':').next_back())
        .map(str::to_string)
        .ok_or_else(|| AppError::Internal(format!("VTA returned non-webvh DID: {did}")))
}

fn prompt_err(e: dialoguer::Error) -> AppError {
    AppError::Internal(format!("interactive prompt failed: {e}"))
}

fn secrets_prompt_err(e: SecretsPromptError) -> AppError {
    match e {
        SecretsPromptError::Dialoguer(d) => prompt_err(d),
        other => {
            warn!(error = %other, "secrets prompt failed");
            AppError::Internal(format!("secrets prompt: {other}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_scid_from_webvh() {
        let scid = extract_scid_or_err("did:webvh:vtc.example.com:v1:abc123").unwrap();
        assert_eq!(scid, "abc123");
    }

    #[test]
    fn extract_scid_refuses_non_webvh() {
        let err = extract_scid_or_err("did:key:z6Mk…").unwrap_err();
        assert!(format!("{err}").contains("non-webvh"));
    }

    #[test]
    fn default_data_dir_sits_alongside_config() {
        let cfg = PathBuf::from("/etc/vtc/config.toml");
        assert_eq!(default_data_dir_for(&cfg), PathBuf::from("/etc/vtc/data"));
    }

    #[test]
    fn default_data_dir_falls_back_when_config_has_no_parent() {
        let cfg = PathBuf::from("config.toml");
        // PathBuf::parent() returns Some("") here on most platforms.
        let dir = default_data_dir_for(&cfg);
        assert!(dir.ends_with("data"));
    }

    #[test]
    fn secrets_choice_to_config_routes_keyring_to_keyring_service() {
        let choice = SecretsBackendChoice::Keyring {
            service: "custom-name".into(),
        };
        let config = secrets_choice_to_config(choice);
        assert_eq!(config.keyring_service, "custom-name");
    }

    #[test]
    fn secrets_choice_to_config_routes_aws_to_aws_fields() {
        let choice = SecretsBackendChoice::Aws {
            secret_name: "my-secret".into(),
            region: Some("us-east-1".into()),
        };
        let config = secrets_choice_to_config(choice);
        assert_eq!(config.aws_secret_name.as_deref(), Some("my-secret"));
        assert_eq!(config.aws_region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn vtc_host_messages_use_pnm_acl_command() {
        let msg = VtcHostMessages.pnm_admin_command_hint("ctx-x", "did:key:zAbc");
        assert!(msg.contains("pnm acl create"));
        assert!(msg.contains("--did did:key:zAbc"));
        assert!(msg.contains("--contexts ctx-x"));
        assert!(msg.contains("--expires 1h"));
    }
}
