use std::io::{self, BufRead, Write};

use dialoguer::{Input, Select};
use ed25519_dalek::SigningKey;
use rand::Rng;
use vta_sdk::prelude::*;

use crate::auth;
use crate::config::{PnmConfig, VtaConfig, save_config, slugify, vta_keyring_key};

/// Options for interactive setup from the CLI.
///
/// Kept as a struct for forward-compatibility — today there are no setup
/// flags (the wizard is fully interactive). `pnm setup` never ingests a
/// credential file: PNM always self-mints, then coordinates an ACL grant
/// + key rotation via the admin.
pub struct SetupOptions {}

/// Interactive setup for PNM.
///
/// Two paths:
/// - **Connect to an existing non-TEE VTA** — PNM mints a temp did:key
///   locally, tells the admin to add it to the ACL, and auto-rotates to a
///   fresh long-lived did:key on first successful authentication.
/// - **Set up a new VTA in a TEE** — operator is bootstrapping a brand new
///   enclave; generates an admin did:key to embed in the TEE config.
pub async fn run_setup(
    _opts: SetupOptions,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let choices = &[
        "Connect to an existing non-TEE VTA",
        "Set up a new VTA in a TEE  — generate admin identity for enclave deployment",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(choices)
        .default(0)
        .interact()?;

    match selection {
        0 => connect_to_non_tee_vta(config).await,
        1 => setup_tee(config).await,
        _ => unreachable!(),
    }
}

/// Connect to an existing non-TEE VTA.
///
/// PNM generates a temp did:key locally, stores the session flagged
/// `needs_rotation`, and prints an `vta acl create ...` command for the
/// admin to run. On first successful authentication, the session auto-
/// rotates to a fresh did:key and drops the temp from the ACL (see
/// `vta_sdk::session::SessionStore::ensure_authenticated`).
///
/// The operator does not need to reach the VTA during setup — rotation
/// happens the first time a command actually needs a token. Setup
/// succeeds even if the VTA is offline or the admin has not yet granted
/// the DID.
async fn connect_to_non_tee_vta(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    let url: String = Input::new()
        .with_prompt("VTA URL (e.g. https://vta.example.com)")
        .interact_text()?;
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err("VTA URL is required".into());
    }

    let vta_did: String = Input::new()
        .with_prompt("VTA DID (ask your admin, or see `vta config show`)")
        .interact_text()?;
    let vta_did = vta_did.trim().to_string();
    if !vta_did.starts_with("did:") {
        return Err("VTA DID must start with `did:` (e.g. did:webvh:... or did:key:...)".into());
    }

    let default_name = vta_did
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("my-vta")
        .to_string();
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default(default_name)
        .interact_text()?;

    let slug = slugify(&name);
    let keyring_key = vta_keyring_key(&slug);

    // Mint a temp admin did:key. This is the DID the user shares with the
    // admin; PNM rotates it out of the ACL the first time it successfully
    // authenticates, so an accidental leak over email/chat only exposes a
    // short-lived identity.
    let (bundle, did) =
        vta_cli_common::local_keygen::generate_admin_did_key(&vta_did, Some(url.clone()));

    auth::store_session_pending_rotation(
        &keyring_key,
        &did,
        &bundle.private_key_multibase,
        &vta_did,
        &url,
    )?;

    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: Some(url.clone()),
            vta_did: Some(vta_did.clone()),
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("\x1b[1;32mTemp admin identity created.\x1b[0m");
    eprintln!();
    eprintln!("  VTA:       {slug}  ({url})");
    eprintln!("  Temp DID:  {did}");
    eprintln!();
    eprintln!("Ask your VTA admin to grant this identity admin access. On the VTA host,");
    eprintln!("they should run:");
    eprintln!();
    eprintln!("  \x1b[1mvta acl create --did {did} --role admin\x1b[0m");
    eprintln!();
    eprintln!("Once the grant is in place, run any PNM command (e.g. `pnm health`). PNM");
    eprintln!("will automatically rotate to a fresh long-lived did:key on first connect");
    eprintln!("and remove the temp DID from the ACL.");
    eprintln!();

    Ok(())
}

/// Set up a new VTA for TEE deployment.
///
/// Single interactive session:
/// 1. Generate admin did:key (in memory)
/// 2. Print DID for config.toml
/// 3. Wait for operator to deploy + boot VTA
/// 4. Prompt for VTA DID
/// 5. Store credential in keyring, save config
///
/// The TEE admin identity is NOT rotated — it's the bootstrap key baked
/// into the TEE's config. Rotating it would break enclave boot.
async fn setup_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("This will create an admin identity for a VTA running in a");
    eprintln!("Trusted Execution Environment. The private key stays on this");
    eprintln!("machine and never touches the TEE or the parent instance.");
    eprintln!();

    // 1. Prompt for name
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default("my-tee-vta".to_string())
        .interact_text()?;
    let slug = slugify(&name);

    // 2. Generate random Ed25519 keypair (in memory only)
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);

    // 3. Print DID for config.toml
    eprintln!();
    eprintln!("Admin identity generated.");
    eprintln!();
    eprintln!("Add this to your VTA's deploy/nitro/config.toml under [tee.kms]:");
    eprintln!();
    println!("  admin_did = \"{did}\"");
    eprintln!();
    eprintln!("Then build the EIF and start the enclave.");

    // 4. Wait for VTA to be running
    eprintln!();
    eprint!("Press Enter once the VTA is running...");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;

    // 5. Prompt for VTA DID
    eprintln!();
    eprintln!("The VTA's DID is shown in its boot logs. You can also retrieve");
    eprintln!("it via: GET /attestation/did-log (if REST is enabled).");
    eprintln!();
    let vta_did: String = Input::new().with_prompt("VTA DID").interact_text()?;

    // 6. Prompt for mediator DID
    let mediator_did: String = Input::new().with_prompt("Mediator DID").interact_text()?;

    // 7. Store identity directly in the keyring. Bundle construction happens
    //    later, inside the TEE-first-boot flow, when the VTA is reachable.
    let keyring_key = vta_keyring_key(&slug);

    // Store session directly — the TEE admin identity does not rotate.
    auth::store_session(
        &keyring_key,
        &did,
        &private_key_multibase,
        &vta_did,
        "", // No REST URL in TEE mode
    )?;

    // 8. Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: None,
            vta_did: Some(vta_did.clone()),
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Admin DID:    {did}");
    eprintln!("  VTA DID:      {vta_did}");
    eprintln!("  Mediator DID: {mediator_did}");
    eprintln!("  Credential stored in keyring (key: {keyring_key})");
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }
    eprintln!();
    eprintln!("You can now run commands against this VTA:");
    eprintln!("  pnm health");
    eprintln!("  pnm keys list");

    Ok(())
}
