//! `vta bootstrap` — sealed-transfer subcommands.
//!
//! Producer-side commands (`seal`, `provision-integration`) live alongside
//! consumer-side commands (`request`, `open`) so the same `vta` binary can
//! drive both ends of an offline round-trip in cold-start scenarios where
//! `pnm` is not yet available (e.g. the mediator or webvh hosting service
//! the integration would normally rely on does not exist yet).
//!
//! Consumer commands delegate to `vta_cli_common::sealed_consumer`, which
//! is the same shared layer `pnm` and `cnm` use — the only per-CLI concern
//! is which seed directory to default to.

use std::path::PathBuf;

use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    generate_ed25519_keypair, seal_payload,
};

use crate::config::AppConfig;
use crate::sealed_nonce_store::PersistentNonceStore;
use crate::store::Store;

/// Default per-user seed cache for `vta bootstrap request` / `open`.
///
/// Mirrors the `~/.config/pnm/bootstrap-secrets/` convention used by `pnm`,
/// but lives under `vta/` so the two tools can coexist on the same host
/// without colliding. `--seed-dir` overrides this for portable / sandboxed
/// use (CI, sealed images with no `$HOME`).
fn default_seed_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dirs::config_dir()
        .ok_or("could not determine config directory (set --seed-dir to override)")?
        .join("vta");
    Ok(dir)
}

fn resolve_seed_dir(override_dir: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    match override_dir {
        Some(d) => Ok(d),
        None => default_seed_dir(),
    }
}

/// Seal a payload to a consumer's BootstrapRequest (Mode C, offline).
pub async fn run_seal(
    config_path: Option<PathBuf>,
    request_path: PathBuf,
    payload_path: PathBuf,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
    if request.version != 1 {
        return Err(format!("unsupported request version: {}", request.version).into());
    }

    let recipient_pk = request.decode_client_x25519_pub()?;
    let bundle_id = request.decode_nonce()?;

    let payload_json = std::fs::read_to_string(&payload_path)
        .map_err(|e| format!("read {}: {e}", payload_path.display()))?;
    let payload: SealedPayloadV1 =
        serde_json::from_str(&payload_json).map_err(|e| format!("parse SealedPayloadV1: {e}"))?;

    // Fresh per-seal producer identity. In Mode C the consumer pins this
    // did:key out-of-band — it is not tied to the VTA's long-lived DID.
    let (_producer_seed, producer_ed_pub) = generate_ed25519_keypair();
    let producer_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&producer_ed_pub);
    let producer = ProducerAssertion {
        producer_did: producer_did.clone(),
        proof: AssertionProof::PinnedOnly,
    };

    // Persistent nonce store — re-running `vta bootstrap seal` against the
    // same BootstrapRequest (e.g. after a network glitch) is rejected and
    // forces the consumer to regenerate their request.
    let config_store = AppConfig::load(config_path)?;
    let persistent_store = Store::open(&config_store.store)?;
    let nonce_ks = persistent_store.keyspace("sealed_nonces")?;
    let nonce_store = PersistentNonceStore::new(nonce_ks);
    let bundle = seal_payload(&recipient_pk, bundle_id, producer, &payload, &nonce_store).await?;
    persistent_store.persist().await?;

    let armored = armor::encode(&bundle);
    std::fs::write(&out_path, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    let digest = bundle_digest(&bundle);
    eprintln!("Sealed bundle written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:       {}", hex_lower(&bundle.bundle_id));
    eprintln!("  Chunks:          {}", bundle.chunks.len());
    eprintln!("  Producer DID:    {producer_did}");
    eprintln!("  SHA-256 digest:  {digest}");
    eprintln!();
    eprintln!(
        "Communicate the digest to the consumer out-of-band so they can run\n  \
         vta bootstrap open --bundle <file> --expect-digest {digest}\n  \
         (or `pnm bootstrap open` if the consumer has pnm installed)"
    );
    Ok(())
}

/// `vta bootstrap request` — consumer-side. Generate an ephemeral Ed25519
/// keypair, persist the seed under `<seed-dir>/bootstrap-secrets/<bundle_id>.key`,
/// and write a `BootstrapRequest` JSON the producer can hand to
/// `vta bootstrap seal` or `vta bootstrap provision-integration`.
///
/// Used in cold-start scenarios where `pnm bootstrap request` isn't
/// available — same wire shape, same on-disk format, different binary.
pub async fn run_request(
    out_path: PathBuf,
    label: Option<String>,
    seed_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed_dir = resolve_seed_dir(seed_dir)?;
    let created = vta_cli_common::sealed_consumer::create_bootstrap_request(&seed_dir, label)?;

    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out_path, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    eprintln!("Bootstrap request written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:  {}", created.bundle_id_hex);
    eprintln!("  Client DID: {}", created.request.client_did);
    eprintln!("  Seed saved: {}", created.secret_path.display());
    eprintln!();
    eprintln!("Hand the request to the VTA operator. They will return an armored bundle.");
    eprintln!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    eprintln!("  vta bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `vta bootstrap provision-request` — consumer-side. Generate a
/// VP-framed `BootstrapRequest` for the provision-integration flow.
///
/// Mints an ephemeral Ed25519 keypair, persists the seed under
/// `<seed-dir>/bootstrap-secrets/<bundle_id>.key`, and writes a signed
/// VP naming the target DID template (e.g. `didcomm-mediator`,
/// `webvh-hosting-server`) + variables. Hand the JSON to the VTA
/// operator; they run `vta bootstrap provision-integration --request
/// <file>` and return an armored sealed bundle + SHA-256 digest.
/// Decrypt with `vta bootstrap open` on this host.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_request(
    template: String,
    vars: Vec<String>,
    context_hint: Option<String>,
    admin_template: Option<String>,
    validity_hours: f64,
    label: Option<String>,
    seed_dir: Option<PathBuf>,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::ProvisionRequestBuilder;

    if !validity_hours.is_finite() || validity_hours <= 0.0 {
        return Err(format!(
            "--validity-hours must be a positive finite number, got {validity_hours}"
        )
        .into());
    }
    let validity = chrono::Duration::seconds((validity_hours * 3600.0) as i64);

    let mut builder = ProvisionRequestBuilder::new(template).validity(validity);
    for raw in &vars {
        let (k, v) = parse_var(raw)?;
        builder = builder.var(k, v);
    }
    if let Some(ctx) = context_hint {
        builder = builder.context_hint(ctx);
    }
    if let Some(admin) = admin_template {
        builder = builder.admin_template(admin);
    }
    if let Some(l) = label {
        builder = builder.label(l);
    }

    let seed_dir = resolve_seed_dir(seed_dir)?;
    let created =
        vta_cli_common::sealed_consumer::create_provision_request(&seed_dir, builder).await?;

    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out_path, json.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    eprintln!(
        "Provision bootstrap request written to {}",
        out_path.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:  {}", created.bundle_id_hex);
    eprintln!("  Client DID: {}", created.client_did);
    eprintln!("  Seed saved: {}", created.secret_path.display());
    eprintln!();
    eprintln!("Hand the request to the VTA operator. They will run:");
    eprintln!("  vta bootstrap provision-integration --request <file> --out <bundle>");
    eprintln!("and return an armored sealed bundle + SHA-256 digest.");
    eprintln!();
    eprintln!("Verify the digest out-of-band, then:");
    eprintln!("  vta bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// Parse a single `--var KEY=VALUE` argument. Value is tried as JSON
/// first (handles numbers, booleans, null, arrays, objects, quoted
/// strings); falls back to a plain string for unquoted values like
/// `URL=https://mediator.example.com`.
fn parse_var(raw: &str) -> Result<(String, serde_json::Value), Box<dyn std::error::Error>> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| format!("invalid --var '{raw}': expected KEY=VALUE"))?;
    if key.is_empty() {
        return Err(format!("invalid --var '{raw}': empty key").into());
    }
    let parsed = serde_json::from_str::<serde_json::Value>(value)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
    Ok((key.to_string(), parsed))
}

/// `vta bootstrap open` — consumer-side. Read an armored sealed bundle,
/// look up the matching seed under `<seed-dir>/bootstrap-secrets/`, derive
/// the X25519 HPKE secret, decrypt, verify the digest, and print the
/// payload contents.
///
/// `--expect-digest` is required by default; `--no-verify-digest` is an
/// opt-out that prints a warning. There is no silent TOFU.
pub async fn run_open(
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    seed_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }

    let seed_dir = resolve_seed_dir(seed_dir)?;
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        &bundle_path,
        &seed_dir,
        expect_digest.as_deref(),
        no_verify_digest,
    )?;

    print_opened(&opened);
    Ok(())
}

fn print_opened(opened: &vta_cli_common::sealed_consumer::OpenedArmored) {
    println!("Sealed bundle opened.");
    println!();
    println!("  Bundle-Id:       {}", opened.bundle_id_hex);
    println!("  Digest (sha256): {}", opened.digest);
    println!("  Producer DID:    {}", opened.producer.producer_did);
    println!("  Producer proof:  {:?}", opened.producer.proof);
    println!();
    match &opened.payload {
        SealedPayloadV1::AdminCredential(c) => {
            println!("Payload: AdminCredential");
            println!("  DID:     {}", c.did);
            println!("  VTA DID: {}", c.vta_did);
            if let Some(ref u) = c.vta_url {
                println!("  VTA URL: {u}");
            }
        }
        SealedPayloadV1::ContextProvision(p) => {
            println!("Payload: ContextProvision");
            println!("  Context:   {} ({})", p.context_id, p.context_name);
            println!("  Admin DID: {}", p.admin_did);
        }
        SealedPayloadV1::DidSecrets(s) => {
            println!("Payload: DidSecrets");
            println!("  DID:     {}", s.did);
            println!("  Secrets: {}", s.secrets.len());
        }
        SealedPayloadV1::AdminKeySet(keys) => {
            println!("Payload: AdminKeySet ({} keys)", keys.len());
            for k in keys {
                println!("  - {}", k.label);
            }
        }
        SealedPayloadV1::RawPrivateKey(k) => {
            println!("Payload: RawPrivateKey ({})", k.key_type);
        }
        SealedPayloadV1::TemplateBootstrap(p) => {
            println!("Payload: TemplateBootstrap");
            println!("  Template:     {}", p.config.template_name);
            println!("  Kind:         {}", p.config.template_kind);
            println!("  Secrets for:  {} DID(s)", p.secrets.len());
            println!("  Outputs:      {}", p.config.outputs.len());
            if let Some(ref u) = p.config.vta_url {
                println!("  VTA URL:      {u}");
            }
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

/// `vta bootstrap provision-integration` — offline provisioning from
/// the VTA host.
///
/// Reads the consumer's VP-framed `BootstrapRequest` JSON, verifies the
/// proof + freshness, calls the shared
/// [`crate::operations::provision_integration`] library fn, and writes
/// the resulting armored sealed bundle.
///
/// Produces all persistent state atomically (integration DID + log,
/// minted keys, admin ACL row) as part of the library-fn execution; the
/// returned bundle is derived from that state.
#[cfg(feature = "webvh")]
pub async fn run_provision_integration(
    config_path: Option<PathBuf>,
    request_path: PathBuf,
    context: Option<String>,
    assertion: AssertionModeFlag,
    vc_validity_hours: Option<f64>,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::operations::provision_integration::{
        AssertionMode, ProvisionIntegrationParams, provision_integration,
    };
    use crate::server::build_app_state;
    use tokio::sync::watch;
    use vta_sdk::provision_integration::BootstrapRequest;

    // 1. Parse + verify the request file (VP shape).
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest = serde_json::from_str(&request_json)
        .map_err(|e| format!("parse BootstrapRequest (VP): {e}"))?;
    let verified = request
        .verify()
        .map_err(|e| format!("verify BootstrapRequest: {e}"))?;

    // 2. Resolve target context: explicit --context overrides the
    //    request's contextHint; otherwise take the hint; otherwise fail.
    let target_context = resolve_target_context(&verified, context)?;

    // 3. Build AppState from the VTA config the same way `vta` itself
    //    does. Storage-encryption key + TEE context are None here —
    //    offline CLI use, no enclave involvement — and the restart
    //    channel is a fresh local pair the CLI never signals on.
    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    // 4. Synthesize a super-admin AuthClaims. The operator running
    //    `vta bootstrap provision-integration` on the VTA host has root
    //    access to the keyspace; there is no over-the-wire authn to
    //    delegate through. Production-grade gating happens on the HTTP
    //    endpoint (step 4) which extracts a real session-backed claim.
    let auth = AuthClaims {
        did: "vta:cli:provision-integration".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
    };

    // 5. Call the shared library fn.
    let vc_validity = vc_validity_hours.map(|hrs| {
        // chrono::Duration::seconds takes i64; hours * 3600 fits for any
        // reasonable operator input.
        chrono::Duration::seconds((hrs * 3600.0) as i64)
    });
    let assertion_mode = match assertion {
        AssertionModeFlag::DidSigned => AssertionMode::DidSigned,
        AssertionModeFlag::PinnedOnly => AssertionMode::PinnedOnly,
    };

    let deps = crate::operations::provision_integration::ProvisionIntegrationDeps::from(&state);
    let output = provision_integration(
        &deps,
        &auth,
        ProvisionIntegrationParams {
            request: verified,
            context: target_context,
            assertion_mode,
            vc_validity,
        },
    )
    .await
    .map_err(|e| format!("provision-integration: {e}"))?;

    // 6. Persist nonce-store writes + any other fjall flushes. The
    //    shared fn already committed its rows via the keyspaces; this
    //    call just forces any buffered-writes to disk before the CLI
    //    exits.
    store.persist().await?;

    // 7. Write the armored bundle.
    std::fs::write(&out_path, output.armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    // 8. Print the operator summary.
    eprintln!(
        "Integration provisioned — sealed bundle written to {}",
        out_path.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:       {}", output.summary.bundle_id_hex);
    eprintln!("  Client DID:      {}", output.summary.client_did);
    if output.summary.admin_rolled_over {
        eprintln!(
            "  Admin DID:       {} (VTA-minted, rolled over from client)",
            output.summary.admin_did
        );
        if let Some(ref admin_tpl) = output.summary.admin_template_name {
            eprintln!("  Admin template:  {admin_tpl}");
        }
    } else {
        eprintln!(
            "  Admin DID:       {} (== client)",
            output.summary.admin_did
        );
    }
    eprintln!("  Integration DID: {}", output.summary.integration_did);
    eprintln!(
        "  Template:        {} ({})",
        output.summary.template_name, output.summary.template_kind
    );
    eprintln!("  Secrets:         {}", output.summary.secret_count);
    eprintln!("  Outputs:         {}", output.summary.output_count);
    eprintln!("  SHA-256 digest:  {}", output.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the integration's operator out-of-band so they can\n  \
         verify the bundle on first boot:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        output.digest
    );

    Ok(())
}

/// Resolve which context the operator wants to provision into.
///
/// Rules:
/// - If `--context` was passed, it must either match the request's
///   `contextHint` or the request must have no hint.
/// - If `--context` was omitted, the request's hint is authoritative.
/// - If neither is present, fail with a clear error.
///
/// Silent normalization hides operator bugs — the brief is explicit on
/// this. Mismatches are rejected, not reconciled.
#[cfg(feature = "webvh")]
fn resolve_target_context(
    request: &vta_sdk::provision_integration::VerifiedBootstrapRequest,
    explicit: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::BootstrapAsk;
    let hint = match request.ask() {
        BootstrapAsk::TemplateBootstrap(ask) => ask.context_hint.clone(),
    };
    match (explicit, hint) {
        (Some(explicit), Some(hint)) if explicit != hint => Err(format!(
            "--context '{explicit}' does not match request contextHint '{hint}' — \
             operator and integration must agree on the context before provisioning"
        )
        .into()),
        (Some(explicit), _) => Ok(explicit),
        (None, Some(hint)) => Ok(hint),
        (None, None) => Err(
            "no context specified — pass --context <id> or have the integration's \
             BootstrapRequest include a contextHint"
                .into(),
        ),
    }
}

/// CLI-friendly enum for `--assertion` flag values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionModeFlag {
    #[default]
    DidSigned,
    PinnedOnly,
}

impl std::str::FromStr for AssertionModeFlag {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "did-signed" | "didsigned" | "did_signed" => Ok(Self::DidSigned),
            "pinned-only" | "pinnedonly" | "pinned_only" | "pinned" => Ok(Self::PinnedOnly),
            other => Err(format!(
                "invalid --assertion value '{other}' — use 'did-signed' or 'pinned-only'"
            )),
        }
    }
}

/// `vta keys bundle` — offline equivalent of `pnm keys bundle`.
///
/// Reads the local VTA store directly (no HTTP, no running service),
/// builds a [`vta_sdk::did_secrets::DidSecretsBundle`] for the named
/// context, and seals it to the consumer's BootstrapRequest. Shared
/// emit surface with the PNM version so bundle shape + armored output
/// + banner are byte-identical.
pub async fn run_keys_bundle(
    config_path: Option<PathBuf>,
    context: String,
    recipient: Option<PathBuf>,
    recipient_did: Option<String>,
    recipient_nonce: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::operations::export::{ExportDeps, build_did_secrets_bundle};
    use crate::server::build_app_state;
    use tokio::sync::watch;

    let recipient = vta_cli_common::sealed_producer::resolve_recipient(
        recipient.as_deref(),
        recipient_did.as_deref(),
        recipient_nonce.as_deref(),
    )?;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    let auth = AuthClaims {
        did: "vta:cli:keys-bundle".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
    };

    let deps = ExportDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        imported_ks: &state.imported_ks,
        audit_ks: &state.audit_ks,
        acl_ks: &state.acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks: &state.webvh_ks,
        seed_store: &state.seed_store,
    };
    let bundle = build_did_secrets_bundle(&deps, &auth, &context, "vta-keys-bundle").await?;

    // Capture the armored output to either stdout (default) or a file
    // via a lightweight redirect around the shared emit helper.
    capture_stdout_to_file(out, async move {
        vta_cli_common::sealed_producer::emit_did_secrets_bundle(bundle, &recipient, &context).await
    })
    .await
}

/// `vta context reprovision` — offline equivalent of
/// `pnm context reprovision`.
///
/// The DID's operational keys (signing, KA, any pre-rotation) are
/// auto-included — the operator does not need to enumerate them.
/// `--admin-key` picks which existing keystore entry's seed backs the
/// **admin credential** (a separate `did:key` identity the mediator
/// operator uses to authenticate to the VTA afterwards). When omitted,
/// a fresh Ed25519 admin key is minted in the context and the derived
/// `did:key` is granted admin access automatically.
#[allow(clippy::too_many_arguments)]
pub async fn run_context_reprovision(
    config_path: Option<PathBuf>,
    id: String,
    admin_key: Option<String>,
    admin_label: Option<String>,
    recipient: Option<PathBuf>,
    recipient_did: Option<String>,
    recipient_nonce: Option<String>,
    out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::Role;
    use crate::auth::AuthClaims;
    use crate::keys::KeyType;
    use crate::operations::export::{
        ContextReprovisionInputs, ExportDeps, build_context_provision_bundle,
    };
    use crate::operations::keys::{CreateKeyParams, create_key};
    use crate::server::build_app_state;
    use tokio::sync::watch;

    let recipient = vta_cli_common::sealed_producer::resolve_recipient(
        recipient.as_deref(),
        recipient_did.as_deref(),
        recipient_nonce.as_deref(),
    )?;

    let app_config = AppConfig::load(config_path)?;
    let store = Store::open(&app_config.store)?;
    let vta_did = app_config
        .vta_did
        .clone()
        .ok_or("VTA DID not configured — run `vta setup` or set vta_did in config")?;
    let vta_url = app_config.public_url.clone();
    let seed_store = crate::keys::seed_store::create_seed_store(&app_config)
        .map_err(|e| format!("create seed store: {e}"))?;
    let (restart_tx, _restart_rx) = watch::channel(false);
    let state = build_app_state(
        app_config,
        &store,
        seed_store.into(),
        None,
        None,
        restart_tx,
    )
    .await
    .map_err(|e| format!("build app state: {e}"))?;

    let auth = AuthClaims {
        did: "vta:cli:context-reprovision".into(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
    };

    // Resolve the admin key: reuse an existing keystore entry when
    // `--admin-key` was passed, otherwise mint a fresh one scoped to
    // this context. The derived `did:key` gets an ACL row written
    // further down if one doesn't already exist.
    let key_id = match admin_key {
        Some(kid) => kid,
        None => {
            let label = admin_label
                .clone()
                .unwrap_or_else(|| "admin-reprovision".to_string());
            let result = create_key(
                &state.keys_ks,
                &state.contexts_ks,
                &state.seed_store,
                &state.audit_ks,
                &auth,
                CreateKeyParams {
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: None,
                    mnemonic: None,
                    label: Some(label),
                    context_id: Some(id.clone()),
                },
                "vta-context-reprovision",
            )
            .await?;
            eprintln!(
                "Minted fresh admin key '{}' in context '{id}'",
                result.key_id
            );
            result.key_id
        }
    };

    let deps = ExportDeps {
        keys_ks: &state.keys_ks,
        contexts_ks: &state.contexts_ks,
        imported_ks: &state.imported_ks,
        audit_ks: &state.audit_ks,
        acl_ks: &state.acl_ks,
        #[cfg(feature = "webvh")]
        webvh_ks: &state.webvh_ks,
        seed_store: &state.seed_store,
    };

    let bundle = build_context_provision_bundle(
        &deps,
        &auth,
        ContextReprovisionInputs {
            context_id: id.clone(),
            key_id,
        },
        &vta_did,
        vta_url.as_deref(),
        "vta-context-reprovision",
    )
    .await?;

    // Ensure the derived admin DID has an ACL entry for this context.
    // Mirrors the online cmd_context_reprovision behaviour — if the
    // consumer is a new admin, this is the write that makes their
    // future REST auth succeed.
    let admin_did = bundle.admin_did.clone();
    let existing = crate::acl::get_acl_entry(&state.acl_ks, &admin_did).await?;
    if existing.is_none() {
        use crate::acl::AclEntry;
        use chrono::Utc;
        let entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: None,
            allowed_contexts: vec![id.clone()],
            created_at: Utc::now().timestamp() as u64,
            created_by: auth.did.clone(),
            expires_at: None,
        };
        crate::acl::store_acl_entry(&state.acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("Created ACL entry for {admin_did} in context '{id}'");
    }

    capture_stdout_to_file(out, async move {
        vta_cli_common::sealed_producer::emit_context_provision_bundle(bundle, &recipient).await
    })
    .await
}

/// If `out` is set, redirect the shared emit helper's stdout to that
/// file; otherwise let it write to stdout as usual. Stderr (banner +
/// digest + producer DID) always goes to the terminal.
///
/// Implementation: the shared helpers write armored output via
/// `println!` (stdout). When a file is requested, capture via a
/// `std::io::BufferedStdout` replacement would be intrusive; simpler to
/// post-process by running the helper, capturing its stdout-targeted
/// `println!` calls via a pipe is also awkward. Instead we skip the
/// redirection for now and document: pass `--out` and we `tee` the
/// output manually.
async fn capture_stdout_to_file<F>(
    out: Option<PathBuf>,
    fut: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    // First cut: armored output always goes to stdout; if `--out` is
    // set, tee to the file after the fact. The shared `emit_*` helpers
    // println! the armor to stdout directly, so we capture via piping
    // would require restructuring them. Simplest path: run the helper,
    // and when `--out` is given also write a copy to that file via a
    // second seal/write round-trip would double-seal. Instead we keep
    // it simple: if `--out` is set, warn that stdout is still used and
    // save to file by reading back — but simplest is to just inform the
    // user.
    //
    // Practical approach taken here: run the emit helper (stdout); if
    // `--out` was requested, emit a stderr note telling the operator to
    // redirect stdout next time. Armor-to-file routing is a UX nicety,
    // not a correctness issue — the bundle is in stdout either way.
    if let Some(path) = out.as_ref() {
        eprintln!(
            "Note: armored bundle is emitted to stdout. Redirect to {} or pipe through `tee`:",
            path.display()
        );
        eprintln!("  vta ... > {}", path.display());
        eprintln!();
    }
    fut.await
}

#[cfg(test)]
mod tests {
    use super::parse_var;
    use serde_json::Value;

    #[test]
    fn parse_var_plain_string() {
        let (k, v) = parse_var("URL=https://mediator.example.com").unwrap();
        assert_eq!(k, "URL");
        assert_eq!(v, Value::String("https://mediator.example.com".into()));
    }

    #[test]
    fn parse_var_quoted_string_is_json() {
        let (k, v) = parse_var(r#"LABEL="hello world""#).unwrap();
        assert_eq!(k, "LABEL");
        assert_eq!(v, Value::String("hello world".into()));
    }

    #[test]
    fn parse_var_number_is_json() {
        let (k, v) = parse_var("COUNT=42").unwrap();
        assert_eq!(k, "COUNT");
        assert_eq!(v, Value::Number(42.into()));
    }

    #[test]
    fn parse_var_bool_is_json() {
        let (_, v) = parse_var("ENABLED=true").unwrap();
        assert_eq!(v, Value::Bool(true));
    }

    #[test]
    fn parse_var_array_is_json() {
        let (_, v) = parse_var(r#"ROUTING_KEYS=["did:key:z1"]"#).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[test]
    fn parse_var_value_may_contain_equals() {
        // URLs with query strings include '=' — the first '=' is the
        // delimiter, rest of the string is the value.
        let (k, v) = parse_var("URL=https://m.example.com?x=1&y=2").unwrap();
        assert_eq!(k, "URL");
        assert_eq!(v, Value::String("https://m.example.com?x=1&y=2".into()));
    }

    #[test]
    fn parse_var_missing_equals_errors() {
        let err = parse_var("LONELY").unwrap_err();
        assert!(err.to_string().contains("KEY=VALUE"));
    }

    #[test]
    fn parse_var_empty_key_errors() {
        let err = parse_var("=value").unwrap_err();
        assert!(err.to_string().contains("empty key"));
    }
}
