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
