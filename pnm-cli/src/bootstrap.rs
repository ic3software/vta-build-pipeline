//! `pnm bootstrap` — sealed-transfer consumer commands.
//!
//! Phase 1 implements the offline (Mode C) consumer flow:
//!
//! - `pnm bootstrap request` generates a fresh Ed25519 keypair, persists the
//!   seed on disk under `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`,
//!   and writes a `BootstrapRequest` JSON (`client_did` as `did:key`) the
//!   operator can hand to the producer.
//! - `pnm bootstrap open` reads an armored sealed bundle, looks up the seed
//!   by bundle_id, derives the X25519 HPKE secret, opens the bundle, prints
//!   the payload, and (for `AdminCredential` payloads) optionally hands off
//!   to `pnm auth login` so the new credential is installed in the keyring.
//!
//! `--expect-digest <hex>` is required by default. `--no-verify-digest` is
//! available but prints a warning — there is no silent TOFU.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vta_sdk::attestation::verify_nitro_assertion;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, ed25519_seed_to_x25519_secret,
    generate_ed25519_keypair, open_bundle,
};

use crate::auth;
use crate::config;

const SECRETS_SUBDIR: &str = "bootstrap-secrets";

fn secrets_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = config::config_dir()?.join(SECRETS_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        // Restrict to owner on every supported platform — the directory
        // itself reveals nothing, but the files inside contain raw
        // 32-byte Ed25519 seeds.
        if let Err(e) = vta_cli_common::secure_file::restrict_dir_to_owner(&dir) {
            eprintln!(
                "warning: could not restrict {} to owner ({e}) — secrets may be \
                 accessible to other local users",
                dir.display()
            );
        }
    }
    Ok(dir)
}

fn secret_path(bundle_id_hex: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(secrets_dir()?.join(format!("{bundle_id_hex}.key")))
}

fn write_secret(path: &Path, secret: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    // Unix: open atomically with 0600 so the file is never publicly
    // readable between create and chmod. Windows: post-open DACL via
    // `restrict_file_to_owner` (see `secure_file` for details).
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path)?;
    file.write_all(secret)?;
    drop(file);
    if let Err(e) = vta_cli_common::secure_file::restrict_file_to_owner(path) {
        eprintln!(
            "warning: could not restrict {} to owner ({e}) — secret may be readable \
             by other local users",
            path.display()
        );
    }
    Ok(())
}

fn read_secret(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("secret file {} is not 32 bytes", path.display()).into())
}

use vta_sdk::hex::lower as hex_lower;

/// `pnm bootstrap request --out <PATH> [--label <NAME>]`
pub async fn run_request(
    out: PathBuf,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (seed, public) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);

    let path = secret_path(&bundle_id_hex)?;
    write_secret(&path, &seed)?;

    let request = BootstrapRequest::new(public, nonce, label);
    let json = serde_json::to_string_pretty(&request)?;
    fs::write(&out, json.as_bytes())?;

    println!("Bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:  {bundle_id_hex}");
    println!("  Client DID: {}", request.client_did);
    println!("  Seed saved: {}", path.display());
    println!();
    println!("Hand the request to the producer. They will return an armored bundle.");
    println!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    println!("  pnm bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `pnm bootstrap provision-request` — consumer-side. Generate a
/// VP-framed `BootstrapRequest` for the provision-integration flow.
///
/// Mints an ephemeral Ed25519 keypair, persists the seed under
/// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`, and writes a
/// signed VP naming the target DID template + variables. Hand the JSON
/// to the VTA operator's `vta bootstrap provision-integration` or
/// `pnm bootstrap provision-integration` (authed bridge) and decrypt
/// the returned bundle with `pnm bootstrap open`.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_request(
    template: String,
    vars: Vec<String>,
    context_hint: Option<String>,
    admin_template: Option<String>,
    validity_hours: f64,
    label: Option<String>,
    out: PathBuf,
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

    let config_dir = config::config_dir()?;
    let created =
        vta_cli_common::sealed_consumer::create_provision_request(&config_dir, builder).await?;

    let json = serde_json::to_string_pretty(&created.request)?;
    fs::write(&out, json.as_bytes())?;

    println!("Provision bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:  {}", created.bundle_id_hex);
    println!("  Client DID: {}", created.client_did);
    println!("  Seed saved: {}", created.secret_path.display());
    println!();
    println!("Hand the request to the VTA operator. They will run:");
    println!("  vta bootstrap provision-integration --request <file> --out <bundle>");
    println!("(or `pnm bootstrap provision-integration` over REST against a live VTA).");
    println!();
    println!("Verify the returned digest out-of-band, then:");
    println!("  pnm bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// Parse a single `--var KEY=VALUE` argument. Value is tried as JSON
/// first; falls back to a plain string for unquoted values.
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

/// `pnm bootstrap open --bundle <PATH> [--expect-digest <HEX>] [--no-verify-digest]`
pub async fn run_open(
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
    expect_vta_did: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if expect_digest.is_none() && !no_verify_digest {
        return Err(
            "--expect-digest <hex> is required (or pass --no-verify-digest to opt out)".into(),
        );
    }
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }

    let armored = fs::read_to_string(&bundle_path)
        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
    let bundles = armor::decode(&armored)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one bundle in {}, found {}",
            bundle_path.display(),
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    let bundle_id_hex = hex_lower(&bundle.bundle_id);

    let secret_path = secret_path(&bundle_id_hex)?;
    if !secret_path.exists() {
        return Err(format!(
            "no stored secret for bundle_id {bundle_id_hex} (expected at {}). \
             Did you run `pnm bootstrap request` on this host?",
            secret_path.display()
        )
        .into());
    }
    let ed_seed = read_secret(&secret_path)?;
    let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);

    let opened = open_bundle(&x_secret, bundle, expect_digest.as_deref())?;

    println!("Sealed bundle opened.");
    println!();
    println!("  Bundle-Id:       {bundle_id_hex}");
    println!("  Digest (sha256): {}", bundle_digest(bundle));
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
            println!();
            println!("To install this credential, use the online bootstrap flow:");
            println!("  pnm bootstrap connect --vta-url <url> [--token <token>]");
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
            match expect_vta_did.as_deref() {
                Some(pinned) => {
                    use vta_sdk::provision_integration::template_verify::verify_template_bootstrap;
                    verify_template_bootstrap((**p).clone(), pinned, chrono::Duration::minutes(5))?;
                    println!();
                    println!("  \x1b[1;32m✓ VC verified against pinned VTA DID\x1b[0m");
                }
                None => {
                    println!();
                    println!("  \x1b[1;33m⚠ VC NOT verified — digest-only trust anchor.\x1b[0m");
                    println!(
                        "    Re-run with --expect-vta-did <did> to verify the authorization VC."
                    );
                }
            }
            println!();
            println!("Install via the provision-integration flow on the integration host.");
        }
    }

    // Best-effort cleanup of the now-used secret. The bundle_id is single-use
    // by design; keeping the secret around offers no value and slightly
    // expands the blast radius if the host is later compromised. Overwrite
    // the bytes with zeros before unlink so a casual forensic read can't
    // recover the seed from the freed blocks.
    if let Err(e) = vta_cli_common::sealed_consumer::zero_overwrite_and_remove(&secret_path) {
        eprintln!(
            "warning: could not remove used secret {}: {e}",
            secret_path.display()
        );
    }

    Ok(())
}

// ── online flow (Mode B — TEE first-boot attestation) ──────────────────

#[derive(Debug, Deserialize)]
struct BootstrapResponseWire {
    bundle: String,
    digest: String,
}

/// `pnm bootstrap connect --vta-url <URL> [--expect-digest <HEX>]`
///
/// Online TEE first-boot bootstrap. Generates an ephemeral Ed25519 keypair,
/// POSTs the `did:key` as `client_did` to `/bootstrap/request`, verifies
/// the attestation quote, installs the minted admin credential, and
/// registers the VTA under a slug in `pnm` config. Only the first successful
/// call against a fresh TEE VTA succeeds — the carve-out closes on success.
///
/// For non-TEE VTAs use `pnm setup` (temp did:key + admin grant via
/// `vta acl create` + auto-rotate on first authenticated connect).
pub async fn run_connect(
    vta_url: String,
    expect_digest: Option<String>,
    vta_slug: Option<String>,
    pnm_config: &mut crate::config::PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (ed_seed, ed_pub) = generate_ed25519_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);

    // Reuse the SDK's canonical wire type so pnm speaks the same shape the
    // server `BootstrapRequestBody` deserializes. Emits `client_did` as a
    // `did:key:z6Mk…` string.
    let body = BootstrapRequest::new(ed_pub, nonce, None);

    let url = format!("{}/bootstrap/request", vta_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("bootstrap request failed ({status}): {body}").into());
    }
    let wire: BootstrapResponseWire = resp.json().await?;

    // Optional client-side digest verification. Attestation + TLS give the
    // primary integrity anchor; this is a belt-and-suspenders check the
    // operator can opt into by communicating the digest out-of-band.
    if let Some(expected) = &expect_digest {
        if expected.to_ascii_lowercase() != wire.digest.to_ascii_lowercase() {
            return Err(format!(
                "server-reported digest {} does not match expected {}",
                wire.digest, expected
            )
            .into());
        }
    }

    let bundles = armor::decode(&wire.bundle)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one armored bundle from server, got {}",
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    if hex_lower(&bundle.bundle_id) != bundle_id_hex {
        return Err("server-returned bundle_id does not match our nonce".into());
    }

    // HPKE decryption uses the X25519 secret derived from our Ed25519 seed.
    let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);
    let opened = open_bundle(&x_secret, bundle, expect_digest.as_deref())?;

    // The attestation quote binds the did:key-visible bytes end-to-end:
    //   SHA256(client_ed25519 || bundle_id || producer_ed25519)
    // so we pass the raw Ed25519 pubkey we generated (the same bytes the
    // server decoded from `client_did`) rather than any X25519 derivative.
    let attest = verify_nitro_assertion(&opened.producer, &ed_pub, &nonce)?;
    println!("TEE attestation verified.");
    println!("  Enclave module: {}", attest.module_id);
    if !attest.pcr0_hex.is_empty() {
        println!("  PCR0:           {}", attest.pcr0_hex);
    }
    if !attest.pcr8_hex.is_empty() {
        println!("  PCR8:           {}", attest.pcr8_hex);
    }

    let credential = match opened.payload {
        SealedPayloadV1::AdminCredential(c) => c,
        other => {
            return Err(format!(
                "expected AdminCredential payload from online bootstrap, got {}",
                variant_name(&other)
            )
            .into());
        }
    };

    let slug = vta_slug.unwrap_or_else(|| default_slug(&credential.vta_did));
    pnm_config.vtas.insert(
        slug.clone(),
        crate::config::VtaConfig {
            name: slug.clone(),
            url: Some(vta_url.clone()),
            vta_did: Some(credential.vta_did.clone()),
        },
    );
    if pnm_config.default_vta.is_none() {
        pnm_config.default_vta = Some(slug.clone());
    }
    crate::config::save_config(pnm_config)?;

    let keyring_key = crate::config::vta_keyring_key(&slug);
    auth::store_session(
        &keyring_key,
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
        Some(&vta_url),
    )?;
    // Verify the credential works end-to-end before declaring success.
    auth::ensure_authenticated(&vta_url, &keyring_key).await?;

    println!();
    println!("Bootstrap complete.");
    println!("  VTA slug:   {slug}");
    println!("  Client DID: {}", credential.did);
    println!("  VTA DID:    {}", credential.vta_did);
    println!("  Digest:     {}", bundle_digest(bundle));
    Ok(())
}

/// `pnm bootstrap provision-integration` — bridge a VP-framed
/// BootstrapRequest to the VTA's `POST /bootstrap/provision-integration`
/// endpoint over the authenticated session, writing the returned
/// armored bundle to disk.
///
/// The VTA runs the same shared library fn as the offline
/// `vta bootstrap provision-integration` CLI; the difference is
/// transport only.
pub async fn run_provision_integration(
    client: &vta_sdk::client::VtaClient,
    request: PathBuf,
    context: Option<String>,
    assertion: String,
    vc_validity_seconds: Option<i64>,
    out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::http::{
        AssertionMode as WireAssertionMode, ProvisionIntegrationRequest,
    };

    // 1. Parse the integration's VP (but don't verify locally — the
    //    server does the authoritative verification).
    let request_json =
        fs::read_to_string(&request).map_err(|e| format!("read {}: {e}", request.display()))?;
    let vp: vta_sdk::provision_integration::BootstrapRequest = serde_json::from_str(&request_json)
        .map_err(|e| format!("parse BootstrapRequest (VP): {e}"))?;

    // 2. Resolve context: explicit > hint > fail. If both present they
    //    must agree.
    let target_context = resolve_target_context_wire(&vp, context)?;

    // 3. Map assertion flag.
    let assertion_mode = match assertion.as_str() {
        "did-signed" | "didsigned" | "did_signed" => WireAssertionMode::DidSigned,
        "pinned-only" | "pinnedonly" | "pinned_only" | "pinned" => WireAssertionMode::PinnedOnly,
        other => {
            return Err(format!(
                "invalid --assertion value '{other}' — use 'did-signed' or 'pinned-only'"
            )
            .into());
        }
    };

    // 4. Submit.
    let resp = client
        .provision_integration(ProvisionIntegrationRequest {
            request: vp,
            context: target_context.clone(),
            assertion: Some(assertion_mode),
            vc_validity_seconds,
        })
        .await?;

    // 5. Write bundle + print summary.
    fs::write(&out, resp.bundle.as_bytes()).map_err(|e| format!("write {}: {e}", out.display()))?;

    eprintln!(
        "Integration provisioned via {} — sealed bundle written to {}",
        client.base_url(),
        out.display()
    );
    eprintln!();
    eprintln!("  Bundle-Id:       {}", resp.summary.bundle_id_hex);
    eprintln!("  Context:         {target_context}");
    eprintln!("  Client DID:      {}", resp.summary.client_did);
    if resp.summary.admin_rolled_over {
        eprintln!(
            "  Admin DID:       {} (VTA-minted, rolled over from client)",
            resp.summary.admin_did
        );
        if let Some(ref admin_tpl) = resp.summary.admin_template_name {
            eprintln!("  Admin template:  {admin_tpl}");
        }
    } else {
        eprintln!("  Admin DID:       {} (== client)", resp.summary.admin_did);
    }
    eprintln!("  Integration DID: {}", resp.summary.integration_did);
    eprintln!(
        "  Template:        {} ({})",
        resp.summary.template_name, resp.summary.template_kind
    );
    eprintln!("  Secrets:         {}", resp.summary.secret_count);
    eprintln!("  Outputs:         {}", resp.summary.output_count);
    eprintln!("  SHA-256 digest:  {}", resp.digest);
    eprintln!();
    eprintln!(
        "Communicate the digest to the integration's operator out-of-band so they can\n  \
         verify the bundle on first boot:\n  \
         pnm bootstrap open --bundle <file> --expect-digest {}",
        resp.digest
    );
    Ok(())
}

fn resolve_target_context_wire(
    request: &vta_sdk::provision_integration::BootstrapRequest,
    explicit: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    use vta_sdk::provision_integration::BootstrapAsk;
    let hint = match &request.ask {
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

fn variant_name(p: &SealedPayloadV1) -> &'static str {
    match p {
        SealedPayloadV1::AdminCredential(_) => "AdminCredential",
        SealedPayloadV1::ContextProvision(_) => "ContextProvision",
        SealedPayloadV1::DidSecrets(_) => "DidSecrets",
        SealedPayloadV1::AdminKeySet(_) => "AdminKeySet",
        SealedPayloadV1::RawPrivateKey(_) => "RawPrivateKey",
        SealedPayloadV1::TemplateBootstrap(_) => "TemplateBootstrap",
    }
}

fn default_slug(vta_did: &str) -> String {
    vta_did.rsplit(':').next().unwrap_or("vta").to_string()
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
    fn parse_var_json_types_round_trip() {
        assert_eq!(parse_var("N=42").unwrap().1, Value::Number(42.into()));
        assert_eq!(parse_var("B=true").unwrap().1, Value::Bool(true));
        assert!(parse_var(r#"A=[1,2]"#).unwrap().1.is_array());
    }

    #[test]
    fn parse_var_value_may_contain_equals() {
        let (_, v) = parse_var("URL=https://m.example.com?x=1").unwrap();
        assert_eq!(v.as_str(), Some("https://m.example.com?x=1"));
    }

    #[test]
    fn parse_var_missing_equals_errors() {
        assert!(parse_var("LONELY").is_err());
    }

    #[test]
    fn parse_var_empty_key_errors() {
        assert!(parse_var("=value").is_err());
    }
}
