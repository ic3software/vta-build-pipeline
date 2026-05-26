//! Offline `vta vault …` subcommands — direct fjall access for the
//! `vault:` keyspace. Daemon must be stopped (fjall exclusive lock); not
//! available in TEE deployments (the enclave's vsock-store is the only
//! reader/writer there). Same constraints as `vta acl`, `vta did-mgmt`, etc.
//!
//! M1 ships **seed only** — populates the keyspace from a JSON file or a
//! built-in three-entry demo set so operators can exercise vault/list/0.1
//! end-to-end before vault/upsert/0.1 lands in M2. `delete` and `list`
//! offline subcommands can follow if they prove useful; for now the dispatcher
//! handlers cover the read path.

use std::fs;
use std::path::{Path, PathBuf};

use vti_common::vault::{SecretKind, SiteTarget, VaultEntry, get_vault_entry, put_vault_entry};

use crate::config::AppConfig;
use crate::store::Store;

pub struct VaultSeedArgs {
    /// Optional path to config.toml — falls back to the default search path
    /// AppConfig::load uses.
    pub config_path: Option<PathBuf>,
    /// Path to a JSON file containing an array of VaultEntry objects.
    /// When omitted, three demo entries are seeded under `context`.
    pub entries_file: Option<PathBuf>,
    /// Trust context id the demo entries land under. Required when
    /// `entries_file` is omitted; ignored when entries supply their own
    /// `contextId`.
    pub context: Option<String>,
    /// Print the entries that would be seeded without writing.
    pub dry_run: bool,
    /// Overwrite an existing entry with the same id (otherwise the seeder
    /// fails fast — vault entries with stable ids generally shouldn't be
    /// silently rewritten).
    pub force: bool,
}

pub async fn run_vault_seed(args: VaultSeedArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let vault_ks = store.keyspace("vault")?;

    let entries: Vec<VaultEntry> = match (&args.entries_file, &args.context) {
        (Some(path), _) => load_entries_from_file(path)?,
        (None, Some(ctx)) => demo_entries(ctx),
        (None, None) => {
            return Err("either --entries-file <path> or --context <id> is required".into());
        }
    };

    if entries.is_empty() {
        eprintln!("No entries to seed.");
        return Ok(());
    }

    // Validate all entries up front before touching the store — this is the
    // bulk operation where partial failures would be the most confusing.
    for (i, e) in entries.iter().enumerate() {
        if e.id.is_empty() {
            return Err(format!("entry {i}: id is empty").into());
        }
        if e.context_id.is_empty() {
            return Err(format!("entry {i} ({}): contextId is empty", e.id).into());
        }
        if e.targets.is_empty() {
            return Err(format!("entry {i} ({}): targets is empty", e.id).into());
        }
        if e.label.is_empty() {
            return Err(format!("entry {i} ({}): label is empty", e.id).into());
        }
        if !args.force
            && let Some(existing) = get_vault_entry(&vault_ks, &e.id).await?
        {
            return Err(format!(
                "entry {} already exists (label={}, version={}); pass --force to overwrite",
                e.id, existing.label, existing.version
            )
            .into());
        }
    }

    if args.dry_run {
        eprintln!("[dry-run] would seed {} entries:", entries.len());
        for e in &entries {
            eprintln!(
                "  {} — {} ({})",
                e.id,
                e.label,
                secret_kind_label(e.secret_kind)
            );
        }
        return Ok(());
    }

    for e in &entries {
        put_vault_entry(&vault_ks, e).await?;
        eprintln!("seeded: {} ({})", e.label, e.id);
    }
    store.persist().await?;

    eprintln!();
    eprintln!("Seeded {} vault entries.", entries.len());
    eprintln!("Restart the VTA daemon, then click \"Load entries\" in the wallet popup.");
    Ok(())
}

fn load_entries_from_file(path: &Path) -> Result<Vec<VaultEntry>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let entries: Vec<VaultEntry> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {} as VaultEntry[]: {e}", path.display()))?;
    Ok(entries)
}

/// Built-in demo set — three entries that exercise every visible-in-UI
/// field of the metadata view (multiple targets including iOS, breach flag,
/// never-used entry, custom selectors, tags).
fn demo_entries(context_id: &str) -> Vec<VaultEntry> {
    let now = chrono::Utc::now().to_rfc3339();
    let stamp = stamp_suffix();
    vec![
        VaultEntry {
            id: format!("vault_demo_github_{stamp}"),
            context_id: context_id.into(),
            targets: vec![
                SiteTarget::WebOrigin {
                    origin: "https://github.com".into(),
                },
                SiteTarget::IosApp {
                    bundle_id: "com.github.stwalkerster.codehub".into(),
                    team_id: Some("VEKTX9H2N7".into()),
                },
            ],
            label: "Work GitHub".into(),
            secret_kind: SecretKind::Passkey,
            tags: vec!["work".into(), "engineering".into()],
            notes: None,
            favicon: None,
            selectors: vec!["recent_uv_required".into()],
            custom_field_names: vec![],
            attachments: vec![],
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: now.clone(),
            created_by: Some("cli:vault-seed".into()),
            updated_at: now.clone(),
            updated_by: None,
            last_used_at: Some("2026-05-25T22:11:00Z".into()),
            version: 1,
        },
        VaultEntry {
            id: format!("vault_demo_aws_{stamp}"),
            context_id: context_id.into(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://aws.amazon.com".into(),
            }],
            label: "Work AWS — root".into(),
            secret_kind: SecretKind::Password,
            tags: vec!["work".into(), "high-value".into()],
            notes: Some("Recovery email: ops@example.com".into()),
            favicon: None,
            selectors: vec!["step_up_push".into()],
            custom_field_names: vec![],
            attachments: vec![],
            expires_at: None,
            breached_at: Some("2026-04-22T00:00:00Z".into()),
            password_changed_at: Some("2026-05-01T08:00:00Z".into()),
            created_at: now.clone(),
            created_by: Some("cli:vault-seed".into()),
            updated_at: now.clone(),
            updated_by: None,
            last_used_at: Some(now.clone()),
            version: 1,
        },
        VaultEntry {
            id: format!("vault_demo_hn_{stamp}"),
            context_id: context_id.into(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://news.ycombinator.com".into(),
            }],
            label: "Hacker News".into(),
            secret_kind: SecretKind::Password,
            tags: vec!["personal".into()],
            notes: None,
            favicon: None,
            selectors: vec![],
            custom_field_names: vec![],
            attachments: vec![],
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: now.clone(),
            created_by: Some("cli:vault-seed".into()),
            updated_at: now,
            updated_by: None,
            last_used_at: None,
            version: 1,
        },
    ]
}

fn secret_kind_label(k: SecretKind) -> &'static str {
    match k {
        SecretKind::Password => "password",
        SecretKind::Passkey => "passkey",
        SecretKind::OauthTokens => "oauth-tokens",
        SecretKind::DidSelfIssued => "did-self-issued",
        SecretKind::DidcommPeer => "didcomm-peer",
        SecretKind::BearerToken => "bearer-token",
        SecretKind::SshKey => "ssh-key",
        SecretKind::Custom => "custom",
    }
}

fn stamp_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{t:x}")
}
