// Module tree is declared in lib.rs (so integration tests under
// `tests/` can pull the same modules the binary uses). Re-import the
// pieces this binary needs at the top level.
use vtc_service::{acl_cli, config, did_key, import_did, keys, server, status, store};
#[cfg(feature = "setup")]
use vtc_service::{did_webvh, emergency, setup};

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::{AppConfig, LogFormat};
use keys::seed_store::create_secret_store;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vtc", about = "Verifiable Trust Community", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the interactive setup wizard
    Setup,
    /// Show VTC status and statistics
    Status,
    /// Create a did:key (offline, no server required)
    CreateDidKey {
        /// Also create an ACL entry with Admin role for the new DID
        #[arg(long)]
        admin: bool,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Create a did:webvh DID (interactive wizard, no server required)
    CreateDidWebvh {
        /// Human-readable label prefix for key records
        #[arg(long)]
        label: Option<String>,
    },
    /// Import an external DID and create an ACL entry (offline, no server required)
    ImportDid {
        /// The DID to import
        #[arg(long)]
        did: String,
        /// Role to assign (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Manage Access Control List entries (offline, no server required)
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },
    /// Operator-level recovery + administration (offline)
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Reset the install carve-out using the master-seed mnemonic.
    ///
    /// Run on a **stopped** daemon. Clears every admin ACL entry
    /// and sister record, then mints a fresh install URL the
    /// operator can claim with a new passkey. The daemon's next
    /// boot emits a loud `EmergencyBootstrapInvoked` audit event
    /// — emergency bootstrap is destructive and intentionally
    /// noisy in the audit log.
    EmergencyBootstrap {
        /// Skip the "are you sure?" confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Provide the 24-word mnemonic non-interactively
        /// (intended for automated tests; production use should
        /// rely on the interactive prompt so the mnemonic doesn't
        /// land in shell history).
        #[arg(long, hide = true)]
        mnemonic: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List all ACL entries
    List {
        /// Filter by context
        #[arg(long)]
        context: Option<String>,
        /// Filter by role (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
    },
    /// Show details of a single ACL entry
    Get {
        /// The DID to look up
        did: String,
    },
    /// Update an existing ACL entry
    Update {
        /// The DID to update
        did: String,
        /// New role (admin, initiator, application, reader)
        #[arg(long)]
        role: Option<String>,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
        /// New context list (comma-separated; omit flag to keep unchanged)
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// The DID to delete
        did: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    #[cfg(feature = "keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        eprintln!("warning: OS keyring unavailable: {e}");
    }

    print_banner();

    match cli.command {
        Some(Commands::Setup) => {
            #[cfg(feature = "setup")]
            {
                if let Err(e) = setup::run_setup_wizard(cli.config).await {
                    eprintln!("Setup failed: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                eprintln!("Setup wizard not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::Status) => {
            if let Err(e) = status::run_status(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidKey { admin, label }) => {
            let args = did_key::CreateDidKeyArgs {
                config_path: cli.config,
                admin,
                label,
            };
            if let Err(e) = did_key::run_create_did_key(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidWebvh { label }) => {
            #[cfg(feature = "setup")]
            {
                let args = did_webvh::CreateDidWebvhArgs {
                    config_path: cli.config,
                    label,
                };
                if let Err(e) = did_webvh::run_create_did_webvh(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = label;
                eprintln!("create-did-webvh is not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::ImportDid { did, role, label }) => {
            let args = import_did::ImportDidArgs {
                config_path: cli.config,
                did,
                role,
                label,
            };
            if let Err(e) = import_did::run_import_did(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Admin { command }) => {
            #[cfg(feature = "setup")]
            {
                match command {
                    AdminCommands::EmergencyBootstrap { yes, mnemonic } => {
                        if let Err(e) = run_emergency_bootstrap_cli(cli.config, yes, mnemonic).await
                        {
                            eprintln!("Emergency bootstrap failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = command;
                eprintln!("admin subcommands are unavailable (compiled without 'setup')");
                std::process::exit(1);
            }
        }
        Some(Commands::Acl { command }) => {
            let result = match command {
                AclCommands::List { context, role } => {
                    acl_cli::run_acl_list(cli.config, context, role).await
                }
                AclCommands::Get { did } => acl_cli::run_acl_get(cli.config, did).await,
                AclCommands::Update {
                    did,
                    role,
                    label,
                    contexts,
                } => acl_cli::run_acl_update(cli.config, did, role, label, contexts).await,
                AclCommands::Delete { did, yes } => {
                    acl_cli::run_acl_delete(cli.config, did, yes).await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTC instance, run:");
                    eprintln!("  vtc setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vtc --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let secret_store = create_secret_store(&config).expect("failed to create secret store");

            if let Err(e) = server::run(config, store, secret_store).await {
                tracing::error!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Interactive `vtc admin emergency-bootstrap` flow.
///
/// 1. Loud warning + confirmation (skippable with `--yes`).
/// 2. Mnemonic prompt via `dialoguer::Password` (or whatever the
///    `--mnemonic` flag provided, for tests).
/// 3. Hands off to `emergency::run_emergency_bootstrap`, which
///    verifies the seed, clears admin state, reopens the carve-out,
///    mints a fresh install token, and persists the
///    `EmergencyBootstrapInvoked` pending marker.
/// 4. Prints the install URL + footer that warns the operator to
///    restart the daemon ASAP so the audit event lands.
#[cfg(feature = "setup")]
async fn run_emergency_bootstrap_cli(
    config_path: Option<std::path::PathBuf>,
    skip_confirm: bool,
    mnemonic: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::{Confirm, Password};

    eprintln!();
    eprintln!("⚠️  EMERGENCY BOOTSTRAP");
    eprintln!(
        "This will clear every existing admin ACL entry and admin sister record, then\n\
         reopen the install carve-out so a new operator can claim a fresh install URL.\n\
         The daemon's next boot will emit a loud `EmergencyBootstrapInvoked` audit event.\n"
    );

    if !skip_confirm {
        let ok = Confirm::new()
            .with_prompt("Proceed?")
            .default(false)
            .interact()?;
        if !ok {
            eprintln!("aborted.");
            return Ok(());
        }
    }

    let mnemonic = match mnemonic {
        Some(m) => m,
        None => Password::new()
            .with_prompt("24-word BIP-39 master-seed mnemonic")
            .interact()?,
    };

    let outcome = emergency::run_emergency_bootstrap(emergency::EmergencyBootstrapArgs {
        config_path,
        mnemonic: Some(mnemonic),
    })
    .await?;

    eprintln!();
    eprintln!("✅ emergency bootstrap complete");
    eprintln!(
        "   admin ACL entries cleared:  {}",
        outcome.admin_entries_cleared
    );
    eprintln!(
        "   admin sister records:       {}",
        outcome.admin_records_cleared
    );
    eprintln!();
    eprintln!("Install URL (one-shot, 15 min TTL):");
    eprintln!("   {}", outcome.install_url);
    eprintln!();
    eprintln!(
        "Restart the daemon (`vtc`) so the `EmergencyBootstrapInvoked` audit event lands\n\
         and the install carve-out reopens. Then claim the install URL with a fresh passkey."
    );
    Ok(())
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} ██████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔════╝{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}██║     {reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██║     {reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}╚██████╗{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow} ╚═════╝{reset}
{dim}  Verifiable Trust Community v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn init_tracing(config: &AppConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match config.log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}
