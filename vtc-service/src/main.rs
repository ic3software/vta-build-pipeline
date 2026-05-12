// Module tree is declared in lib.rs (so integration tests under
// `tests/` can pull the same modules the binary uses). Re-import the
// pieces this binary needs at the top level.
use vtc_service::{config, did_key, keys, server, status, store};
#[cfg(feature = "setup")]
use vtc_service::{emergency, setup};

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
    /// Operator-level recovery + administration (offline)
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Reset the install carve-out via the VTA's recovery path.
    ///
    /// Run on a **stopped** daemon. Authenticates against the VTA
    /// using a fresh ephemeral DID the operator authorizes at the
    /// VTA, then clears every admin ACL entry and admin sister
    /// record locally and mints a fresh install URL the operator
    /// can claim with a new passkey. The daemon's next boot emits
    /// a loud `EmergencyBootstrapInvoked` audit event.
    ///
    /// Replaces the BIP-39-mnemonic-based recovery from M0.10's
    /// initial implementation; see `tasks/vtc-mvp/vta-driven-keys.md`
    /// §4 for the design.
    EmergencyBootstrap {
        /// Skip the "are you sure?" confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// VTA context the recovery DID should be authorized into.
        /// Defaults to the value persisted in `config.toml`.
        #[arg(long)]
        context: Option<String>,
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
        Some(Commands::Admin { command }) => {
            #[cfg(feature = "setup")]
            {
                match command {
                    AdminCommands::EmergencyBootstrap { yes, context } => {
                        if let Err(e) = run_emergency_bootstrap_cli(cli.config, yes, context).await
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
/// 2. Operator authorizes a fresh ephemeral DID at the VTA via
///    `pnm acl create` (the wizard prints the exact command).
/// 3. The driver calls the VTA's `provision-integration` flow
///    (`VtaIntent::AdminRotated`) with that ephemeral DID. The
///    VTA's accept/reject IS the recovery authority — see
///    `tasks/vtc-mvp/vta-driven-keys.md` §4.
/// 4. On success: local admin ACL + sister records cleared, install
///    carve-out reopened, fresh install token minted.
#[cfg(feature = "setup")]
async fn run_emergency_bootstrap_cli(
    config_path: Option<std::path::PathBuf>,
    skip_confirm: bool,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use dialoguer::Confirm;

    eprintln!();
    eprintln!("⚠️  EMERGENCY BOOTSTRAP");
    eprintln!(
        "This clears every existing admin ACL entry and admin sister record, then\n\
         reopens the install carve-out so a new operator can claim a fresh install URL.\n\
         \n\
         The VTA accepts or rejects the recovery: if your PNM admin credential at the\n\
         VTA is still valid, the VTA will accept it; otherwise this command fails and\n\
         no local state is touched. The daemon's next boot emits a loud\n\
         `EmergencyBootstrapInvoked` audit event.\n"
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

    let outcome = emergency::run_emergency_bootstrap(emergency::EmergencyBootstrapArgs {
        config_path,
        context,
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
