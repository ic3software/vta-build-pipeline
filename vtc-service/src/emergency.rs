//! `vtc admin emergency-bootstrap` — destructive operator recovery.
//!
//! The previous BIP-39-mnemonic-based recovery was incompatible
//! with the VTA-provisioned key model (see
//! `tasks/vtc-mvp/vta-driven-keys.md` §4) — a mnemonic the
//! operator typed could never decode to the random bytes the VTA
//! handed back. PR A stubs this surface; PR B reimplements
//! emergency bootstrap on top of the VTA's
//! `provision-integration` flow (`VtaIntent::AdminRotated`).
//!
//! Server-startup callers still need a few pieces from this
//! module:
//! - [`PendingEmergencyBootstrap`] — the marker the live impl
//!   persists after a successful recovery so the daemon's next
//!   boot emits an `EmergencyBootstrapInvoked` audit envelope.
//!   The marker shape is forward-stable; PR B writes it, PR A
//!   only ever reads it.
//! - Re-exports of the same shape via [`crate::install`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;

pub use crate::install::PendingEmergencyBootstrap;

/// CLI args. Mirrors the live shape so the `main.rs` clap surface
/// keeps compiling.
pub struct EmergencyBootstrapArgs {
    pub config_path: Option<PathBuf>,
    /// VTA context the recovery DID will be authorized into.
    pub context: Option<String>,
}

/// Outcome of a successful run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBootstrapOutcome {
    pub install_url: String,
    pub admin_entries_cleared: usize,
    pub admin_records_cleared: usize,
}

/// Sentinel error returned by every CLI path while the rework is
/// pending. The `main.rs` runner surfaces it verbatim with a
/// follow-up operator hint.
pub fn emergency_bootstrap_unavailable() -> AppError {
    AppError::Internal(
        "vtc admin emergency-bootstrap is being reworked under \
         tasks/vtc-mvp/vta-driven-keys.md §4 — refusing to mutate state until the \
         VTA-credential-based recovery flow lands."
            .into(),
    )
}

/// Stub. Refuses with [`emergency_bootstrap_unavailable`].
pub async fn run_emergency_bootstrap(
    _args: EmergencyBootstrapArgs,
) -> Result<EmergencyBootstrapOutcome, AppError> {
    Err(emergency_bootstrap_unavailable())
}
