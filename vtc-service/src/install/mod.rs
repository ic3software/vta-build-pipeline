//! Install token + carve-out state machine.
//!
//! Implements **M0.4** of the VTC MVP Phase 0 plan. The install
//! token is the one-time bearer credential the operator clicks to
//! turn `vtc setup` into a bootstrapped admin via the WebAuthn
//! ceremony (M0.5 follow-up). This module owns:
//!
//! - **[`token`]** — `InstallToken` claims + the EdDSA JWT
//!   signer/verifier derived from the VTC's master seed via HKDF.
//! - **[`state_machine`]** — the `install` keyspace state machine
//!   that gates the install carve-out (`Issued` → `Consumed` →
//!   `Closed`), with the **claim-window** pattern adopted from
//!   `webvh-common::server::passkey::store` (plan D12). A failed
//!   WebAuthn ceremony doesn't burn the token — only a successful
//!   `finish_claim` does.
//! - **[`INSTALL_CARVEOUT_LOCK`]** — a single process-wide async
//!   mutex guarding the state-machine transitions so two concurrent
//!   `start_claim` calls on the same token can't both pass the
//!   "claimed_at not set within the window" check.
//!
//! See spec §4.1 / §4.2 for the consumer-facing flow.

pub mod state_machine;
pub mod token;

pub use state_machine::{InstallTokenState, InstallTokenStore, StartClaimOutcome};
pub use token::{
    INSTALL_AUDIENCE, INSTALL_SUBJECT, INSTALL_TOKEN_DEFAULT_TTL_SECS, InstallTokenClaims,
    InstallTokenSigner, mint_install_token, parse_install_token,
};

use tokio::sync::Mutex;

/// Process-wide async mutex serialising every install-token state
/// machine transition. Mirrors VTA's `MODE_B_LOCK` invariant — the
/// claim-check then claim-set sequence must be atomic across
/// concurrent Axum tasks. Operators don't pay for it post-install
/// (the carve-out is `Closed` and the mutex sits idle).
pub static INSTALL_CARVEOUT_LOCK: Mutex<()> = Mutex::const_new(());
