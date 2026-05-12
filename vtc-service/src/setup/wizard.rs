//! Interactive `vtc setup` wizard.
//!
//! Drives the VTA-provisioned bootstrap of a fresh VTC daemon:
//!
//! 1. Prompts for the five configuration knobs (config path, VTC
//!    URL, admin-UX URL, VTA URL, VTA DID, VTA context).
//! 2. Mints an ephemeral `did:key` used only for the round-trip.
//! 3. Pauses for the operator to authorize the ephemeral DID at
//!    the VTA (e.g. `pnm acl create --did <…> --role admin
//!    --contexts <context>`).
//! 4. Drives `vta_sdk::provision_client::runner::run_provision`
//!    with `VtaIntent::FullSetup` + `ProvisionAsk::for_template
//!    ("vtc-host", { URL, ADMIN_UX_URL }, context)`.
//! 5. Opens the sealed bundle, extracts the `DidKeyMaterial` into
//!    a [`crate::setup::VtcKeyBundle`], writes the bundle into the
//!    secret store, writes the `did.jsonl` log to disk, writes
//!    `config.toml`, mints an install token, prints the URL.
//!
//! Stubbed for PR A — the live wizard implementation lands in the
//! follow-up PR that promotes `vti-common::setup::secrets_prompt`
//! and wires the `vta-sdk` provision-runner. The stub keeps the
//! `vtc setup` command bound so `main.rs` compiles + so operators
//! get a clear "not yet shipped" message instead of a silent
//! crash if they invoke the half-built command.
//!
//! See `tasks/vtc-mvp/vta-driven-keys.md` §3 for the call graph
//! the live impl follows.

use std::path::PathBuf;

use vti_common::error::AppError;

/// Stub. Returns a clear error directing the operator to the
/// upcoming PR that ships the live wizard. Replaced wholesale in
/// the follow-up PR.
pub async fn run_setup_wizard(_config_path: Option<PathBuf>) -> Result<(), AppError> {
    Err(AppError::Internal(
        "vtc setup is being reworked under tasks/vtc-mvp/vta-driven-keys.md §3 — the live \
         wizard ships in a follow-up PR. Until then, run `pnm` to provision a VTC via the \
         vta-sdk `provision-integration` flow and inject the resulting VtcKeyBundle into \
         the secret store directly."
            .into(),
    ))
}
