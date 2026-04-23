//! VTA setup flows — split into focused submodules:
//!
//! - [`interactive`]: prompt-driven `vta setup` wizard.
//! - [`from_toml`]: non-interactive `vta setup --from <file>` loading a
//!   [`WizardInputs`] TOML schema.
//!
//! This file retains the small helpers both paths share (seed-context
//! bootstrap, webvh-URL prompt, silent mnemonic generation) and
//! re-exports the public entry points so callers keep importing from
//! `crate::setup::*` — `main.rs` and `did_webvh.rs` don't need to know
//! the internal layout.

use bip39::Mnemonic;
use dialoguer::{Confirm, Input};
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use url::Url;

use crate::contexts::{self, ContextRecord};
use crate::store::KeyspaceHandle;

mod from_toml;
mod interactive;

// Submodules are private — external callers reach the entry points via
// the re-exports below. Allowed-unused because `WizardInputs` and its
// nested enums are referenced from doc-string links (including in
// `main.rs`) rather than imported directly; making them pub-use keeps
// the `vta_service::setup::WizardInputs` path in the published docs.
#[allow(unused_imports)]
pub use from_toml::{
    ExistingDataDirPolicy, MessagingInput, SecretsBackendInput, VtaDidInput, WizardInputs,
    apply_inputs, run_setup_from_file,
};
pub use interactive::run_setup_wizard;

/// Create a seed application context and store it. Shared by both the
/// interactive wizard and the non-interactive `--from <file>` path.
pub(crate) async fn create_seed_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    contexts::create_context(contexts_ks, id, name).await
}

/// Generate a fresh 24-word BIP-39 mnemonic without displaying or
/// confirming it. Used by the non-interactive `--from <file>` path —
/// the operator captures the seed later via `pnm backup export` once
/// the first admin has connected.
///
/// The interactive wizard wraps this in a display+confirm prompt
/// (`interactive::generate_mnemonic_with_confirmation`) so the operator
/// must explicitly acknowledge they've recorded it before setup
/// continues.
pub(crate) fn generate_mnemonic_silent() -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    Ok(Mnemonic::from_entropy(&entropy)?)
}

/// Prompt the user for a URL (e.g. `https://example.com/dids/vta`) and
/// convert it to a [`WebVHURL`]. Re-prompts on invalid input.
///
/// Shared between the interactive wizard (for the VTA DID / mediator
/// DID URL) and `did_webvh.rs`'s standalone `vta create-did-webvh`
/// CLI. Kept at the module root (not inside `interactive`) because the
/// CLI is not conceptually part of the wizard flow.
pub(crate) fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}
