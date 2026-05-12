//! Setup-time helpers shared between the `vta setup` and `vtc setup`
//! wizards.
//!
//! Behind the `setup` feature flag because the helpers use
//! [`dialoguer`] and that's a non-trivial dep tree we don't want
//! pulled into headless server runtimes (enclaves, sidecars).
//!
//! ## What lives here
//!
//! - [`secrets_prompt`] — the "pick a secret-store backend" UX. Each
//!   service has its own `SecretsConfig` shape (vta-service includes
//!   Vault, vtc-service doesn't, etc.), so the prompt returns a
//!   neutral [`secrets_prompt::SecretsBackendChoice`] enum and the
//!   caller maps it into their own concrete config. Decouples the
//!   prompt logic from any one config schema.
//!
//! ## What does not live here
//!
//! - BIP-39 mnemonic generation. The VTC's seed model
//!   (`tasks/vtc-mvp/vta-driven-keys.md`) makes the VTA the sole
//!   key authority; there's no operator-held mnemonic to display
//!   or confirm. `vta-service`'s mnemonic helper stays in-tree
//!   until the VTA itself adopts a comparable model.

pub mod secrets_prompt;
