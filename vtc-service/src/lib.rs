//! VTC service library surface.
//!
//! `vtc-service` is primarily a binary crate (`vtc`) — see `src/main.rs`
//! for the CLI entry point. This `lib.rs` exists to expose the internal
//! module tree to integration tests under `tests/` (and, in the future,
//! to alternative front-ends).
//!
//! Every module here is `pub` so integration tests can construct the
//! same `AppState` + `routes::router()` the binary uses, but the crate
//! is `publish = workspace` only because removing it would break the
//! workspace `Cargo.toml`'s symmetric treatment of `vta-service` and
//! `vtc-service`. External consumers should depend on `vta-sdk`, not
//! on this crate.

pub mod acl;
pub mod acl_cli;
pub mod auth;
pub mod community;
pub mod config;
pub mod config_store;
pub mod did_key;
#[cfg(feature = "setup")]
pub mod did_webvh;
pub mod error;
pub mod import_did;
pub mod install;
pub mod keys;
pub mod messaging;
pub mod routes;
pub mod server;
#[cfg(feature = "setup")]
pub mod setup;
pub mod status;
pub mod store;
pub mod supervisor;
pub mod webauthn;
