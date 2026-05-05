//! Shared helpers for the e2e integration-test binaries.
//!
//! Each `tests/*.rs` binary in this crate gets its own copy of the
//! `common` module, so items unused by one test bin still compile.
//! Suppress dead-code warnings at module scope rather than tagging
//! every public item.
#![allow(dead_code)]

pub mod test_vta;
pub mod test_vta_responder;

use std::sync::Once;

static INIT: Once = Once::new();

/// One-shot per-process setup: tracing subscriber + rustls/jsonwebtoken
/// `CryptoProvider`s. The crypto providers are mandatory because the
/// test graph compiles in both `rust_crypto` and `aws_lc_rs`, so neither
/// crate's auto-select picks a winner. Delegated to the test mediator's
/// idempotent helper so we stay in lockstep with the provider the
/// mediator binary itself uses.
///
/// `RUST_LOG` controls the tracing level; default is `warn`.
/// Idempotent — safe to call from every test.
pub fn init_tracing() {
    INIT.call_once(|| {
        affinidi_messaging_test_mediator::install_default_crypto_provider();

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_test_writer()
            .try_init();
    });
}
