//! Shared helpers for the e2e integration-test binaries.
//!
//! Each `tests/*.rs` binary in this crate gets its own copy of the
//! `common` module, so items unused by one test bin still compile.
//! Suppress dead-code warnings at module scope rather than tagging
//! every public item.
#![allow(dead_code)]

pub mod test_vta;

use std::sync::Once;

static INIT: Once = Once::new();

/// One-shot per-process setup: tracing subscriber + rustls
/// `CryptoProvider`. The crypto provider is mandatory because the test
/// graph compiles in both `rust_crypto` and `aws_lc_rs`, so rustls
/// refuses to auto-select. Mirrors what `tdk-common` and the mediator
/// binary do at startup.
///
/// `RUST_LOG` controls the tracing level; default is `warn`.
/// Idempotent — safe to call from every test.
pub fn init_tracing() {
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // `jsonwebtoken` ships its own `CryptoProvider` plumbing, distinct
        // from rustls's. Both `rust_crypto` and `aws_lc_rs` features are
        // enabled in the e2e test graph (via the workspace pin and the
        // mediator's pin respectively), so its auto-select panics on
        // first use. Install the aws_lc provider here once.
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();

        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_test_writer()
            .try_init();
    });
}
