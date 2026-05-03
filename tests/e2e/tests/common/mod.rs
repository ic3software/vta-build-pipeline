//! Shared helpers for the e2e integration-test binaries.

use std::sync::Once;

static TRACING_INIT: Once = Once::new();

/// Install a single `tracing_subscriber` for the test process.
/// `RUST_LOG` controls the level; default is `warn`. Idempotent — safe
/// to call from every test.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_test_writer()
            .try_init();
    });
}
