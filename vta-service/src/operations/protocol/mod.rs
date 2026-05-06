//! DIDComm protocol management operations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! This module orchestrates the post-setup state changes the spec
//! requires (enable, disable, migrate, drain-cancel, report). Phase 1
//! lands only the foundations; the operations themselves arrive in
//! later phases.

pub mod disable_didcomm;
pub mod document;
pub mod drain_cancel;
pub mod enable_didcomm;
pub mod enable_rest;
pub mod invariant;
pub mod migrate_mediator;
pub mod report;
pub mod snapshot;

/// Process-wide lock serializing every protocol-state mutation
/// (enable / disable / migrate / drain-cancel). Modeled on
/// `MODE_B_LOCK` in `routes/bootstrap.rs`. Held across the entire
/// op (handshake → publish → registry update), not per-step.
///
/// Read paths (`services list`, `mediator report`) do not need the
/// lock and intentionally do not take it. Mutation paths take it
/// unconditionally.
pub static PROTOCOL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::PROTOCOL_LOCK;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Two tasks contending for `PROTOCOL_LOCK` execute serially: the
    /// second cannot enter its critical section until the first has
    /// released. Detected via an `in_critical_section` counter that
    /// must never exceed 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn protocol_lock_serializes_concurrent_mutations() {
        let in_section = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        async fn critical(in_section: Arc<AtomicUsize>, max_observed: Arc<AtomicUsize>) {
            let _guard = PROTOCOL_LOCK.lock().await;
            let n = in_section.fetch_add(1, Ordering::SeqCst) + 1;
            max_observed.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            in_section.fetch_sub(1, Ordering::SeqCst);
        }

        let a = tokio::spawn(critical(Arc::clone(&in_section), Arc::clone(&max_observed)));
        let b = tokio::spawn(critical(Arc::clone(&in_section), Arc::clone(&max_observed)));
        let (ra, rb) = tokio::join!(a, b);
        ra.unwrap();
        rb.unwrap();

        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            1,
            "PROTOCOL_LOCK must serialize: at most one task in the critical section at a time"
        );
    }
}
