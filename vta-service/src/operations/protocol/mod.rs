//! DIDComm protocol management operations.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`.
//!
//! This module orchestrates the post-setup state changes the spec
//! requires (enable, disable, migrate, drain-cancel, report). Phase 1
//! lands only the foundations; the operations themselves arrive in
//! later phases.

pub mod disable_didcomm;
pub mod disable_rest;
pub mod document;
pub mod drain_cancel;
pub mod enable_didcomm;
pub mod enable_rest;
pub mod invariant;
pub mod report;
pub mod rollback_rest;
pub mod snapshot;
pub mod update_didcomm;
pub mod update_rest;

/// Process-wide lock serializing every protocol-state mutation
/// (enable / disable / migrate / drain-cancel). Modeled on
/// `MODE_B_LOCK` in `routes/bootstrap.rs`. Held across the entire
/// op (handshake → publish → registry update), not per-step.
///
/// Read paths (`services list`, `mediator report`) do not need the
/// lock and intentionally do not take it. Mutation paths take it
/// unconditionally.
pub static PROTOCOL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Whether a forward operation was invoked directly by the
/// operator or as the fail-forward dispatch from a rollback.
///
/// Threaded through every forward op (enable / update / disable
/// for both REST and DIDComm) so the emitted telemetry event can
/// carry a `triggered_by: "rollback"` field per spec §3.5a. The
/// rollback layer (T3.1 / T3.2) reads the per-kind snapshot,
/// computes the equivalent forward operation, and dispatches into
/// it with [`OpContext::Rollback`]; the forward op runs unchanged
/// modulo this telemetry tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpContext {
    Direct,
    Rollback,
}

impl OpContext {
    /// JSON value to surface in the `triggered_by` telemetry field
    /// for this context. Returns `None` for [`OpContext::Direct`]
    /// — direct operations don't carry the field at all (omitted
    /// rather than serialized as `"direct"`, since the absence is
    /// the conventional signal).
    #[must_use]
    pub fn telemetry_triggered_by(self) -> Option<&'static str> {
        match self {
            OpContext::Direct => None,
            OpContext::Rollback => Some("rollback"),
        }
    }
}

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
