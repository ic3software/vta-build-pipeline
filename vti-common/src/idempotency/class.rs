//! [`IdempotencyClass`] — the op-class enum that drives cache TTL.

use serde::{Deserialize, Serialize};

/// Op class for an idempotent route, set explicitly at registration
/// time (plan **D6**: clarity over cleverness; no heuristic on HTTP
/// method).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdempotencyClass {
    /// Standard create / update / read. Cached for 24 h —
    /// long retry window for offline-then-online clients.
    NonDestructive,

    /// Delete / revoke / destructive mutation. Cached for **60 s only**
    /// so a network-flake retry returns the same outcome but a later
    /// intentional re-creation under the same UUID isn't silently
    /// no-op'd against a freshly-deleted target.
    Destructive,
}

impl IdempotencyClass {
    /// Cache lifetime in seconds. Pinned in code rather than config
    /// to keep the semantic boundary between the two classes obvious
    /// — operators don't tune it.
    pub fn ttl_seconds(self) -> u64 {
        match self {
            Self::NonDestructive => 24 * 60 * 60,
            Self::Destructive => 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_destructive_caches_for_24_hours() {
        assert_eq!(IdempotencyClass::NonDestructive.ttl_seconds(), 86_400);
    }

    #[test]
    fn destructive_caches_for_60_seconds() {
        assert_eq!(IdempotencyClass::Destructive.ttl_seconds(), 60);
    }
}
