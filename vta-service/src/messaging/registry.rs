//! Multi-mediator listener registry.
//!
//! The VTA's DID document advertises **at most one** mediator at a
//! time (the *active* mediator), but the VTA may keep WebSocket
//! listeners open against zero or more *draining* mediators
//! simultaneously, each with its own TTL deadline. This module owns
//! that state and the policy around it.
//!
//! ## Layering
//!
//! - [`RegistryState`] is a pure, synchronous state machine — every
//!   transition is testable without I/O. It tracks active/drain
//!   bindings and the per-listener bounded outbound buffer.
//! - [`MediatorListenerRegistry`] composes [`RegistryState`] with
//!   [`SharedTelemetrySink`] and a handle to the live
//!   `DIDCommService`. The async methods translate registry actions
//!   into upstream `add_listener` / `remove_listener` /
//!   `send_message_with_retry` calls.
//!
//! Reconnect-with-backoff (1s → 60s cap, exponential factor 2.0)
//! is provided by the upstream library via
//! `RestartPolicy::Always { backoff: RetryConfig }`. We do not
//! reimplement it here; we only configure it on the listener.
//!
//! ## Inbound attribution
//!
//! Inbound DIDComm messages already carry the listener id via
//! `affinidi_messaging_didcomm_service::HandlerContext::listener_id`.
//! This module's convention is **listener id = mediator DID**, so
//! the handler receives the originating mediator DID directly with
//! no additional plumbing.
//!
//! ## Sticky outbound routing
//!
//! Responses to inbound requests are sent back through the listener
//! they arrived on (the upstream library does this naturally for
//! handler-returned responses). For VTA-initiated outbound calls,
//! [`Self::active_listener_id`] returns the active mediator DID.
//!
//! When the active mediator is momentarily disconnected, callers
//! enqueue via [`Self::buffer_outbound`]; the registry retries on
//! reconnect, bounded by the mediator's drain deadline. On overflow
//! or expiry, the response is dropped and a
//! [`TelemetryKind::DidcommResponseDropped`] event is recorded.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;

use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

/// Default per-listener outbound buffer capacity (responses queued
/// while the listener is momentarily disconnected). Spec: 128.
pub const DEFAULT_OUTBOUND_CAPACITY: usize = 128;

/// A binding to a mediator: the DID we advertise/use and the
/// resolved endpoint URL. The endpoint is captured at activation
/// time so a downstream listener config can be reconstructed
/// without re-resolving the DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatorBinding {
    pub mediator_did: String,
    pub endpoint: String,
}

/// State of a draining mediator: still listening, but not advertised
/// in the DID document; will be cancelled when `drains_until`
/// elapses (or sooner via [`RegistryState::cancel_drain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainEntry {
    pub mediator_did: String,
    pub endpoint: String,
    pub drains_until: DateTime<Utc>,
    /// Monotonically increasing counter, incremented on every
    /// transition that touches this mediator. Reconnect tasks that
    /// race with a registry mutation can detect they are stale by
    /// observing a generation bump.
    pub generation: u64,
}

/// A response queued for a specific listener.
#[derive(Debug, Clone)]
pub struct PendingResponse {
    pub recipient_did: String,
    pub message_type: String,
    pub body: JsonValue,
    pub thread_id: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("mediator `{0}` is currently active; cannot drain it without a replacement")]
    ActiveMediatorMustBeReplaced(String),
    #[error("mediator `{0}` is not registered (neither active nor draining)")]
    NotRegistered(String),
    #[error("mediator `{0}` is already in drain state")]
    AlreadyDraining(String),
    #[error("mediator `{0}` is the active mediator and cannot be cancelled (use disable instead)")]
    CannotCancelActive(String),
}

/// Pure synchronous state machine — no I/O, no `await`. All
/// transitions in this type are deterministic and unit-testable.
#[derive(Debug, Default)]
pub struct RegistryState {
    active: Option<MediatorBinding>,
    drains: HashMap<String, DrainEntry>,
    /// Per-listener bounded outbound buffer, keyed by mediator DID.
    outbound: HashMap<String, VecDeque<PendingResponse>>,
    outbound_capacity: usize,
    /// Monotonic counter for generation tagging. Incremented on
    /// every state-mutating call.
    next_generation: u64,
}

impl RegistryState {
    pub fn new() -> Self {
        Self {
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            ..Default::default()
        }
    }

    pub fn with_outbound_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "outbound capacity must be > 0");
        Self {
            outbound_capacity: capacity,
            ..Default::default()
        }
    }

    pub fn active(&self) -> Option<&MediatorBinding> {
        self.active.as_ref()
    }

    pub fn drains(&self) -> impl Iterator<Item = &DrainEntry> {
        self.drains.values()
    }

    pub fn drain_for(&self, mediator_did: &str) -> Option<&DrainEntry> {
        self.drains.get(mediator_did)
    }

    pub fn is_registered(&self, mediator_did: &str) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| a.mediator_did == mediator_did)
            || self.drains.contains_key(mediator_did)
    }

    /// Promote a mediator to the active slot. If a different
    /// mediator was already active, the caller is expected to
    /// follow up with [`Self::start_drain`] for the old one — this
    /// method does NOT auto-drain; the caller controls the TTL.
    pub fn activate(&mut self, binding: MediatorBinding) -> Option<MediatorBinding> {
        let prior = self.active.take();
        self.next_generation += 1;
        // If the new mediator was previously draining, evict that
        // entry — it's being promoted back to active.
        self.drains.remove(&binding.mediator_did);
        self.active = Some(binding);
        prior
    }

    /// Move a mediator into drain state.
    ///
    /// `mediator_did` may be either the currently-active mediator
    /// (in which case the caller must have already promoted a
    /// replacement) or a previously-active mediator already
    /// dethroned by [`Self::activate`]. Returns the drain entry's
    /// generation.
    pub fn start_drain(
        &mut self,
        mediator_did: &str,
        endpoint: String,
        drains_until: DateTime<Utc>,
    ) -> Result<u64, RegistryError> {
        if let Some(ref a) = self.active
            && a.mediator_did == mediator_did
        {
            return Err(RegistryError::ActiveMediatorMustBeReplaced(
                mediator_did.into(),
            ));
        }
        if self.drains.contains_key(mediator_did) {
            return Err(RegistryError::AlreadyDraining(mediator_did.into()));
        }
        self.next_generation += 1;
        let generation = self.next_generation;
        self.drains.insert(
            mediator_did.to_string(),
            DrainEntry {
                mediator_did: mediator_did.to_string(),
                endpoint,
                drains_until,
                generation,
            },
        );
        Ok(generation)
    }

    /// Cancel a drain entry. Refuses to cancel the active mediator —
    /// disabling DIDComm goes through a separate code path.
    pub fn cancel_drain(&mut self, mediator_did: &str) -> Result<DrainEntry, RegistryError> {
        if let Some(ref a) = self.active
            && a.mediator_did == mediator_did
        {
            return Err(RegistryError::CannotCancelActive(mediator_did.into()));
        }
        let entry = self
            .drains
            .remove(mediator_did)
            .ok_or_else(|| RegistryError::NotRegistered(mediator_did.into()))?;
        self.outbound.remove(mediator_did);
        self.next_generation += 1;
        Ok(entry)
    }

    /// Sweep expired drains. Returns the entries that were dropped.
    /// Caller (e.g. the TTL sweeper task in P2.2) translates each
    /// dropped entry into a `remove_listener` upstream call plus a
    /// `MediatorDrainExpire` telemetry event.
    pub fn expire_drains(&mut self, now: DateTime<Utc>) -> Vec<DrainEntry> {
        let expired: Vec<String> = self
            .drains
            .iter()
            .filter(|(_, e)| e.drains_until <= now)
            .map(|(k, _)| k.clone())
            .collect();
        let mut dropped = Vec::with_capacity(expired.len());
        for did in expired {
            if let Some(entry) = self.drains.remove(&did) {
                self.outbound.remove(&did);
                dropped.push(entry);
            }
        }
        if !dropped.is_empty() {
            self.next_generation += 1;
        }
        dropped
    }

    /// Disable DIDComm entirely: drop the active binding (the caller
    /// has already moved any successor into `start_drain` if it
    /// wants the old listener to keep receiving for a while).
    /// Returns the prior active binding.
    pub fn deactivate(&mut self) -> Option<MediatorBinding> {
        let prior = self.active.take();
        if prior.is_some() {
            self.next_generation += 1;
        }
        prior
    }

    /// Enqueue an outbound response for the named listener.
    ///
    /// Returns:
    /// - `Ok(BufferOutcome::Queued)` if the response was added.
    /// - `Ok(BufferOutcome::DroppedOldest(dropped))` if the buffer
    ///   was full; the oldest entry was evicted to make room. The
    ///   caller is expected to record a
    ///   [`TelemetryKind::DidcommResponseDropped`] event for the
    ///   evicted item.
    /// - `Err(RegistryError::NotRegistered)` if the named mediator
    ///   is neither active nor draining.
    pub fn buffer_outbound(
        &mut self,
        mediator_did: &str,
        response: PendingResponse,
    ) -> Result<BufferOutcome, RegistryError> {
        if !self.is_registered(mediator_did) {
            return Err(RegistryError::NotRegistered(mediator_did.into()));
        }
        let buf = self.outbound.entry(mediator_did.to_string()).or_default();
        let outcome = if buf.len() == self.outbound_capacity {
            let dropped = buf.pop_front().expect("buf is at capacity, so non-empty");
            buf.push_back(response);
            BufferOutcome::DroppedOldest(dropped)
        } else {
            buf.push_back(response);
            BufferOutcome::Queued
        };
        Ok(outcome)
    }

    /// Drain (in the queue sense) and return all buffered outbound
    /// responses for the named listener — typically called when the
    /// listener reconnects and the registry can flush them.
    pub fn take_outbound(&mut self, mediator_did: &str) -> Vec<PendingResponse> {
        self.outbound
            .remove(mediator_did)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn outbound_len(&self, mediator_did: &str) -> usize {
        self.outbound
            .get(mediator_did)
            .map(VecDeque::len)
            .unwrap_or(0)
    }

    pub fn outbound_capacity(&self) -> usize {
        self.outbound_capacity
    }
}

#[derive(Debug, Clone)]
pub enum BufferOutcome {
    Queued,
    DroppedOldest(PendingResponse),
}

impl BufferOutcome {
    pub fn is_queued(&self) -> bool {
        matches!(self, Self::Queued)
    }

    pub fn is_dropped(&self) -> bool {
        matches!(self, Self::DroppedOldest(_))
    }
}

// ---------------------------------------------------------------------------
// Async wrapper composing state with telemetry. The live `DIDCommService`
// integration (add_listener / remove_listener / send_message_with_retry)
// will be wired in subsequent tasks (P2.3 handshake adds listeners; the
// per-vertical operations call `activate` / `start_drain` / `cancel_drain`
// here). For now, this struct exposes the registry surface with telemetry
// emission so the operations layer can be developed against it.
// ---------------------------------------------------------------------------

pub struct MediatorListenerRegistry {
    state: RwLock<RegistryState>,
    telemetry: SharedTelemetrySink,
}

impl MediatorListenerRegistry {
    pub fn new(telemetry: SharedTelemetrySink) -> Self {
        Self {
            state: RwLock::new(RegistryState::new()),
            telemetry,
        }
    }

    pub fn with_capacity(telemetry: SharedTelemetrySink, capacity: usize) -> Self {
        Self {
            state: RwLock::new(RegistryState::with_outbound_capacity(capacity)),
            telemetry,
        }
    }

    pub async fn active_listener_id(&self) -> Option<String> {
        self.state
            .read()
            .await
            .active()
            .map(|b| b.mediator_did.clone())
    }

    pub async fn drain_count(&self) -> usize {
        self.state.read().await.drains().count()
    }

    pub async fn drain_deadline(&self, mediator_did: &str) -> Option<DateTime<Utc>> {
        self.state
            .read()
            .await
            .drain_for(mediator_did)
            .map(|e| e.drains_until)
    }

    /// Promote the named mediator to active. The caller is
    /// responsible for opening the upstream listener BEFORE calling
    /// this (handshake-before-promotion); this method only updates
    /// registry state and emits telemetry.
    pub async fn record_activate(&self, binding: MediatorBinding) -> Option<MediatorBinding> {
        let mediator_did = binding.mediator_did.clone();
        let prior = {
            let mut s = self.state.write().await;
            s.activate(binding)
        };
        let _ = self
            .telemetry
            .record(
                TelemetryEvent::new(TelemetryKind::MediatorMigrateStart)
                    .with_mediator(&mediator_did)
                    .with_field(
                        "from",
                        prior
                            .as_ref()
                            .map(|b| JsonValue::from(b.mediator_did.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
            )
            .await;
        prior
    }

    pub async fn record_drain(
        &self,
        mediator_did: &str,
        endpoint: String,
        drains_until: DateTime<Utc>,
    ) -> Result<u64, RegistryError> {
        let generation = {
            let mut s = self.state.write().await;
            s.start_drain(mediator_did, endpoint, drains_until)?
        };
        let _ = self
            .telemetry
            .record(
                TelemetryEvent::new(TelemetryKind::MediatorDrainStart)
                    .with_mediator(mediator_did)
                    .with_field("drains_until", JsonValue::from(drains_until.to_rfc3339()))
                    .with_field("generation", JsonValue::from(generation)),
            )
            .await;
        Ok(generation)
    }

    pub async fn record_cancel(&self, mediator_did: &str) -> Result<DrainEntry, RegistryError> {
        let entry = {
            let mut s = self.state.write().await;
            s.cancel_drain(mediator_did)?
        };
        let _ = self
            .telemetry
            .record(
                TelemetryEvent::new(TelemetryKind::MediatorDrainCancel).with_mediator(mediator_did),
            )
            .await;
        Ok(entry)
    }

    /// Apply TTL expiry, returning the dropped entries. Caller (the
    /// P2.2 sweeper) tears down the upstream listeners.
    pub async fn record_expiries(&self, now: DateTime<Utc>) -> Vec<DrainEntry> {
        let dropped = {
            let mut s = self.state.write().await;
            s.expire_drains(now)
        };
        for entry in &dropped {
            let _ = self
                .telemetry
                .record(
                    TelemetryEvent::new(TelemetryKind::MediatorDrainExpire)
                        .with_mediator(&entry.mediator_did)
                        .with_field("generation", JsonValue::from(entry.generation)),
                )
                .await;
        }
        dropped
    }

    pub async fn record_deactivate(&self) -> Option<MediatorBinding> {
        let prior = {
            let mut s = self.state.write().await;
            s.deactivate()
        };
        if let Some(ref b) = prior {
            let _ = self
                .telemetry
                .record(
                    TelemetryEvent::new(TelemetryKind::ServicesDidcommDisable)
                        .with_mediator(&b.mediator_did),
                )
                .await;
        }
        prior
    }

    /// Buffer an outbound response addressed to a specific listener.
    /// On overflow, emits `DidcommResponseDropped` for the evicted
    /// item.
    pub async fn buffer_outbound(
        &self,
        mediator_did: &str,
        response: PendingResponse,
    ) -> Result<BufferOutcome, RegistryError> {
        let outcome = {
            let mut s = self.state.write().await;
            s.buffer_outbound(mediator_did, response)?
        };
        if let BufferOutcome::DroppedOldest(ref dropped) = outcome {
            let _ = self
                .telemetry
                .record(
                    TelemetryEvent::new(TelemetryKind::DidcommResponseDropped)
                        .with_mediator(mediator_did)
                        .with_sender(dropped.recipient_did.clone())
                        .with_message_type(dropped.message_type.clone())
                        .with_field("reason", JsonValue::from("buffer-overflow")),
                )
                .await;
        }
        Ok(outcome)
    }

    /// Take all buffered outbound responses for a listener. Typically
    /// called by a flusher task on listener-reconnect.
    pub async fn take_outbound(&self, mediator_did: &str) -> Vec<PendingResponse> {
        let mut s = self.state.write().await;
        s.take_outbound(mediator_did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::sync::Arc;
    use vti_common::telemetry::{RingBufferTelemetry, TelemetryFilter};

    fn binding(did: &str, endpoint: &str) -> MediatorBinding {
        MediatorBinding {
            mediator_did: did.into(),
            endpoint: endpoint.into(),
        }
    }

    fn pending(recipient: &str) -> PendingResponse {
        PendingResponse {
            recipient_did: recipient.into(),
            message_type: "https://example.org/msg/1.0/test".into(),
            body: JsonValue::Null,
            thread_id: Some("thid-1".into()),
        }
    }

    fn now_plus(secs: i64) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(secs)
    }

    // ---------- pure state machine ----------

    #[test]
    fn activate_promotes_and_returns_prior() {
        let mut s = RegistryState::new();
        assert!(s.active().is_none());
        let prior = s.activate(binding("did:m:A", "wss://A"));
        assert!(prior.is_none());
        assert_eq!(s.active().unwrap().mediator_did, "did:m:A");

        let prior = s.activate(binding("did:m:B", "wss://B"));
        assert_eq!(prior.unwrap().mediator_did, "did:m:A");
        assert_eq!(s.active().unwrap().mediator_did, "did:m:B");
    }

    #[test]
    fn drain_refuses_active_mediator() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        let err = s
            .start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap_err();
        assert_eq!(
            err,
            RegistryError::ActiveMediatorMustBeReplaced("did:m:A".into())
        );
    }

    #[test]
    fn drain_after_replacement_succeeds() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        let generation = s
            .start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        assert!(generation > 0);
        assert!(s.drain_for("did:m:A").is_some());
        assert_eq!(s.active().unwrap().mediator_did, "did:m:B");
    }

    #[test]
    fn drain_refuses_already_draining() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        let err = s
            .start_drain("did:m:A", "wss://A".into(), now_plus(120))
            .unwrap_err();
        assert_eq!(err, RegistryError::AlreadyDraining("did:m:A".into()));
    }

    #[test]
    fn cancel_removes_drain_entry() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        let entry = s.cancel_drain("did:m:A").unwrap();
        assert_eq!(entry.mediator_did, "did:m:A");
        assert!(s.drain_for("did:m:A").is_none());
    }

    #[test]
    fn cancel_refuses_active() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        let err = s.cancel_drain("did:m:A").unwrap_err();
        assert_eq!(err, RegistryError::CannotCancelActive("did:m:A".into()));
    }

    #[test]
    fn cancel_unknown_mediator_errors() {
        let mut s = RegistryState::new();
        let err = s.cancel_drain("did:m:nope").unwrap_err();
        assert_eq!(err, RegistryError::NotRegistered("did:m:nope".into()));
    }

    #[test]
    fn expire_drains_returns_only_expired() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.activate(binding("did:m:C", "wss://C"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(-10))
            .unwrap();
        s.start_drain("did:m:B", "wss://B".into(), now_plus(60))
            .unwrap();

        let dropped = s.expire_drains(Utc::now());
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].mediator_did, "did:m:A");
        assert!(s.drain_for("did:m:A").is_none());
        assert!(s.drain_for("did:m:B").is_some());
    }

    #[test]
    fn overlapping_drains_coexist() {
        // Spec criterion #5: many overlapping drains permitted.
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.activate(binding("did:m:C", "wss://C"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(3600))
            .unwrap();
        s.start_drain("did:m:B", "wss://B".into(), now_plus(1800))
            .unwrap();
        assert_eq!(s.drains().count(), 2);
        assert_eq!(s.active().unwrap().mediator_did, "did:m:C");
    }

    #[test]
    fn reactivating_drained_mediator_evicts_drain_entry() {
        // Rollback: A in drain, then `migrate --to A` re-promotes A.
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        assert!(s.drain_for("did:m:A").is_some());
        s.activate(binding("did:m:A", "wss://A"));
        assert!(
            s.drain_for("did:m:A").is_none(),
            "reactivation must evict the drain entry"
        );
        assert_eq!(s.active().unwrap().mediator_did, "did:m:A");
    }

    #[test]
    fn deactivate_drops_active_only() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        let prior = s.deactivate();
        assert_eq!(prior.unwrap().mediator_did, "did:m:B");
        assert!(s.active().is_none());
        assert!(s.drain_for("did:m:A").is_some(), "drain unaffected");
    }

    #[test]
    fn buffer_outbound_queues_under_capacity() {
        let mut s = RegistryState::with_outbound_capacity(3);
        s.activate(binding("did:m:A", "wss://A"));
        for i in 0..3 {
            let outcome = s
                .buffer_outbound("did:m:A", pending(&format!("did:peer:{i}")))
                .unwrap();
            assert!(outcome.is_queued());
        }
        assert_eq!(s.outbound_len("did:m:A"), 3);
    }

    #[test]
    fn buffer_outbound_evicts_oldest_at_capacity() {
        let mut s = RegistryState::with_outbound_capacity(2);
        s.activate(binding("did:m:A", "wss://A"));
        s.buffer_outbound("did:m:A", pending("did:peer:0")).unwrap();
        s.buffer_outbound("did:m:A", pending("did:peer:1")).unwrap();
        let outcome = s.buffer_outbound("did:m:A", pending("did:peer:2")).unwrap();
        match outcome {
            BufferOutcome::DroppedOldest(p) => assert_eq!(p.recipient_did, "did:peer:0"),
            _ => panic!("expected DroppedOldest"),
        }
        assert_eq!(s.outbound_len("did:m:A"), 2);
        let taken = s.take_outbound("did:m:A");
        let recipients: Vec<&str> = taken.iter().map(|p| p.recipient_did.as_str()).collect();
        assert_eq!(recipients, vec!["did:peer:1", "did:peer:2"]);
    }

    #[test]
    fn buffer_outbound_rejects_unknown_listener() {
        let mut s = RegistryState::new();
        let err = s.buffer_outbound("did:m:nope", pending("x")).unwrap_err();
        assert_eq!(err, RegistryError::NotRegistered("did:m:nope".into()));
    }

    #[test]
    fn buffer_outbound_works_for_draining_listener() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        let outcome = s.buffer_outbound("did:m:A", pending("did:peer:1")).unwrap();
        assert!(outcome.is_queued());
    }

    #[test]
    fn cancel_drain_drops_buffered_responses() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        s.buffer_outbound("did:m:A", pending("did:peer:1")).unwrap();
        s.cancel_drain("did:m:A").unwrap();
        assert_eq!(s.outbound_len("did:m:A"), 0);
    }

    #[test]
    fn expire_drains_drops_buffered_responses() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        s.activate(binding("did:m:B", "wss://B"));
        s.start_drain("did:m:A", "wss://A".into(), now_plus(-10))
            .unwrap();
        s.buffer_outbound("did:m:A", pending("did:peer:1")).unwrap();
        s.expire_drains(Utc::now());
        assert_eq!(s.outbound_len("did:m:A"), 0);
    }

    #[test]
    fn generation_increments_on_every_mutation() {
        let mut s = RegistryState::new();
        s.activate(binding("did:m:A", "wss://A"));
        let g1 = s.next_generation;
        s.activate(binding("did:m:B", "wss://B"));
        assert!(s.next_generation > g1);
        let g2 = s.next_generation;
        s.start_drain("did:m:A", "wss://A".into(), now_plus(60))
            .unwrap();
        assert!(s.next_generation > g2);
        let g3 = s.next_generation;
        s.cancel_drain("did:m:A").unwrap();
        assert!(s.next_generation > g3);
    }

    // ---------- async wrapper + telemetry ----------

    fn telemetry() -> SharedTelemetrySink {
        Arc::new(RingBufferTelemetry::with_capacity(64))
    }

    #[tokio::test]
    async fn async_activate_emits_migrate_start() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        let events = sink.query(&TelemetryFilter::new()).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TelemetryKind::MediatorMigrateStart);
        assert_eq!(events[0].mediator_did.as_deref(), Some("did:m:A"));
    }

    #[tokio::test]
    async fn async_drain_emits_drain_start() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        reg.record_activate(binding("did:m:B", "wss://B")).await;
        reg.record_drain("did:m:A", "wss://A".into(), now_plus(60))
            .await
            .unwrap();
        let events = sink
            .query(
                &TelemetryFilter::new()
                    .kind(TelemetryKind::MediatorDrainStart)
                    .mediator("did:m:A"),
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn async_cancel_emits_drain_cancel() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        reg.record_activate(binding("did:m:B", "wss://B")).await;
        reg.record_drain("did:m:A", "wss://A".into(), now_plus(60))
            .await
            .unwrap();
        reg.record_cancel("did:m:A").await.unwrap();
        let events = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::MediatorDrainCancel))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn async_expire_emits_per_dropped_entry() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        reg.record_activate(binding("did:m:B", "wss://B")).await;
        reg.record_activate(binding("did:m:C", "wss://C")).await;
        reg.record_drain("did:m:A", "wss://A".into(), now_plus(-10))
            .await
            .unwrap();
        reg.record_drain("did:m:B", "wss://B".into(), now_plus(-5))
            .await
            .unwrap();
        let dropped = reg.record_expiries(Utc::now()).await;
        assert_eq!(dropped.len(), 2);
        let events = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::MediatorDrainExpire))
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn async_buffer_overflow_emits_response_dropped() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::with_capacity(Arc::clone(&sink), 2);
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        reg.buffer_outbound("did:m:A", pending("did:peer:0"))
            .await
            .unwrap();
        reg.buffer_outbound("did:m:A", pending("did:peer:1"))
            .await
            .unwrap();
        let outcome = reg
            .buffer_outbound("did:m:A", pending("did:peer:2"))
            .await
            .unwrap();
        assert!(outcome.is_dropped());
        let events = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::DidcommResponseDropped))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sender_did.as_deref(), Some("did:peer:0"));
        assert_eq!(
            events[0].fields.get("reason").and_then(|v| v.as_str()),
            Some("buffer-overflow"),
        );
    }

    #[tokio::test]
    async fn active_listener_id_tracks_state() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        assert!(reg.active_listener_id().await.is_none());
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        assert_eq!(reg.active_listener_id().await.as_deref(), Some("did:m:A"));
        reg.record_deactivate().await;
        assert!(reg.active_listener_id().await.is_none());
    }

    #[tokio::test]
    async fn drain_count_is_observable() {
        let sink = telemetry();
        let reg = MediatorListenerRegistry::new(Arc::clone(&sink));
        reg.record_activate(binding("did:m:A", "wss://A")).await;
        reg.record_activate(binding("did:m:B", "wss://B")).await;
        reg.record_drain("did:m:A", "wss://A".into(), now_plus(60))
            .await
            .unwrap();
        assert_eq!(reg.drain_count().await, 1);
    }
}
