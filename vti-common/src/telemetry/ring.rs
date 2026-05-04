//! In-memory bounded ring-buffer telemetry sink.

use std::collections::VecDeque;

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{TelemetryError, TelemetryEvent, TelemetryFilter, TelemetrySink};

const DEFAULT_CAPACITY: usize = 10_000;

pub struct RingBufferTelemetry {
    buf: RwLock<VecDeque<TelemetryEvent>>,
    capacity: usize,
}

impl RingBufferTelemetry {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBufferTelemetry capacity must be > 0");
        Self {
            buf: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for RingBufferTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TelemetrySink for RingBufferTelemetry {
    async fn record(&self, event: TelemetryEvent) -> Result<(), TelemetryError> {
        let mut buf = self.buf.write().await;
        if buf.len() == self.capacity {
            buf.pop_front();
        }
        buf.push_back(event);
        Ok(())
    }

    async fn query(&self, filter: &TelemetryFilter) -> Result<Vec<TelemetryEvent>, TelemetryError> {
        let buf = self.buf.read().await;
        Ok(buf
            .iter()
            .rev()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetryKind;
    use chrono::{Duration, Utc};

    fn ev(kind: TelemetryKind) -> TelemetryEvent {
        TelemetryEvent::new(kind)
    }

    #[tokio::test]
    async fn round_trip_record_and_query() {
        let sink = RingBufferTelemetry::with_capacity(8);
        sink.record(ev(TelemetryKind::DidcommInbound).with_mediator("did:test:A"))
            .await
            .unwrap();
        let out = sink.query(&TelemetryFilter::new()).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, TelemetryKind::DidcommInbound);
        assert_eq!(out[0].mediator_did.as_deref(), Some("did:test:A"));
    }

    #[tokio::test]
    async fn capacity_overflow_drops_oldest() {
        let sink = RingBufferTelemetry::with_capacity(3);
        for i in 0..5 {
            sink.record(
                ev(TelemetryKind::DidcommInbound).with_field("i", serde_json::Value::from(i)),
            )
            .await
            .unwrap();
        }
        let out = sink.query(&TelemetryFilter::new()).await.unwrap();
        assert_eq!(out.len(), 3, "buffer cap respected");
        let ids: Vec<i64> = out
            .iter()
            .map(|e| e.fields["i"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, vec![4, 3, 2], "newest-first; 0 and 1 dropped");
    }

    #[tokio::test]
    async fn time_range_filter() {
        let sink = RingBufferTelemetry::with_capacity(16);
        let t0 = Utc::now();
        for offset_secs in [0, 60, 120] {
            let mut e = ev(TelemetryKind::DidcommInbound);
            e.at = t0 + Duration::seconds(offset_secs);
            sink.record(e).await.unwrap();
        }
        let out = sink
            .query(
                &TelemetryFilter::new()
                    .since(t0 + Duration::seconds(30))
                    .until(t0 + Duration::seconds(90)),
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn kind_filter() {
        let sink = RingBufferTelemetry::with_capacity(16);
        sink.record(ev(TelemetryKind::DidcommInbound))
            .await
            .unwrap();
        sink.record(ev(TelemetryKind::MediatorHandshakeOk))
            .await
            .unwrap();
        sink.record(ev(TelemetryKind::MediatorDrainExpire))
            .await
            .unwrap();
        let out = sink
            .query(&TelemetryFilter::new().kind(TelemetryKind::MediatorHandshakeOk))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, TelemetryKind::MediatorHandshakeOk);
    }

    #[tokio::test]
    async fn mediator_filter() {
        let sink = RingBufferTelemetry::with_capacity(16);
        sink.record(ev(TelemetryKind::DidcommInbound).with_mediator("did:test:A"))
            .await
            .unwrap();
        sink.record(ev(TelemetryKind::DidcommInbound).with_mediator("did:test:B"))
            .await
            .unwrap();
        let out = sink
            .query(&TelemetryFilter::new().mediator("did:test:A"))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mediator_did.as_deref(), Some("did:test:A"));
    }

    #[tokio::test]
    async fn sender_filter() {
        let sink = RingBufferTelemetry::with_capacity(16);
        sink.record(ev(TelemetryKind::DidcommInbound).with_sender("did:peer:alice"))
            .await
            .unwrap();
        sink.record(ev(TelemetryKind::DidcommInbound).with_sender("did:peer:bob"))
            .await
            .unwrap();
        let out = sink
            .query(&TelemetryFilter::new().sender("did:peer:alice"))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sender_did.as_deref(), Some("did:peer:alice"));
    }

    #[tokio::test]
    async fn newest_first_ordering() {
        let sink = RingBufferTelemetry::with_capacity(16);
        for i in 0..5 {
            sink.record(
                ev(TelemetryKind::DidcommInbound).with_field("seq", serde_json::Value::from(i)),
            )
            .await
            .unwrap();
        }
        let out = sink.query(&TelemetryFilter::new()).await.unwrap();
        let seqs: Vec<i64> = out
            .iter()
            .map(|e| e.fields["seq"].as_i64().unwrap())
            .collect();
        assert_eq!(seqs, vec![4, 3, 2, 1, 0]);
    }

    #[tokio::test]
    async fn combined_filters() {
        let sink = RingBufferTelemetry::with_capacity(16);
        sink.record(
            ev(TelemetryKind::DidcommInbound)
                .with_mediator("did:test:A")
                .with_sender("did:peer:alice"),
        )
        .await
        .unwrap();
        sink.record(
            ev(TelemetryKind::DidcommInbound)
                .with_mediator("did:test:A")
                .with_sender("did:peer:bob"),
        )
        .await
        .unwrap();
        sink.record(ev(TelemetryKind::MediatorHandshakeOk).with_mediator("did:test:A"))
            .await
            .unwrap();

        let out = sink
            .query(
                &TelemetryFilter::new()
                    .kind(TelemetryKind::DidcommInbound)
                    .mediator("did:test:A")
                    .sender("did:peer:alice"),
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sender_did.as_deref(), Some("did:peer:alice"));
    }

    #[tokio::test]
    async fn arc_dyn_dispatch_works() {
        // Proves the trait is dyn-compatible — caller can swap impls behind
        // an Arc<dyn TelemetrySink>. Foreshadows P5.3 (criterion #17).
        let sink: super::super::SharedTelemetrySink =
            std::sync::Arc::new(RingBufferTelemetry::with_capacity(4));
        sink.record(ev(TelemetryKind::DidcommInbound))
            .await
            .unwrap();
        let out = sink.query(&TelemetryFilter::new()).await.unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _ = RingBufferTelemetry::with_capacity(0);
    }
}
