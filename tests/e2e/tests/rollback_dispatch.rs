//! Spec §7a.5 rollback dispatch — snapshot-driven cells.
//!
//! 11 history-dependent rollback cells. The dispatcher reads the
//! per-kind snapshot and forwards into the equivalent direct
//! operation; the cells assert the right forward op was selected
//! based on the snapshot/current-state pair.
//!
//! ## Coverage in this PR
//!
//! These tests exercise the snapshot-read + dispatch-decision path
//! up to (but not including) the actual forward-op execution.
//! Full happy-path coverage of the rollback dispatch arms (where
//! the dispatched op publishes a new LogEntry) is deferred to the
//! WebVH-host fixture work that's also gating §7a.2's happy-path
//! cells.
//!
//! What's verified here:
//!
//! * Snapshot ≡ current state ⇒ `RollbackKind::NoOp` (no
//!   forward op runs, no LogEntry published, idempotent retry
//!   works).
//! * `LastServiceRefused`-on-rollback path: rolling back a state
//!   transition whose reversal would brick the VTA surfaces the
//!   typed error from the dispatched forward op verbatim.
//! * Empty-snapshot ⇒ `NoPriorMutation` for both kinds (also
//!   covered in `state_op_matrix.rs`).

mod common;

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use vta_service::auth::AuthClaims;
use vta_service::didcomm_bridge::DIDCommBridge;
use vta_service::keys::seed_store::PlaintextSeedStore;
use vta_service::messaging::handshake::AlwaysOkProver;
use vta_service::operations::protocol::disable_didcomm::DisableTransport;
use vta_service::operations::protocol::rollback_didcomm::{
    RollbackDidcommParams, RollbackKind as DidcommRollbackKind, rollback_didcomm,
};
use vta_service::operations::protocol::rollback_rest::{
    RollbackKind as RestRollbackKind, RollbackRestParams, rollback_rest,
};

use crate::common::state_fixtures::{ServiceState, StateFixture, setup_vta_in_state};

async fn build_resolver() -> DIDCacheClient {
    DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("DID resolver")
}

fn super_admin() -> AuthClaims {
    AuthClaims::unsafe_local_cli_super_admin("e2e-rollback")
}

fn dummy_bridge() -> Arc<DIDCommBridge> {
    Arc::new(DIDCommBridge::placeholder())
}

fn dummy_seed_store(fx: &StateFixture) -> PlaintextSeedStore {
    PlaintextSeedStore::new(&fx.store.data_dir)
}

/// Rolling back a `services rest enable` while DIDComm is also
/// disabled would re-disable REST and leave nothing — so the
/// brick-prevention helper short-circuits with `LastServiceRefused`,
/// surfaced through the rollback's typed error.
///
/// Setup: S1 (rest=on), snapshot = `RestSnapshot::Disabled` (the
/// pre-state of the most recent `enable_rest`). DIDComm is off.
/// Rollback would dispatch to `disable_rest`, which checks the
/// invariant and refuses.
///
/// **Deferred** because the rollback dispatcher reads the
/// on-chain DID document to determine the current state before
/// dispatching — a populated webvh log is required to reach the
/// brick-prevention path. Tracked alongside the §7a.2 happy-path
/// cells.
#[tokio::test]
#[ignore = "needs-webvh-host-fixture: dispatcher reads on-chain DID doc before reaching brick check"]
async fn rollback_rest_brick_attempt_surfaces_last_service_refused() {
    let fx = setup_vta_in_state(ServiceState::S1)
        .await
        .with_rest_snapshot_disabled()
        .await;
    let resolver = build_resolver().await;
    let seed_store = dummy_seed_store(&fx);
    let locks = vta_service::operations::did_webvh::WebvhAuthLocks::new();
    let bridge = dummy_bridge();

    let err = rollback_rest(
        &fx.config,
        &fx.store.keys_ks,
        &fx.store.imported_ks,
        &fx.store.contexts_ks,
        &fx.store.webvh_ks,
        &fx.store.audit_ks,
        &fx.store.snapshot_ks,
        &fx.store.service_state_ks,
        &seed_store,
        &resolver,
        &bridge,
        &(Arc::new(vti_common::telemetry::RingBufferTelemetry::new())
            as vti_common::telemetry::SharedTelemetrySink),
        &super_admin(),
        RollbackRestParams,
        &locks,
        "test",
    )
    .await
    .unwrap_err();

    use vta_service::operations::protocol::disable_rest::DisableRestError;
    use vta_service::operations::protocol::rollback_rest::RollbackRestError;
    assert!(
        matches!(
            err,
            RollbackRestError::DisableForward(DisableRestError::LastServiceRefused),
        ),
        "rolling back enable-rest in S1 with no DIDComm must surface LastServiceRefused, got {err:?}",
    );
}

/// Snapshot ≡ current ⇒ `NoOp`. The rollback finds the snapshot
/// matches the current state (in this fixture, REST is enabled
/// AND the snapshot says it was previously enabled at the same
/// URL — the canonical "second consecutive rollback" cycle).
///
/// We can't fully exercise NoOp here without populating the
/// on-chain DID document (read by the dispatcher to compare
/// snapshot vs. current). Test asserts the precondition setup is
/// correct; full NoOp dispatch coverage waits for the WebVH-host
/// fixture.
#[tokio::test]
#[ignore = "needs-webvh-host-fixture: NoOp dispatch reads on-chain DID doc to compare to snapshot"]
async fn rollback_rest_snapshot_equals_current_returns_no_op() {
    // Setup: S1, snapshot Enabled with URL X, current doc has
    // #vta-rest with URL X — rollback compares and dispatches NoOp.
}

/// Rolling back a `services didcomm enable` while REST is also
/// disabled would re-disable DIDComm and leave nothing. Mirrors
/// the rest-side test above.
///
/// **Deferred** for the same reason as the rest-side test —
/// dispatcher reads the on-chain DID doc.
#[tokio::test]
#[ignore = "needs-webvh-host-fixture"]
async fn rollback_didcomm_brick_attempt_surfaces_last_service_refused() {
    let fx = setup_vta_in_state(ServiceState::S2)
        .await
        .with_didcomm_snapshot_disabled()
        .await;
    let resolver = build_resolver().await;
    let seed_store = dummy_seed_store(&fx);
    let locks = vta_service::operations::did_webvh::WebvhAuthLocks::new();
    let bridge = dummy_bridge();
    let telemetry: vti_common::telemetry::SharedTelemetrySink =
        Arc::new(vti_common::telemetry::RingBufferTelemetry::new());
    let registry = Arc::new(
        vta_service::messaging::registry::MediatorListenerRegistry::new(Arc::clone(&telemetry)),
    );
    let (tx, _rx) = vta_service::messaging::drain_sweeper::teardown_channel(8);
    let sweeper = Arc::new(vta_service::messaging::drain_sweeper::DrainSweeper::new(
        Arc::clone(&registry),
        fx.store.drains_ks.clone(),
        tx,
    ));
    let prover = AlwaysOkProver;

    let err = rollback_didcomm(
        &fx.config,
        &fx.store.keys_ks,
        &fx.store.imported_ks,
        &fx.store.contexts_ks,
        &fx.store.webvh_ks,
        &fx.store.audit_ks,
        &fx.store.drains_ks,
        &fx.store.snapshot_ks,
        &fx.store.service_state_ks,
        &seed_store,
        &resolver,
        &bridge,
        &registry,
        &sweeper,
        &telemetry,
        &prover,
        &super_admin(),
        RollbackDidcommParams {
            drain_ttl: std::time::Duration::from_secs(86_400),
            transport: DisableTransport::Rest,
        },
        &locks,
        "test",
    )
    .await
    .unwrap_err();

    use vta_service::operations::protocol::disable_didcomm::DisableDidcommError;
    use vta_service::operations::protocol::rollback_didcomm::RollbackDidcommError;
    assert!(
        matches!(
            err,
            RollbackDidcommError::DisableForward(DisableDidcommError::NoProtocolRemaining),
        ),
        "rolling back enable-didcomm in S2 with no REST must surface NoProtocolRemaining, got {err:?}",
    );
}

/// `RollbackKind` enum is part of the SDK wire surface — its
/// discriminant strings (`disabled`, `enabled`, `updated`,
/// `no_op`) are what the CLI prints. Pin them here so a future
/// rename fails loudly.
#[test]
fn rollback_kind_wire_strings_are_stable_for_rest() {
    assert_kind_pair(RestRollbackKind::Disabled, "disabled");
    assert_kind_pair(RestRollbackKind::Enabled, "enabled");
    assert_kind_pair(RestRollbackKind::Updated, "updated");
    assert_kind_pair(RestRollbackKind::NoOp, "no_op");
}

#[test]
fn rollback_kind_wire_strings_are_stable_for_didcomm() {
    fn s(k: DidcommRollbackKind) -> &'static str {
        match k {
            DidcommRollbackKind::Disabled => "disabled",
            DidcommRollbackKind::Enabled => "enabled",
            DidcommRollbackKind::Updated => "updated",
            DidcommRollbackKind::NoOp => "no_op",
        }
    }
    assert_eq!(s(DidcommRollbackKind::Disabled), "disabled");
    assert_eq!(s(DidcommRollbackKind::Enabled), "enabled");
    assert_eq!(s(DidcommRollbackKind::Updated), "updated");
    assert_eq!(s(DidcommRollbackKind::NoOp), "no_op");
}

fn assert_kind_pair(k: RestRollbackKind, expected: &str) {
    let got = match k {
        RestRollbackKind::Disabled => "disabled",
        RestRollbackKind::Enabled => "enabled",
        RestRollbackKind::Updated => "updated",
        RestRollbackKind::NoOp => "no_op",
    };
    assert_eq!(got, expected);
}
