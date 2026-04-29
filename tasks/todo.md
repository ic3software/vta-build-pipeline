# Todo: DIDComm Protocol Management

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Each task lists: **acceptance** (what must be true), **verify** (how to
prove it), **files** (what's touched), **deps** (which task IDs must
land first). Tasks within a phase that share `deps` can run in
parallel.

Spec: `docs/05-design-notes/didcomm-protocol-management.md`
Plan: `tasks/plan.md`

---

## Phase 1 — Foundations

### `[x]` P1.1 — TelemetrySink trait + RingBufferTelemetry

- **Acceptance**
  - `TelemetrySink` trait defined with `record(event)` and `query(filter)`
  - `TelemetryEvent` struct with strongly-typed `TelemetryKind` enum
    (no free-string action names)
  - `TelemetryFilter` supports: time range, kind set, mediator DID,
    sender DID
  - `RingBufferTelemetry` is bounded (default capacity 10_000),
    overflow drops oldest, query returns newest-first
  - Trait is in `vti-common`, not behind a feature flag
  - `Send + Sync`, `Arc`-shared, lock-free reads where possible
- **Verify**
  - Unit tests: round-trip event via record/query, time-range filter,
    kind filter, capacity overflow drops oldest
  - Stub impl in `tests/` proves trait swappability (foreshadows
    success criterion #17)
- **Files**
  - `vti-common/src/telemetry/mod.rs` (new)
  - `vti-common/src/telemetry/ring.rs` (new)
  - `vti-common/src/lib.rs` (re-export)
- **Deps**: none

### `[x]` P1.2 — DID-doc service-array patch helpers

- **Acceptance**
  - Pure functions over `serde_json::Value`:
    - `current_didcomm_service(doc) -> Option<DidcommServiceRef>`
    - `with_didcomm_service(doc, did, endpoint) -> Value`
    - `without_didcomm_service(doc) -> Value`
  - Operate by `id` fragment match (`#didcomm`), not by service `type`
    array contents (which can vary by template)
  - Preserve all other service entries byte-for-byte
  - Preserve `verificationMethod`, `authentication`, `keyAgreement`
    arrays byte-for-byte
  - At-most-one `#didcomm` invariant enforced (replace, not append)
- **Verify**
  - Property test: round-trip `with → without → with` on fixture docs
    from `vta-service/tests/fixtures/` produces identical output to
    direct `with` on the original
  - Regression test: feed in a wizard-built doc with `add_mediator_service
    = true`, run `without_didcomm_service`, then re-add — assert byte-
    identical to original
  - Locked-down test: after any patch, `verificationMethod` is byte-
    identical to input (proxies the spec's "verification keys preserved"
    invariant at the helper layer)
- **Files**
  - `vta-service/src/operations/protocol/document.rs` (new)
- **Deps**: none

### `[x]` P1.3 — Multi-mediator listener registry

- **Acceptance**
  - `MediatorListenerRegistry` with operations:
    `record_activate`, `record_drain`, `record_cancel`,
    `record_expiries`, `record_deactivate`, `active_listener_id`,
    `drain_count`, `drain_deadline`
  - Reconnect-with-backoff is provided by upstream
    `RestartPolicy::Always { backoff }` (configured at listener
    add time; not reimplemented in registry)
  - Inbound messages tagged with arrival mediator DID via the
    upstream `HandlerContext.listener_id` (convention:
    `listener_id = mediator_did`)
  - Outbound responses sticky-routed: `buffer_outbound(mediator_did,
    response)` queues for the named listener
  - Per-mediator outbound buffer is bounded (default 128); overflow
    drops oldest and emits `TelemetryKind::DidcommResponseDropped`
- **Verify**
  - Pure state-machine tests cover activate/drain/cancel/expire/
    overflow/rollback/multi-drain/deactivate (16 tests)
  - Async wrapper tests cover telemetry emission for every event
    kind (9 tests)
  - Live in-process mock-mediator integration tests deferred to
    Phase 4 verticals (the upstream library handles WebSocket
    transport; integration belongs at the per-vertical level)
- **Files**
  - `vta-service/src/messaging/registry.rs` (new — at module-mate
    of `messaging/router.rs`, replaces the originally planned
    `didcomm/listener.rs` since upstream provides the per-mediator
    task)
  - `vta-service/src/messaging/mod.rs` (re-export)
- **Deps**: P1.1 (uses `TelemetrySink` for drop events)

### `[x]` P1.4 — PROTOCOL_LOCK

- **Acceptance**
  - Process-wide `tokio::sync::Mutex<()>` named `PROTOCOL_LOCK` in
    `vta-service/src/operations/protocol/mod.rs`
  - All five operations (enable, disable, migrate, drain_cancel,
    plus the `services list` and `report` reads, even though reads
    don't need the lock — make this explicit in code comments)
  - Modelled exactly on `MODE_B_LOCK` placement in
    `vta-service/src/main.rs`
  - Held across the entire op (handshake → publish → registry update),
    not per-step
- **Verify**
  - Concurrency test: spawn two `migrate_mediator` calls
    simultaneously with distinct targets; assert serialization (the
    second observes the first's state, not the original state)
- **Files**
  - `vta-service/src/operations/protocol/mod.rs` (new)
- **Deps**: none

═══ Checkpoint A ═══════════════════════════════════════════════════
**Stop here.** Human reviews trait shapes, registry semantics, doc-
patch correctness. Iterate on P1.1–P1.4 until +1. No spec-visible
behaviour yet — this is plumbing.

---

## Phase 2 — Stateful infra

### `[ ]` P2.1 — Drain state persistence + boot replay

- **Acceptance**
  - New fjall keyspace `drains` (or namespaced under existing
    `webvh` keyspace, decided in implementation)
  - Schema: key = mediator DID, value = `DrainEntry { mediator_did,
    endpoint, drains_until: SystemTime, generation: u64 }`
  - Serialized as CBOR (matches existing keyspace patterns)
  - On VTA boot, replay the drain set: re-register listeners with the
    registry, arm sweepers for remaining TTL
  - 30-day cap enforced at write time (refuse longer; surface error)
- **Verify**
  - Restart test (foreshadows criterion #8): write entry, kill VTA,
    restart, assert listener restored, TTL countdown resumed from
    persisted deadline
  - Cap test: attempt 31-day TTL, assert error variant
    `DrainTtlExceeded`
- **Files**
  - `vta-service/src/operations/protocol/drain.rs` (new)
  - `vta-service/src/operations/protocol/state.rs` (new — boot replay)
- **Deps**: P1.3

### `[ ]` P2.2 — Drain TTL sweeper

- **Acceptance**
  - Single `tokio::task::JoinSet` keyed by mediator DID
  - Each entry: `tokio::time::sleep_until(drains_until)` then
    `registry.cancel(did)` + emit
    `TelemetryKind::MediatorDrainExpire`
  - Cancellation: `drain_cancel` op aborts the entry's task and
    triggers immediate listener teardown
  - Survives boot replay (P2.1 re-arms entries on startup)
- **Verify**
  - Time-mocked test: register drain with TTL 1h, advance clock,
    assert listener dropped + telemetry event
  - Cancel test: register drain, cancel via op, assert task aborted
    + listener dropped immediately
- **Files**
  - `vta-service/src/operations/protocol/drain.rs` (extend)
- **Deps**: P2.1

### `[ ]` P2.3 — Mediator handshake (5-step preflight)

- **Acceptance**
  - `mediator_handshake(did, endpoint, opts)` performs:
    1. Resolve DID → keyAgreement + DIDCommMessaging endpoint
    2. Connect WebSocket, authenticate VTA's DID via
       challenge/response
    3. Register listener with mediator
    4. Send `https://didcomm.org/trust-ping/2.0/ping` to self via
       this mediator
    5. Wait for pong (timeout configurable, default 10s)
  - On any failure: returns typed `MediatorHandshakeFailed { stage,
    cause }` and emits `TelemetryKind::MediatorHandshakeFailed`
  - On success: emits `TelemetryKind::MediatorHandshakeOk`,
    listener stays open and is handed to the registry
  - `--force` callers skip steps 2–5 (NOT step 1) and emit
    `TelemetryKind::MediatorHandshakeBypassed`
- **Verify**
  - Mock mediator with controllable failure injection per stage
  - Test each stage failure → assert correct `stage` field in error
  - Success path test → assert listener handed to registry +
    telemetry event
  - Force bypass → assert no steps 2–5, telemetry "bypassed" event
- **Files**
  - `vta-service/src/operations/protocol/handshake.rs` (new)
- **Deps**: P1.1, P1.3

═══ Checkpoint B ═══════════════════════════════════════════════════
**Stop here.** Human reviews: handshake stages match spec? `--force`
audit shape feels right? Drain TTL math correct? Restart resilience
proven? +1 before phase 3.

---

## Phase 3 — First end-to-end vertical: `enable_didcomm`

This is the trial run for the vertical-slice pattern. Get it right
before replicating three more times.

### `[ ]` P3.1 — `enable_didcomm` operation

- **Acceptance**
  - Function in `vta-service/src/operations/protocol/enable_didcomm.rs`
  - Takes verified params + super-admin auth, returns
    `EnableDidcommResponse { new_version_id, mediator_did }`
  - Holds `PROTOCOL_LOCK` for the duration
  - Sequence: `services.didcomm` config check (must be currently
    false) → run handshake (P2.3) → patch DID doc (P1.2) → call
    `update_did_webvh` (preserves verificationMethod, rotates
    control keys) → flip `services.didcomm = true` in config →
    register listener as active in registry
  - Refuses if DIDComm already enabled with typed error
    `DidcommAlreadyEnabled` (suggested fix: use migrate)
- **Verify**
  - Unit test: state machine guards (already-enabled refusal)
  - Integration test deferred to P3.5
- **Files**
  - `vta-service/src/operations/protocol/enable_didcomm.rs` (new)
- **Deps**: P1.2, P1.3, P1.4, P2.3

### `[ ]` P3.2 — REST route `POST /services/didcomm/enable`

- **Acceptance**
  - Route in `vta-service/src/routes/protocol.rs`
  - JWT-gated, super-admin only
  - Deserializes into `EnableDidcommRequest`, produces
    `VerifiedEnableDidcommRequest` via typestate, hands to op
  - Maps typed errors to HTTP statuses:
    `DidcommAlreadyEnabled` → 409 with body containing suggested fix
    `MediatorHandshakeFailed { stage }` → 502 with `stage` exposed
- **Verify**
  - Route-level integration test against ephemeral VTA
- **Files**
  - `vta-service/src/routes/protocol.rs` (new)
  - `vta-service/src/routes/mod.rs` (mount)
- **Deps**: P3.1

### `[ ]` P3.3 — vta-sdk client + transport selector skeleton

- **Acceptance**
  - `vta-sdk/src/protocol/mod.rs` exposes typed client trait:
    `services_enable_didcomm`, `services_disable_didcomm`,
    `services_list`, `mediator_migrate`, `mediator_drain_cancel`,
    `mediator_report`
  - `--transport` selector (`auto | rest | didcomm`) routes the
    call. `auto` checks if DIDComm is up locally and prefers it,
    else REST. `enable_didcomm` is REST-only and the SDK enforces
    that
  - Returns typed errors that mirror the operation layer's variants
    (no opaque `Protocol(String)`)
  - Only `services_enable_didcomm` actually wired in this task; the
    rest stub `unimplemented!()` (replaced in Phase 4)
- **Verify**
  - SDK client integration test against the route from P3.2
- **Files**
  - `vta-sdk/src/protocol/mod.rs` (new)
  - `vta-sdk/src/protocol/transport.rs` (new — auto/rest/didcomm
    selector)
- **Deps**: P3.2

### `[ ]` P3.4 — `pnm services` command group scaffold

- **Acceptance**
  - `pnm services enable didcomm --mediator-did <did> [--mediator-url
    <url>] [--handshake-timeout <dur>] [--force] [--transport rest]`
    fully wired
  - `pnm services list` wired (reads from local config + registry
    snapshot endpoint)
  - `pnm services disable didcomm` returns "not implemented yet"
    placeholder (filled in Phase 4)
  - Error rendering uses suggested-fix strings — operator sees the
    corrected command, not just the HTTP status
- **Verify**
  - CLI smoke test: `pnm services enable didcomm` against a test VTA
    succeeds end-to-end
  - Suggested-fix message verified by snapshot test
- **Files**
  - `vta-cli-common/src/commands/services.rs` (new)
  - `pnm-cli/src/main.rs` (mount)
- **Deps**: P3.3

### `[ ]` P3.5 — Integration test: success criterion #1

- **Acceptance**
  - Test name: `protocol_enable_didcomm_from_rest_only`
  - Sets up a REST-only VTA via test harness (skips DIDComm in
    setup wizard)
  - Spins up an in-process mock mediator
  - Runs `pnm services enable didcomm --mediator-did <M>` against
    the test VTA
  - Asserts: `did.jsonl` has exactly one new LogEntry; new entry's
    document has exactly one `#didcomm` service pointing at M;
    `verificationMethod` is byte-identical to the prior entry's;
    listener is registered as active; subsequent inbound DIDComm
    challenge/response succeeds via M
- **Verify**
  - Test runs green in CI
- **Files**
  - `vta-service/tests/protocol_enable.rs` (new)
- **Deps**: P3.4

═══ Checkpoint C ═══════════════════════════════════════════════════
**Stop here.** This is the most important review point. Human walks
the full vertical (operation → route → SDK → CLI → integration test)
and confirms the shape is right. Any wire-shape changes now, before
P4 replicates the pattern three more times. +1 to proceed.

---

## Phase 4 — Remaining verticals

Each follows the same shape as Phase 3. Repeat the sub-tasks
(operation, REST route, DIDComm protocol handler, SDK wiring, CLI,
integration test) per vertical. Tasks below are intentionally
coarser — break into the same five sub-tasks as P3.x when starting.

### `[ ]` P4.1 — `disable_didcomm` vertical

- **Acceptance**
  - Op refuses if `services.rest = false` with typed
    `NoProtocolRemaining` error + suggested fix
  - Op refuses `--drain-ttl 0s` when called over DIDComm transport
    with typed `DrainTtlTooShortForDidcomm { min: 1h }`; allows 0s
    over REST
  - Removes `#didcomm` service from DID doc, schedules listener
    drain with given TTL, flips `services.didcomm = false`
  - DIDComm protocol handler at
    `https://openvtc.org/protocols/services-management/1.0/disable`
- **Verify**
  - Integration tests: success criteria #2, #3, #12 from spec
- **Files**
  - `vta-service/src/operations/protocol/disable_didcomm.rs`
  - `vta-service/src/routes/protocol.rs` (extend)
  - `vta-service/src/didcomm/protocol/services_management.rs` (new)
  - `vta-sdk/src/protocol/mod.rs` (wire)
  - `vta-cli-common/src/commands/services.rs` (extend)
  - `vta-service/tests/protocol_disable.rs` (new)
- **Deps**: P3.5 (vertical pattern locked in)

### `[ ]` P4.2 — `migrate_mediator` vertical

- **Acceptance**
  - Op runs handshake against new mediator → publishes LogEntry
    swapping `#didcomm` → places prior mediator in drain
  - Allows overlapping drains (no refusal on multiple in-flight
    drains, modulo the 30-day cap per drain)
  - Refuses if new mediator is already in drain with suggested
    fix pointing at `mediator drain cancel` or `rollback`
  - DIDComm protocol handler at
    `https://openvtc.org/protocols/mediator-management/1.0/migrate`
  - `--transport auto` defaults to DIDComm; CLI flag `--transport
    rest` available
- **Verify**
  - Integration tests: success criteria #4, #5, #11 (#11 = transport
    parity), #13 (handshake aborts publish), #14 (`--force` audit)
- **Files**
  - `vta-service/src/operations/protocol/migrate_mediator.rs`
  - `vta-service/src/didcomm/protocol/mediator_management.rs` (new)
  - `vta-service/tests/protocol_migrate.rs`
  - SDK + CLI wiring
- **Deps**: P3.5

### `[ ]` P4.3 — `drain_cancel` vertical

- **Acceptance**
  - Op drops named mediator's listener immediately, removes drain
    entry, emits `TelemetryKind::MediatorDrainCancel`
  - Refuses if named DID is the active mediator (suggest
    `services disable didcomm`)
- **Verify**
  - Integration test: success criterion #7
- **Files**
  - `vta-service/src/operations/protocol/drain_cancel.rs`
  - SDK + CLI + DIDComm handler + integration test
- **Deps**: P3.5

### `[ ]` P4.4 — `mediator report` vertical

- **Acceptance**
  - Op queries `TelemetrySink` for events in the requested window,
    aggregates per-mediator counts and per-sender last-seen mediator
  - Returns `MediatorReport { window, mediators: Vec<MediatorStats>,
    senders: Vec<SenderLastSeen> }`
  - CLI supports `--format json` (default) and `--format table`
- **Verify**
  - Integration test: success criterion #9
- **Files**
  - `vta-service/src/operations/protocol/report.rs`
  - SDK + CLI + DIDComm handler + integration test
- **Deps**: P3.5

### `[ ]` P4.5 — `rollback` CLI alias

- **Acceptance**
  - `pnm mediator rollback --to <did> --drain-ttl <dur>` calls the
    same migrate op with `audit_kind = MigrateRollback`
  - No new operation code; pure CLI wrapper over P4.2
  - Telemetry event distinguishes rollback from forward migrate
- **Verify**
  - Integration test: success criterion #6 (rollback equivalence:
    DID doc after rollback matches pre-migrate state byte-for-byte
    in `service[]`, modulo `versionId` and rotated control keys)
- **Files**
  - `vta-cli-common/src/commands/mediator.rs` (extend)
  - `vta-service/tests/protocol_rollback.rs`
- **Deps**: P4.2

═══ Checkpoint D ═══════════════════════════════════════════════════
**Stop here.** Human reviews DIDComm-transport behaviour across all
four operations, especially disable-over-DIDComm ordering and 1h
min-TTL guard. +1 to proceed to verification phase.

---

## Phase 5 — Cross-cutting verification + docs

### `[ ]` P5.1 — Full success-criteria test sweep

- **Acceptance**
  - All 17 spec success criteria pass as real integration tests
    (no mocks beyond mediator endpoints)
  - Tests live alongside the per-vertical files; this task is the
    audit that none were skipped or weakened during implementation
- **Verify**
  - CI green; matrix table in PR description maps each criterion
    to the test name that covers it
- **Files**
  - All `vta-service/tests/protocol_*.rs`
- **Deps**: P4.5

### `[ ]` P5.2 — Restart resilience integration test

- **Acceptance**
  - Test name: `protocol_restart_resilience`
  - Triggers mid-drain VTA restart, asserts drain set restored,
    listeners re-opened, TTL countdown resumed
  - Covers spec success criterion #8
- **Verify**
  - Test runs green in CI
- **Files**
  - `vta-service/tests/protocol_restart.rs` (new)
- **Deps**: P5.1

### `[ ]` P5.3 — Telemetry-sink swappability test

- **Acceptance**
  - A test-only `Vec<Mutex<TelemetryEvent>>` impl of `TelemetrySink`
  - Same protocol_migrate test runs with both
    `RingBufferTelemetry` and the test impl, both green
  - Covers spec success criterion #17
- **Verify**
  - CI green
- **Files**
  - `vta-service/tests/protocol_telemetry_swap.rs` (new)
- **Deps**: P5.1

### `[ ]` P5.4 — Operator docs

- **Acceptance**
  - New file `docs/03-integrating/didcomm-protocol-management.md`
    walks an operator through enable, disable, migrate, rollback,
    report — with worked CLI examples and expected DID doc deltas
  - Cross-refs from `docs/03-integrating/did-webvh-update.md`
    (point readers at this for the mediator-specific path)
  - README.md crate map mentions the new feature briefly if needed
- **Verify**
  - Manual review; spec link from docs back to design note
- **Files**
  - `docs/03-integrating/didcomm-protocol-management.md` (new)
  - `docs/03-integrating/did-webvh-update.md` (cross-ref)
- **Deps**: P5.1 (so docs reflect what shipped, not what was planned)

### `[ ]` P5.5 — CHANGELOG entry

- **Acceptance**
  - One CHANGELOG entry per crate that gained surface
    (vti-common, vta-service, vta-sdk, vta-cli-common, pnm-cli),
    versions bumped per workspace convention
  - DCO-signed merge commit
- **Verify**
  - `cargo fmt && cargo clippy --workspace --all-targets &&
    cargo test --workspace` all green
- **Files**
  - `CHANGELOG.md`
  - `*/Cargo.toml` (version bumps where the public API changed)
- **Deps**: P5.4

═══ Checkpoint E ═══════════════════════════════════════════════════
**Done.** Spec criteria all green, docs up to date, version bumps
in. Ready to merge.

---

## Quick reference: spec criterion → task

| # | Criterion | Owning task |
|---|---|---|
| 1 | Enable from REST-only | P3.5 |
| 2 | Disable with drain | P4.1 |
| 3 | Disable refused (no protocol) | P4.1 |
| 4 | Migrate | P4.2 |
| 5 | Overlapping drains | P4.2 |
| 6 | Rollback equivalence | P4.5 |
| 7 | Cancel drain | P4.3 |
| 8 | Restart resilience | P5.2 |
| 9 | Reporting | P4.4 |
| 10 | Verification keys preserved | P1.2 (helper-level), P3.5 (e2e) |
| 11 | DIDComm transport parity | P4.2 (per-op tests) |
| 12 | Disable-over-DIDComm response routing | P4.1 |
| 13 | Handshake aborts publish | P4.2 |
| 14 | `--force` bypass auditable | P4.2 |
| 15 | Reconnect under transient drop | P1.3 (registry-level), P4.2 (e2e) |
| 16 | Sticky outbound routing | P1.3 (registry-level), P4.2 (e2e) |
| 17 | Telemetry-sink swappability | P5.3 |
