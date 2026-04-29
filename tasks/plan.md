# Plan: DIDComm Protocol Management (post-setup)

Companion to `docs/05-design-notes/didcomm-protocol-management.md`.
This is the implementation plan; `todo.md` is the actionable task list.

## Objective

Ship the four operator-facing features in the spec — enable, disable,
migrate, rollback — plus reporting, with DIDComm-first transport and
production-grade resilience (handshake-before-promotion, drain set,
sticky outbound routing). Single PNM CLI surface; CNM out of scope.

## Phase 1 outcome (2026-04-29)

Phase 1 landed with Checkpoint A green. Three design adjustments
discovered during implementation, recorded here so the plan stays
accurate:

1. **Upstream library already provides reconnect.** The
   `affinidi-messaging-didcomm-service` crate provides
   `add_listener` / `remove_listener` /
   `send_message_with_retry(listener_id, ...)` and
   `RestartPolicy::Always { backoff: RetryConfig }`. The
   `MediatorListenerRegistry` is therefore a thin state-machine +
   telemetry layer rather than a per-mediator task implementation.
   The originally planned `vta-service/src/didcomm/listener.rs` file
   is unnecessary.
2. **Registry lives at `vta-service/src/messaging/registry.rs`** to
   match the existing `messaging/` module layout (sibling to
   `messaging/router.rs` and `messaging/handlers.rs`).
3. **DIDComm fragment is `#vta-didcomm`**, not `#didcomm`. The
   workspace's setup wizard already emits this fragment; the
   patcher matches it for backward compatibility with already-
   published DID documents. Spec text uses `#didcomm` as a
   shorthand only.

Convention adopted: **listener id = mediator DID**. This makes
inbound attribution free — `HandlerContext.listener_id` already
carries the originating mediator DID with no additional plumbing.

## Component dependency graph

```
                        ┌─────────────────────┐
                        │ TelemetrySink trait │
                        │ + RingBuffer impl   │
                        │ (vti-common)        │
                        └──────────┬──────────┘
                                   │
            ┌──────────────────────┴──────────────────────┐
            ▼                                             ▼
  ┌─────────────────────┐                    ┌────────────────────────┐
  │ Listener registry   │                    │ DID-doc service        │
  │ (multi-mediator,    │                    │ patch helpers          │
  │  reconnect, sticky) │                    │ (read-modify-write of  │
  │ (didcomm_bridge.rs) │                    │  service[])            │
  └──────────┬──────────┘                    └────────────┬───────────┘
             │                                            │
             ├────────────┬─────────────────┐             │
             ▼            ▼                 ▼             │
   ┌──────────────┐ ┌───────────┐  ┌──────────────┐       │
   │ Drain state  │ │ Handshake │  │ PROTOCOL_LOCK│       │
   │ + sweeper    │ │ preflight │  │              │       │
   │ (fjall ks)   │ │ (5-step)  │  │              │       │
   └──────┬───────┘ └─────┬─────┘  └───────┬──────┘       │
          │               │                │              │
          └───────────────┴────────┬───────┴──────────────┘
                                   ▼
                       ┌───────────────────────┐
                       │ Operations            │
                       │ - enable_didcomm      │
                       │ - disable_didcomm     │
                       │ - migrate_mediator    │
                       │ - drain_cancel        │
                       │ - report_query        │
                       └───────────┬───────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
      ┌─────────────────┐                  ┌────────────────────┐
      │ REST routes     │                  │ DIDComm protocol   │
      │ (routes/        │                  │ handlers           │
      │  protocol.rs)   │                  │ (didcomm/protocol/)│
      └────────┬────────┘                  └──────────┬─────────┘
               │                                      │
               └──────────────────┬───────────────────┘
                                  ▼
                       ┌──────────────────────┐
                       │ vta-sdk client       │
                       │ + transport selector │
                       │ (--transport auto/…) │
                       └──────────┬───────────┘
                                  ▼
                    ┌──────────────────────────┐
                    │ pnm-cli command groups   │
                    │ - services {enable,…}    │
                    │ - mediator {migrate,…}   │
                    └──────────────────────────┘
```

Dependencies flow downward; no cycles. Foundations on the left
(telemetry, doc patch) are pure additions and can be built in
parallel with the registry on the right.

## Slicing strategy: vertical, not horizontal

We do **not** ship "all operations at once, then all routes at once,
then all CLI at once." Instead, after the foundations land, each
operator-facing feature is a **vertical slice**: operation +
REST route + DIDComm handler + SDK client + CLI command + integration
test. The `enable` slice ships before `disable` ships before `migrate`
ships. This way:

- Each PR is independently reviewable.
- We discover wire-shape mistakes on the first vertical and fix them
  before they replicate across the other three.
- The integration test for each slice exercises the full stack — we
  do not merge a half-wired feature.

## Phase sequence

```
Phase 1 — Foundations (parallel-safe)
    P1.1 Telemetry sink trait + ring-buffer impl
    P1.2 DID-doc service-array patch helpers
    P1.3 Listener registry (multi-mediator)
    P1.4 PROTOCOL_LOCK
═════════════════════════════════ Checkpoint A ═════════════════════════════════
        Review trait shapes, registry semantics, doc-patch correctness.
        No spec-visible behaviour yet; this is plumbing.

Phase 2 — Stateful infra
    P2.1 Drain state persistence + boot replay
    P2.2 Drain TTL sweeper (JoinSet)
    P2.3 Mediator handshake (5-step preflight + --force bypass)
═════════════════════════════════ Checkpoint B ═════════════════════════════════
        Review handshake stages, --force audit, drain restart-resilience.

Phase 3 — First end-to-end vertical: enable_didcomm
    P3.1 enable_didcomm operation
    P3.2 REST route POST /services/didcomm/enable
    P3.3 vta-sdk client + transport selector (REST-only path here)
    P3.4 pnm services enable/list/disable CLI scaffold (enable wired,
         disable returning "not implemented" placeholder)
    P3.5 Integration test: success criterion #1
═════════════════════════════════ Checkpoint C ═════════════════════════════════
        Review the full vertical shape — operation, route, SDK, CLI.
        Adjust before replicating the pattern three more times.

Phase 4 — Remaining verticals
    P4.1 disable_didcomm vertical (op + REST + DIDComm handler + SDK + CLI)
    P4.2 migrate_mediator vertical
    P4.3 drain_cancel vertical
    P4.4 mediator report vertical
    P4.5 rollback CLI (thin wrapper around migrate)
═════════════════════════════════ Checkpoint D ═════════════════════════════════
        Review DIDComm-transport wiring, especially disable-over-DIDComm
        ordering and 1h min-TTL guard.

Phase 5 — Cross-cutting verification + docs
    P5.1 All 17 success criteria as integration tests (green)
    P5.2 Restart resilience test (criterion #8)
    P5.3 Telemetry-sink swappability test (criterion #17)
    P5.4 Operator docs in docs/03-integrating/
    P5.5 CHANGELOG entry
═════════════════════════════════ Checkpoint E ═════════════════════════════════
        Final review. Spec criteria all green. Ready to merge.
```

## Risk register and mitigations

| Risk | Mitigation |
|---|---|
| **`update_did_webvh` semantics shift** under us (spec assumes control-key rotation only when `document = Some`). | P1.2 includes a regression test that locks down "verificationMethod byte-identical after document-change update" against fixture data. Catches any upstream change. |
| **Listener registry races** when migrate and disconnect interleave. | All registry mutations go through a `parking_lot::RwLock` over the registry map; reconnect tasks check generation counters before re-arming a connection. Covered in success criterion #15. |
| **Trust-ping round-trip flaky** in CI. | `--handshake-timeout` is configurable; CI sets it explicitly. Mock mediator implements ping handler. |
| **Outbound buffering blowup** when drain mediator is unreachable for a long time. | Per-mediator buffer is bounded (e.g. 128 messages); overflow drops oldest with telemetry event. Spec already says "in-memory only, dropped on restart." |
| **DIDComm transport for `disable didcomm`** orders wrong (response after listener teardown). | 1h min-TTL guard makes this non-physical. Success criterion #12 verifies. |
| **Spec drift during implementation** (we discover the shape needs to change). | Update the spec **first**, then implement. Each PR links to the spec section it implements. |
| **Existing setup wizard regressions** from doc-patch helpers. | P1.2 must run the existing wizard test suite green. No changes to wizard code in this feature. |

## Out of scope (explicit non-goals)

- CNM CLI surface (deferred per operator decision).
- Persisting outbound DIDComm response buffers across restart.
- Alternate `TelemetrySink` impls beyond `RingBufferTelemetry` (file,
  blockchain, fjall sink — trait ships, impls do not).
- Auto-rotation of `verificationMethod` keys (this feature explicitly
  must not touch them).
- Mediator provisioning — operator brings the mediator DID; provisioning
  remains `provision-integration --template didcomm-mediator`.
- Unifying the `audit!` macro with `TelemetrySink` (separate refactor).
- DIDComm v2 transport for `enable didcomm` (impossible — DIDComm not
  yet up at call time; REST-only by nature).

## Verification model

A task is **not done** until:

1. Code change merges with passing CI (`cargo build --workspace`,
   `cargo test --workspace`, `cargo clippy --workspace --all-targets`,
   `cargo fmt --check`).
2. Acceptance criteria hold (in `todo.md` per task).
3. The relevant spec success criterion passes as a real integration
   test (not a mock).
4. Audit/telemetry events emit with the documented shapes.

For the cross-cutting Phase 5 work, a task is done when the explicitly
named spec success criterion (e.g. #8, #17) executes green in CI.

## Estimation

This is design-doc-level estimation; refine when slicing each task.

| Phase | Slices | Rough effort |
|---|---|---|
| 1 — Foundations | 4 | 2–3 days |
| 2 — Stateful infra | 3 | 2 days |
| 3 — First vertical | 5 | 1–2 days |
| 4 — Remaining verticals | 5 | 4–5 days |
| 5 — Verification + docs | 5 | 1–2 days |
| **Total** | **22** | **~2 weeks of focused work** |

Verticals after the first should compress significantly because the
shape is set — most of the cost is in the first vertical and the
foundations.
