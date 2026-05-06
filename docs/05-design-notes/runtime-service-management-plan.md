# Plan: Runtime service-endpoint management

Status: **Implemented**
Companion to: `runtime-service-management.md` (the approved spec)
Owner: Glenn Gore
Last updated: 2026-05-06

This plan decomposes the spec into ordered phases, identifies what
can run in parallel, lists the major risks, and pins the verification
checkpoint at each phase boundary. Tasks (Phase 3) are generated
**from this plan** in a separate doc.

## P0. Foundations (blocks everything else)

These need to land first. Tiny, individually trivial, but absolutely
on the critical path.

* **P0.1 — Resolve §10 open questions.** Convert the four spec open
  questions into decisions:
  * DIDComm-preferred encoding: choose array-ordering (DIDComm
    first) **or** DIDComm v2 `priority` key. Recommendation: array
    ordering — it's universally honored by DID-Core resolvers,
    `priority` is only DIDComm v2 spec-aware. Confirm by reading
    the existing built-in templates' service shapes.
  * URL reachability probing: **don't probe.** Trust the operator,
    consistent with mediator DID handling.
  * `routing_keys`: confirm the existing
    `vta_sdk::protocol::protocol_management` shape carries it; if
    not, extend before P1.
  * `services list` JSON shape: minimal — `{kind, enabled, config}`
    per kind. Don't reuse `services report`'s telemetry-heavy
    schema.
* **P0.2 — Add new typed errors to `VtaError`.** `NoPriorMutation`,
  `UnsupportedTransport`, `LastServiceRefused`, `ServiceNotPresent`,
  `ServiceAlreadyEnabled`, `MediatorHandshakeFailed`,
  `DrainTtlOutOfBounds`. Some may already exist — audit
  `vta-sdk/src/error.rs` first.
* **P0.3 — Previous-config snapshot store.** New fjall keyspace
  `service-prev-config/<kind>`; module
  `vta-service/src/operations/protocol/snapshot.rs` with
  `read`/`write`/`clear` accessors. **Order invariant:** snapshot
  is persisted *before* the runtime mutation runs, so a crash
  between snapshot and mutation just means rollback target is the
  current state (no-op). Crash between mutation and LogEntry
  publication is the existing transactional-rollback pattern.
* **P0.4 — Brick-prevention invariant helper.**
  `protocol::invariant::would_violate_last_service(state, op) ->
  Result<(), VtaError>`. Used by every `disable` and every
  `rollback` path. Single source of truth — no duplicated
  conditionals.

**Verification:** `cargo build --workspace --all-features` clean.
New errors round-trip through serde (REST + DIDComm transports).

## P1. REST operations (parallel with P2)

* **P1.1 — Wire types** in `vta-sdk::protocol::services`:
  `EnableRestRequest`, `UpdateRestRequest`, `DisableRestRequest`,
  `RollbackRestRequest`, `ServiceMutationResponse`.
* **P1.2 — URL validator** in vta-sdk: shared by REST + service-entry
  rendering. `https://` only, `url::Url` parse, no fragment, no
  userinfo.
* **P1.3 — REST operations** under `vta-service/src/operations/protocol/`:
  `enable_rest.rs`, `update_rest.rs`, `disable_rest.rs`. Each:
  * validate input
  * check brick-prevention (disable only)
  * persist snapshot (P0.3)
  * mutate DID-doc service[]
  * publish LogEntry
  * emit telemetry
* **P1.4 — REST route handlers** in `routes/protocol.rs`. Wire to
  the shared operation layer (no duplicated logic).
* **P1.5 — DIDComm handlers for REST operations** in
  `messaging/handlers_protocol.rs`. Same shared operation layer.

**Verification:** unit tests in each `operations/protocol/*_rest.rs`
file cover happy path + each rejection variant. Manual smoke:
`curl -X POST .../services/rest/update -d '{"url":"..."}'` against
a local VTA changes the URL on next `did.jsonl` fetch.

## P2. DIDComm refactor (parallel with P1)

Goal: bring the existing DIDComm operations onto the shared snapshot
store + brick-prevention helper without changing observable behavior.
**Refactor first; add features second.** Each step here should be
zero-behavior-change relative to today's tests.

* **P2.1 — Adopt P0.3 snapshot store** in `enable_didcomm.rs`,
  `disable_didcomm.rs`, `migrate_mediator.rs`. Replace any ad-hoc
  "previous mediator" tracking with the new module.
* **P2.2 — Adopt P0.4 invariant helper** in `disable_didcomm.rs`.
  Existing `LastServiceRefused`-equivalent check is replaced by
  the shared helper.
* **P2.3 — Rename for spec alignment.** Internal: keep file names
  but expose the operations as `update_didcomm` (was migrate). No
  semantic change. The `migrate_mediator.rs` file can stay; just
  rename the public `pub fn` and update call sites. (Optional —
  only do this if it doesn't sprawl. If it does, defer to a
  follow-up.)
* **P2.4 — DIDComm-preferred ordering** per P0.1 decision. One
  function in `did_webvh/render.rs` (or wherever service[] is
  built) sorts the array. Touched by every operation but lives in
  one place.

**Verification:** all existing protocol-management tests still pass
unchanged. `git diff` on each refactor commit shows mechanical
changes only — no logic edits.

## P3. Fail-forward rollback

Builds on P0.3 (snapshot store), P1 (REST ops), P2 (DIDComm
refactor). Rollback is *literally* "read snapshot → run forward
operation → done." That's why the snapshot store has to exist
first.

* **P3.1 — `rollback_rest.rs`.** Reads snapshot for `rest`, dispatches
  to `enable_rest` / `update_rest` / `disable_rest` based on what
  the snapshot reveals.
* **P3.2 — `rollback_didcomm.rs`.** Same pattern. Replaces today's
  rollback path; **breaking** semantic change from "rewind" to
  "fail-forward." Update existing tests.
* **P3.3 — Telemetry `triggered_by` field.** The forward operations
  emit `service.<kind>.<verb>` events. Rollback dispatches into
  them with a context flag that adds `triggered_by: "rollback"` to
  the event metadata. Simple enum on the operation entry point.
* **P3.4 — Brick-prevention on rollback.** Reuses P0.4. Tested by
  the §7a.5 history scenarios that resolve to `LastServiceRefused`.

**Verification:** unit tests for each rollback path covering the
§7a.5 histories at unit level. e2e versions come in P6.

## P4. `services list` query

* **P4.1 — Operation** `protocol::list::list_services()` returning
  `ServicesListResponse` (per P0.1 minimal shape).
* **P4.2 — REST + DIDComm handlers** wiring to P4.1.

**Verification:** unit test against synthetic state covering S1, S2,
S3.

## P5. CLI surface

Breaking change to the user-facing CLI per the spec. Touch carefully:
the `pnm`/`cnm`/`vta` binaries all share `vta-cli-common`.

* **P5.1 — Delete `vta-cli-common/src/commands/mediator.rs`.**
  Update `mod.rs` re-exports.
* **P5.2 — Rewrite `vta-cli-common/src/commands/services.rs`** to
  the §5.1 shape. New functions per (kind, verb) pair.
* **P5.3 — `pnm-cli`/`cnm-cli` clap definitions.** Drop `mediator`
  subcommand; expand `services` subcommand to the new tree.
* **P5.4 — `vta services …`** — add to `vta-service/src/main.rs`.
* **P5.5 — Operator-error guidance.** Per CLAUDE.md, when a
  command fails with a typed `VtaError`, the CLI prints the
  corrected command. Specifically:
  * `LastServiceRefused` → suggest enabling the other transport
    first
  * `ServiceNotPresent` on `update` → suggest `enable`
  * `ServiceAlreadyEnabled` on `enable` → suggest `update`
  * `NoPriorMutation` on `rollback` → "no prior mutation to roll
    back to; use `services <kind> <verb>` directly"
* **P5.6 — Migration cue.** When the old `pnm mediator` command
  is invoked, clap will reject it (subcommand not found). Add a
  custom error message printer that catches the unknown-subcommand
  path and suggests the new shape, e.g., "the `mediator` subcommand
  was retired; try `pnm services didcomm …`."

**Verification:** `pnm --help`, `cnm --help`, `vta --help` all show
the new tree. `pnm mediator migrate <did>` prints the migration cue.
Each of the new commands runs against a local VTA end-to-end.

## P6. End-to-end test matrix

Per spec §7a. ~64 tests. Build the harness once; the tests are
small. The harness is the bulk of the work.

* **P6.1 — State fixtures** in `tests/e2e`: helpers
  `setup_vta_in_state(S1|S2|S3)` that produce a freshly-set-up VTA
  in each starting state. Foundational — every other test depends.
* **P6.2 — State × Op matrix tests (§7a.2).** 24 cells. Each test
  asserts: outcome (state transition or typed error), one new
  LogEntry (or none for error paths), `verificationMethod`
  byte-identical. Most cells are 10–20 lines.
* **P6.3 — Transport coverage (§7a.3).** Re-run §7a.2's accepted
  cells over DIDComm transport using the existing test mediator.
  Done as a parameterized test rather than copy-paste.
* **P6.4 — Drain interaction tests (§7a.4).** 11 scenarios. Each
  exercises drain set persistence, sticky routing, restart
  replay, TTL bounds.
* **P6.5 — Rollback history tests (§7a.5).** 11 scenarios.
* **P6.6 — Sequencing soak paths (§7a.6).** 6 paths. These look
  like operator session transcripts.
* **P6.7 — Restart-resilience harness.** Helper to kill + restart
  the VTA process mid-test. Used by §7a.4 restart row and §7a.6
  path 5.

**Verification:** all e2e tests green under `cargo nextest run -p
e2e`. CI time delta tracked — if it doubles, we parallelize harder
or split into a separate CI job.

## P7. Documentation

* **P7.1 — New operator guide:**
  `docs/03-integrating/runtime-service-management.md`. Walks
  through every command with an example transcript.
* **P7.2 — Retire/redirect:**
  `docs/03-integrating/didcomm-protocol-management.md` and
  `docs/05-design-notes/didcomm-protocol-management.md`. Either
  fold their content into the new doc and leave a stub redirect,
  or update them to scope-only-DIDComm-specifics. Pick one in P7
  start.
* **P7.3 — Workspace CLAUDE.md.** Update the "DIDComm protocol
  management" integration-flow section to reflect the
  generalization. Rename it to "Runtime service management."
* **P7.4 — Migration note.** Brief upgrade guide for the breaking
  CLI changes. Likely lives at top of P7.1 doc.
* **P7.5 — Two memory entries** (per the auto-memory system):
  one updating `project_didcomm_protocol_management.md` to
  "subsumed by runtime-service-management"; one new project
  memory recording the architectural choice (per-kind snapshot
  store, fail-forward rollback) so future sessions don't
  re-litigate it.

**Verification:** docs reviewed. CLAUDE.md updated. Memory entries
written.

## Critical-path graph

```
        ┌──── P1 (REST ops) ────┐
P0 ────┤                          ├──→ P3 (rollback) ──→ P4 (list) ──→ P5 (CLI) ──→ P6 (e2e) ──→ P7 (docs)
        └──── P2 (DIDComm refactor)
```

* P0 is fully sequential and small.
* P1 and P2 are independent and run in parallel.
* P3 needs both P1 and P2 done.
* P4 is a small leaf; runs alongside P3 if convenient.
* P5 needs operations stable (P3 done).
* P6 needs CLI stable (P5 done) — well, the e2e tests can use the
  REST API directly without CLI, so P6.1–P6.6 *could* start after
  P3, with the CLI-using paths in P6.6 deferred. Worth doing if P5
  becomes a bottleneck.
* P7 is parallel-with-P6 territory.

## Parallelism opportunities

| Pair | Can run in parallel? |
|---|---|
| P1 ↔ P2 | Yes — different code paths, both depend only on P0 |
| P3.1 ↔ P3.2 | Yes — REST and DIDComm rollback are independent |
| P6.2 ↔ P6.4 ↔ P6.5 | Yes — different test categories |
| P6 ↔ P7 | Yes — docs work doesn't need green tests |

Phases that **cannot** parallelize:
- P0 must finish before any other phase
- P5 cannot start until P3 is stable (CLI calls operations)
- P6 transport-coverage tests need P5's DIDComm handlers (or hit
  the messaging layer directly)

## Risks (specific to this implementation)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| P2 refactor accidentally regresses drain timing or handshake | medium | high | Refactor commits must show no test diff; existing 111-test suite is the trip-wire |
| Snapshot persisted, mutation succeeds, LogEntry publish fails | low | medium | Same transactional-rollback pattern as today's `migrate_mediator`; test crash injection at each step |
| DIDComm-preferred encoding (P2.4) breaks compat with existing chains | medium | high | Add a one-time chain-replay test on a fixture chain produced by current main; assert clients still resolve correctly |
| Single-step rollback semantics surprise an operator | low | low | Doc'd in spec §3.5a; `services list` shows previous-config so operator can self-check |
| ~64 e2e tests blow CI time | high | medium | Parameterize §7a.2/§7a.3 in nextest; split into a separate CI job if > 10 min |
| Breaking CLI change reaches a user mid-session | low | low | P5.6 migration cue; release notes on next version bump |
| `pnm mediator` references inside our own docs | medium | low | Grep audit in P7 |

## Verification checkpoints (gate to next phase)

* **End of P0:** workspace builds clean, errors serialize, snapshot
  store has a passing read/write/clear test.
* **End of P1:** REST operations have unit tests passing, manual
  smoke against a local VTA changes the URL.
* **End of P2:** existing test suite still green, mechanical-diff
  refactor commits.
* **End of P3:** rollback unit tests pass for both kinds, including
  brick-prevention rejections.
* **End of P4:** `services list` returns the documented shape from
  S1/S2/S3 fixtures.
* **End of P5:** new CLI surface live, old commands print
  migration cue, operator-error guidance verified by manual
  invocation.
* **End of P6:** all 64 e2e tests green; CI time within budget.
* **End of P7:** docs reviewed, CLAUDE.md updated, memory entries
  written.

## What this plan does **not** decide

These remain spec-internal questions and are deferred to the Tasks
phase or implementation:

* Exact field names in wire types (`mediator_did` vs `mediator`)
* Telemetry event JSON schema beyond name + LogEntry version-id
* CI job split vs. single job for new e2e tests
* Whether to fold `didcomm-protocol-management.md` docs into the
  new doc or leave them as historical notes (decide in P7)

## Open items requiring user input before Phase 3

These are go/no-go decisions before I generate tasks:

1. **P2.3 — internal rename `migrate_mediator` → `update_didcomm`.**
   Worth doing, or leave the file/function names as-is and only
   rename at the public surface? My lean: rename for symmetry with
   the spec, but if it sprawls, defer.
2. **P6 ordering — start e2e harness work (P6.1) in parallel with
   P3?** This is "build the harness early so we can use it for P3
   verification." Lean: yes — P6.1 has no deps on P3.
3. **P7 docs disposition — fold `didcomm-protocol-management.md`
   docs into the new unified doc, or leave them as
   pre-generalization historical notes?** Lean: fold and leave a
   redirect, since the new content is a strict superset.

Once you give a thumbs-up (and resolve those three), I'll generate
the Phase 3 task list with explicit acceptance criteria and file
paths per task.
