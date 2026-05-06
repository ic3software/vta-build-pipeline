# Tasks: Runtime service-endpoint management

Status: **DRAFT — Phase 3 (Tasks)**
Companion to: `runtime-service-management.md` (spec) and
`runtime-service-management-plan.md` (plan).
Owner: Glenn Gore
Last updated: 2026-05-06

Decisions locked in with the user (2026-05-06):
- **Rename:** `migrate_mediator` → `update_didcomm` end-to-end
  (file, fn, message types, telemetry, CLI). It's not really a
  migration — it's an update to which mediator is active.
- **P6.1 parallel with P3:** start the e2e harness alongside
  rollback work.
- **Fold docs:** the existing `didcomm-protocol-management.md`
  pages become redirects to a unified runtime-service-management
  operator guide.

Each task below is sized to land in a single focused session and
touch ≲ 5 files. Tasks are ordered by dependency. `Deps:` lists
prerequisite task IDs; tasks with no `Deps:` are eligible from the
start of their phase.

---

## P0 — Foundations

### T0.1 · Resolve §10 open questions and audit pre-existing code
- **Acceptance:** Spec §10 items 1–4 are converted to decisions and
  recorded in the spec. The `routing_keys` shape in
  `vta_sdk::protocol::protocol_management` is confirmed
  sufficient (or extension scoped if not).
- **Verify:** `git diff docs/05-design-notes/runtime-service-management.md`
  shows the four decisions; grep confirms the `routing_keys` field.
- **Files:** `docs/05-design-notes/runtime-service-management.md`,
  spot-edits to `vta-sdk/src/protocol/protocol_management.rs`
  if extension is needed.

### T0.2 · Add new typed errors to `VtaError`
- **Acceptance:** `LastServiceRefused`, `ServiceNotPresent`,
  `ServiceAlreadyEnabled`, `MediatorHandshakeFailed { reason }`,
  `DrainTtlOutOfBounds { min, max, requested }`, `NoPriorMutation`,
  `UnsupportedTransport` are present (added or confirmed already
  present). Each round-trips through serde via REST and DIDComm
  envelopes.
- **Verify:** `cargo test -p vta-sdk error::serde_round_trip` (new
  parameterized test); audit existing variants to avoid duplicates.
- **Files:** `vta-sdk/src/error.rs`, plus a new test module.

### T0.3 · Per-kind previous-config snapshot store
- **Acceptance:** `vta-service/src/operations/protocol/snapshot.rs`
  exposes `read(&Store, ServiceKind) -> Option<ServiceConfigSnapshot>`,
  `write(&Store, ServiceKind, ServiceConfigSnapshot)`, and
  `clear(&Store, ServiceKind)`. Backed by a new fjall keyspace
  `service-prev-config`. Snapshot persists *before* the runtime
  mutation that depends on it.
- **Verify:** unit tests covering write→read, clear→read=None,
  overwrite, vsock-store parity for the enclave path.
- **Files:** `vta-service/src/operations/protocol/snapshot.rs`
  (new), `vta-service/src/operations/protocol/mod.rs`,
  `vti-common/src/store/keyspace.rs` (or wherever keyspaces are
  registered).

### T0.4 · Brick-prevention invariant helper
- **Acceptance:** `protocol::invariant::would_violate_last_service(
  state: &CurrentServices, op: ProposedOp) -> Result<(), VtaError>`.
  Single source of truth for the §3.2 invariant. Used by every
  `disable` and every `rollback` path.
- **Verify:** unit tests covering all three states × all
  brick-causing ops.
- **Files:** `vta-service/src/operations/protocol/invariant.rs`
  (new), `vta-service/src/operations/protocol/mod.rs`.

---

## P1 — REST operations (parallel with P2)

### T1.1 · Wire types in `vta_sdk::protocol::services`
- **Acceptance:** New module exposes `EnableRestRequest`,
  `UpdateRestRequest`, `DisableRestRequest`, `RollbackRestRequest`,
  `ServiceMutationResponse` per spec §4.
- **Verify:** serde round-trip tests for each type.
- **Files:** `vta-sdk/src/protocol/services.rs` (new),
  `vta-sdk/src/protocol/mod.rs`.
- **Deps:** —

### T1.2 · URL validator helper
- **Acceptance:** `vta_sdk::protocol::services::validate_service_url`
  enforces `https://`, `url::Url` parse, no fragment, no userinfo.
  Returns the typed `VtaError` rejection variant.
- **Verify:** unit tests for each rejection branch + happy path.
- **Files:** `vta-sdk/src/protocol/services.rs`,
  `vta-sdk/src/error.rs`.
- **Deps:** T0.2

### T1.3 · `enable_rest` / `update_rest` / `disable_rest` operations
- **Acceptance:** Three new ops under
  `vta-service/src/operations/protocol/`. Each: validate input →
  invariant check (disable only) → snapshot → mutate DID-doc
  service[] → publish LogEntry → emit telemetry. Errors map to
  typed `VtaError` per the §7a.2 matrix.
- **Verify:** unit tests for happy path + each rejection per
  operation.
- **Files:** `vta-service/src/operations/protocol/{enable_rest,
  update_rest, disable_rest}.rs` (new),
  `vta-service/src/operations/protocol/mod.rs`,
  `vta-service/src/operations/did_webvh/render.rs` (or wherever
  service[] is built).
- **Deps:** T0.3, T0.4, T1.1, T1.2

### T1.4 · REST route handlers for rest operations
- **Acceptance:** `POST /services/rest/{enable,update,disable}`
  wired to T1.3 ops; super-admin auth gating; serde shapes match
  §4.
- **Verify:** Axum handler tests + manual smoke against a local
  VTA (`curl` updates the URL on next `did.jsonl` fetch).
- **Files:** `vta-service/src/routes/protocol.rs`.
- **Deps:** T1.3

### T1.5 · DIDComm handlers for rest operations
- **Acceptance:** Three new DIDComm message types registered;
  handlers in `messaging/handlers_protocol.rs` call the same op
  layer. Authcrypt + ACL gates identical to existing protocol-mgmt.
- **Verify:** handler unit tests against test mediator harness.
- **Files:** `vta-service/src/messaging/handlers_protocol.rs`,
  `vta-sdk/src/protocol/services.rs` (DIDComm message type IDs).
- **Deps:** T1.3

---

## P2 — DIDComm refactor (parallel with P1)

Each task in P2 must be a **mechanical, no-behavior-change**
commit. Tripwire: existing 111-test protocol-mgmt suite runs green
unchanged.

### T2.1 · Adopt snapshot store in existing DIDComm ops
- **Acceptance:** `enable_didcomm`, `disable_didcomm`,
  `migrate_mediator` use `protocol::snapshot::*` instead of any
  ad-hoc previous-mediator tracking.
- **Verify:** existing test suite green; `git diff` shows only
  storage substitution.
- **Files:** `vta-service/src/operations/protocol/{enable_didcomm,
  disable_didcomm, migrate_mediator}.rs`.
- **Deps:** T0.3

### T2.2 · Adopt invariant helper in `disable_didcomm`
- **Acceptance:** Existing brick-prevention check replaced by
  `protocol::invariant::would_violate_last_service`. No behavior
  change.
- **Verify:** existing tests pass.
- **Files:** `vta-service/src/operations/protocol/disable_didcomm.rs`.
- **Deps:** T0.4

### T2.3 · Rename `migrate_mediator` → `update_didcomm`
- **Acceptance:** File renamed
  `migrate_mediator.rs` → `update_didcomm.rs`. Public function
  `migrate_mediator` → `update_didcomm`. SDK message types renamed
  on both REST and DIDComm transports. Telemetry event names
  updated. CLI not touched yet (P5 owns that). Old name absent
  from the codebase (`grep -ri migrate_mediator` returns zero).
- **Verify:** `cargo build --workspace --all-features` clean;
  `cargo test --workspace` green; grep for old name empty.
- **Files:** `vta-service/src/operations/protocol/update_didcomm.rs`
  (renamed), `vta-service/src/operations/protocol/mod.rs`,
  `vta-service/src/routes/protocol.rs`,
  `vta-service/src/messaging/handlers_protocol.rs`,
  `vta-sdk/src/protocol/protocol_management.rs` (message types).
  May exceed 5 files — split commit by layer (ops → routes/msg →
  sdk) if it keeps each commit reviewable.
- **Deps:** T2.1, T2.2

### T2.4 · DIDComm-preferred ordering in DID-doc rendering
- **Acceptance:** When both REST and DIDComm services are
  advertised, the rendered service[] places DIDComm first (per
  T0.1 decision: array-ordering convention).
- **Verify:** new render unit test; chain-replay test against a
  fixture LogEntry chain produced from current `main` confirms
  no client-resolution regression.
- **Files:** `vta-service/src/operations/did_webvh/render.rs`,
  `vta-service/tests/fixtures/` (new fixture chain).
- **Deps:** T0.1

---

## P3 — Fail-forward rollback

### T3.1 · `rollback_rest` operation
- **Acceptance:** Reads snapshot for `rest`, dispatches to
  `enable_rest` / `update_rest` / `disable_rest` based on snapshot
  contents. Brick-prevention rejects via T0.4. Emits
  `service.rest.<verb>` telemetry with `triggered_by: "rollback"`
  (T3.3).
- **Verify:** unit tests for each §7a.5 REST history scenario.
- **Files:** `vta-service/src/operations/protocol/rollback_rest.rs`
  (new), `vta-service/src/operations/protocol/mod.rs`.
- **Deps:** T0.3, T0.4, T1.3, T3.3

### T3.2 · `rollback_didcomm` operation (rewrite as fail-forward)
- **Acceptance:** Replaces existing rollback code. Reads snapshot
  for `didcomm`, dispatches to `enable_didcomm` / `update_didcomm`
  / `disable_didcomm`. Optional `drain_ttl` flows into
  `update_didcomm` / `disable_didcomm`.
- **Verify:** unit tests for each §7a.5 DIDComm history scenario;
  existing rollback tests rewritten to assert fail-forward
  semantic.
- **Files:** `vta-service/src/operations/protocol/rollback_didcomm.rs`
  (new), `vta-service/src/operations/protocol/mod.rs`,
  any existing `rollback`-suffixed file gets folded in or deleted.
- **Deps:** T0.3, T0.4, T2.1, T2.3, T3.3

### T3.3 · `triggered_by` telemetry context
- **Acceptance:** Forward operations accept an `OpContext` enum
  (`Direct` | `Rollback`) and include it in the emitted telemetry
  event payload.
- **Verify:** assertion test that a direct call emits no
  `triggered_by` field and a rollback-routed call emits
  `triggered_by: "rollback"`.
- **Files:** `vta-service/src/operations/protocol/mod.rs`, each
  forward operation file (light touch — pass-through arg),
  `vti-common/src/telemetry/` (event field documented).
- **Deps:** T1.3, T2.1

### T3.4 · Route + DIDComm handlers for rollback
- **Acceptance:** `POST /services/{rest,didcomm}/rollback` wired
  to T3.1/T3.2; matching DIDComm handlers; auth + ACL identical
  to existing protocol-mgmt.
- **Verify:** handler tests; smoke against local VTA.
- **Files:** `vta-service/src/routes/protocol.rs`,
  `vta-service/src/messaging/handlers_protocol.rs`,
  `vta-sdk/src/protocol/services.rs` (DIDComm message type IDs).
- **Deps:** T3.1, T3.2

---

## P4 — `services list` query

### T4.1 · `list_services` operation + handlers
- **Acceptance:** Returns minimal `ServicesListResponse =
  Vec<ServiceState>` where each entry is `{ kind, enabled, config:
  Option<ServiceConfig> }`. REST + DIDComm handlers share one op.
  Super-admin only.
- **Verify:** unit tests against synthetic state for each of
  S1/S2/S3.
- **Files:** `vta-service/src/operations/protocol/list.rs` (new),
  `vta-service/src/routes/protocol.rs`,
  `vta-service/src/messaging/handlers_protocol.rs`,
  `vta-sdk/src/protocol/services.rs`.
- **Deps:** T1.3, T2.1

---

## P5 — CLI surface

### T5.1 · Delete `vta-cli-common::commands::mediator`
- **Acceptance:** File `vta-cli-common/src/commands/mediator.rs`
  deleted; `mod.rs` re-export removed; pnm/cnm clap definitions
  for `mediator` subcommand removed; `cargo build` clean.
- **Verify:** `grep -ri 'commands::mediator' vta-cli-common pnm-cli
  cnm-cli` empty; `cargo build --workspace`.
- **Files:** `vta-cli-common/src/commands/mediator.rs` (delete),
  `vta-cli-common/src/commands/mod.rs`, `pnm-cli/src/main.rs`,
  `cnm-cli/src/main.rs` (or wherever subcommands are defined).
- **Deps:** T2.3

### T5.2 · Rewrite `services.rs` for §5.1 shape
- **Acceptance:** 12 command functions for the §5.1 surface, each
  calling the relevant `vta-sdk` client. No clap definitions in
  this file (those live in pnm/cnm/vta).
- **Verify:** `cargo build --workspace`; manual smoke for one
  command per kind.
- **Files:** `vta-cli-common/src/commands/services.rs` (rewrite),
  `vta-cli-common/src/commands/mod.rs`.
- **Deps:** T1.3, T1.4, T1.5, T2.3, T3.4, T4.1

### T5.3 · Wire pnm-cli + cnm-cli clap subcommands
- **Acceptance:** Clap tree matches §5.1 exactly; help output
  verified. `pnm services rest enable --url X` reaches T5.2's
  function.
- **Verify:** `pnm services --help`, `cnm services --help`.
- **Files:** `pnm-cli/src/main.rs`, `cnm-cli/src/main.rs`.
- **Deps:** T5.2

### T5.4 · Add `vta services …` to vta-service main
- **Acceptance:** Same 12 commands available via the `vta` local
  CLI, dispatched through the same `vta-cli-common::services`
  entry points.
- **Verify:** `vta services --help`; one happy-path command
  end-to-end.
- **Files:** `vta-service/src/main.rs`.
- **Deps:** T5.2

### T5.5 · Operator-error guidance in CLI
- **Acceptance:** Each typed `VtaError` from spec §4 prints a
  suggested-next-command line per CLAUDE.md "operator errors
  should suggest the fix":
  - `LastServiceRefused` → "enable the other transport first via …"
  - `ServiceNotPresent` on update/disable → "this service isn't
    enabled; run `services <kind> enable …`"
  - `ServiceAlreadyEnabled` on enable → "this service is already
    enabled; use `services <kind> update …` to change it"
  - `NoPriorMutation` on rollback → "no prior mutation; use
    `services <kind> <verb>` directly"
  - `DrainTtlOutOfBounds` → "drain TTL must be between {min} and
    {max}"
- **Verify:** manual invocation of each error path.
- **Files:** `vta-cli-common/src/commands/services.rs`, possibly
  a small shared formatter helper.
- **Deps:** T5.2

### T5.6 · Migration cue for retired `mediator` subcommand
- **Acceptance:** `pnm mediator …` and `cnm mediator …` print
  "the `mediator` subcommand was retired in version X.Y; use
  `pnm services didcomm …` instead" and exit non-zero. Custom
  unknown-subcommand handler.
- **Verify:** manual invocation; exit code != 0.
- **Files:** `pnm-cli/src/main.rs`, `cnm-cli/src/main.rs`.
- **Deps:** T5.1

---

## P6 — End-to-end test matrix

T6.1 starts in parallel with P3 (it has no deps on P3 code; it
hits routes that already exist or land with P1/P2).

### T6.1 · State fixtures in `tests/e2e`
- **Acceptance:** Helpers `setup_vta_in_state(S1)`,
  `setup_vta_in_state(S2)`, `setup_vta_in_state(S3)` produce a
  fresh-fjall, fresh-mediator VTA in the documented state.
  Asserted by reading the DID doc and matching service[].
- **Verify:** `cargo nextest run -p e2e fixtures::`.
- **Files:** `tests/e2e/src/fixtures.rs` (new) + `lib.rs`.
- **Deps:** T1.4 (REST routes available), T2.3 (mediator update
  route renamed)

### T6.2 · State × Op matrix tests (§7a.2 + §7a.3)
- **Acceptance:** 24 cell tests, each parameterized over transport
  where the cell is reachable on both. Each test asserts: state
  transition or typed error, exactly one new LogEntry on success
  (zero on error), `verificationMethod` byte-identical pre/post.
- **Verify:** `cargo nextest run -p e2e --test state_op_matrix`.
- **Files:** `tests/e2e/tests/state_op_matrix.rs` (new).
- **Deps:** T6.1, T1.5, T3.4, T4.1

### T6.3 · Drain interaction tests (§7a.4)
- **Acceptance:** 11 scenarios from spec §7a.4. Includes
  process-restart-mid-drain (depends on T6.7).
- **Verify:** `cargo nextest run -p e2e --test drain`.
- **Files:** `tests/e2e/tests/drain.rs` (new).
- **Deps:** T6.1, T6.7

### T6.4 · Rollback history tests (§7a.5)
- **Acceptance:** 11 scenarios from spec §7a.5 (6 DIDComm + 5
  REST), including the `LastServiceRefused` brick-attempts.
- **Verify:** `cargo nextest run -p e2e --test rollback`.
- **Files:** `tests/e2e/tests/rollback.rs` (new).
- **Deps:** T6.1, T3.4

### T6.5 · Sequencing soak paths (§7a.6)
- **Acceptance:** 6 multi-step paths from spec §7a.6.
- **Verify:** `cargo nextest run -p e2e --test sequencing`.
- **Files:** `tests/e2e/tests/sequencing.rs` (new).
- **Deps:** T6.1, T6.7 (path 5 needs restart-resilience)

### T6.6 · Restart-resilience harness
- **Acceptance:** `tests/e2e/src/restart.rs` exposes
  `kill_and_restart(&mut TestVta)` that preserves the on-disk
  fjall store and re-binds the same listener config.
- **Verify:** trivial test that kills a VTA mid-handshake and
  verifies it resumes.
- **Files:** `tests/e2e/src/restart.rs` (new), `tests/e2e/src/lib.rs`.
- **Deps:** T6.1

### T6.7 · CI runtime budget check
- **Acceptance:** Total e2e suite runtime ≤ 10 min on CI runner;
  if exceeded, split into `e2e-fast` and `e2e-slow` jobs.
- **Verify:** GitHub Actions run timing.
- **Files:** `.github/workflows/*.yml`.
- **Deps:** T6.2, T6.3, T6.4, T6.5

---

## P7 — Documentation + memory

### T7.1 · New operator guide
- **Acceptance:** `docs/03-integrating/runtime-service-management.md`
  walks through every §5.1 command with an example transcript.
  Top of the file has the migration note (T7.4 folds in here).
- **Verify:** manual review.
- **Files:** `docs/03-integrating/runtime-service-management.md`
  (new).
- **Deps:** T5.4 (so transcripts use the final command shape)

### T7.2 · Fold + redirect old DIDComm docs
- **Acceptance:** `docs/03-integrating/didcomm-protocol-management.md`
  becomes a one-screen redirect stub linking to T7.1.
  `docs/05-design-notes/didcomm-protocol-management.md` updated to
  state it has been superseded by `runtime-service-management.md`.
- **Verify:** broken-link grep clean; manual review.
- **Files:** `docs/03-integrating/didcomm-protocol-management.md`,
  `docs/05-design-notes/didcomm-protocol-management.md`.
- **Deps:** T7.1

### T7.3 · Update workspace `CLAUDE.md`
- **Acceptance:** "DIDComm protocol management" integration-flow
  section renamed to "Runtime service management"; content
  reflects the generalization (REST + DIDComm, fail-forward
  rollback, snapshot store, brick-prevention, 24h drain default).
- **Verify:** read the section; ensure code-path references match
  current file paths post-rename.
- **Files:** `CLAUDE.md` (workspace root).
- **Deps:** T2.3, T3.2

### T7.4 · Migration note for breaking CLI changes
- **Acceptance:** Top-of-doc section in T7.1 lists removed
  commands and their new equivalents, plus the 24h default drain
  behavior change.
- **Verify:** read the section.
- **Files:** `docs/03-integrating/runtime-service-management.md`.
- **Deps:** T7.1

### T7.5 · Memory updates
- **Acceptance:** Existing
  `project_didcomm_protocol_management.md` updated to "subsumed
  by runtime-service-management feature." A new project memory
  records the load-bearing architectural choices (per-kind
  snapshot store, fail-forward rollback, brick-prevention
  invariant, 24h drain default) so future sessions don't
  re-litigate them.
- **Verify:** memory entries readable via the auto-memory system.
- **Files:** `~/.claude/projects/.../memory/project_didcomm_protocol_management.md`,
  `~/.claude/projects/.../memory/project_runtime_service_management.md`,
  `~/.claude/projects/.../memory/MEMORY.md`.
- **Deps:** all prior phases done

---

## Phase summary

| Phase | Tasks | Critical-path tasks |
|---|---|---|
| P0 | T0.1 – T0.4 | T0.3, T0.4 |
| P1 | T1.1 – T1.5 | T1.3 |
| P2 | T2.1 – T2.4 | T2.3 |
| P3 | T3.1 – T3.4 | T3.4 |
| P4 | T4.1 | T4.1 |
| P5 | T5.1 – T5.6 | T5.2 → T5.3/T5.4 |
| P6 | T6.1 – T6.7 | T6.1 → T6.2 |
| P7 | T7.1 – T7.5 | T7.1 |

**Total:** 33 tasks. Median ~3 files / task; longest is T2.3
(rename) which is split by review-friendly layers.

## Implementation order — recommended commit landing sequence

If a single engineer is driving this end-to-end, the order that
keeps each commit reviewable and CI green is:

1. T0.1 → T0.2 → T0.3 → T0.4
2. T1.1 → T1.2 (parallel safe with anything below)
3. T2.1 → T2.2 (mechanical, no behavior change)
4. T2.3 (rename — the breaking-API commit)
5. T2.4 (ordering — landed once because every later test depends)
6. T1.3 → T1.4 → T1.5 (REST surface goes live)
7. T6.1 (e2e harness — start using it for everything below)
8. T6.6 (restart helper — needed for drain tests soon)
9. T3.3 → T3.1 → T3.2 → T3.4 (rollback)
10. T4.1 (list)
11. T6.2 → T6.4 → T6.3 → T6.5 (test matrix progressively)
12. T5.1 → T5.2 → T5.3 → T5.4 → T5.5 → T5.6 (CLI flip)
13. T7.1 → T7.2 → T7.3 → T7.4 → T7.5 (docs + memory)
14. T6.7 (CI budget check — last, when full suite exists)

## Once tasks are approved

I'll move to Phase 4 (Implement) starting at T0.1. Each task is
landed via:
1. Branch from `main`: `feat/runtime-services-T<id>`
2. Implement → unit tests → `cargo fmt`
3. Open PR; CI green; review
4. Merge with DCO sign-off

Per CLAUDE.md commit hygiene: no `--no-verify`, no skipping DCO
signatures, no amending merged commits.
