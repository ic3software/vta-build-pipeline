# VTC MVP — Phase 3 plan

> **Status:** draft, awaiting review.
> **Deliverable:** "Community on the wider network." Per spec
> §16 Phase 3: trust-registry publish, three departure
> dispositions, `registry.rego` consumption, `MembershipSyncer`
> + diagnostic surfacing, RTBF override + batched timing,
> cross-community recognition (session-mint hardening).
> **Spec:** `docs/05-design-notes/vtc-mvp.md` §§5.7, 6.1,
> 8.1–8.4, 11.1, 13, 14.3.

## Objective

After Phase 3, a VTC stops being an island:

- The VTC publishes its issuer profile to the configured trust
  registry on boot. Publish failures degrade `registry_status`
  but don't crash the daemon.
- Every `MemberAdded` / `MemberRemoved` / `RoleChanged` audit
  event drives a sync job against the registry. The
  `MembershipSyncer` task reconciles asynchronously with
  exponential backoff + boot-time replay.
- Removals resolve to one of three dispositions
  (`Purge` / `Tombstone` / `Historical`), with the envelope
  set by `registry.rego` (default policy already shipped in
  Phase 2 — Phase 3 wires the consumer).
- A member-initiated `Purge` always overrides the policy's
  `min_disposition` floor (RTBF). RTBF mutations are batched
  daily so record-disappearance can't be timed-aligned with the
  override event.
- A foreign community's VEC can mint a local session — but
  only if the live StatusList check passes, the foreign issuer
  is present in the trust-registry recognition graph, and the
  minted session TTL is clamped to the earliest expiry across
  the chain. No caching: every refresh re-runs the full check.
- `/v1/health/diagnostics` surfaces the registry health,
  sync-queue depth, last success/failure, and policy hashes so
  oncall can see the lag without grepping telemetry.

Out of scope (deferred to Phase 4+):

- VRC issuance, custom endorsement, `relationships.rego` —
  Phase 4.
- Personhood `assert` / `revoke` endpoints — Phase 4 (the
  deny-all stub already ships).
- Public website + admin UX — Phase 5.
- DIDComm transport for trust-registry sync (Phase 3 is HTTP
  only).
- `did:webvh` rotation (M2.15.2) — ships as a parallel
  follow-up.
- Sealed-transfer of VMC + VEC to applicant DIDs — separate
  follow-up.

## Scope (per spec §16, Phase 3 row)

### In scope

- **Trust-registry HTTP client** — idempotent issuer-profile
  publish on boot; retries on transient failures; degrades
  `registry_status` to `"degraded"` after configurable
  failure window.
- **`registry_records` keyspace** — local mirror of what the
  registry currently knows about each member.
- **`sync_queue` keyspace** — pending + in-flight + failed
  sync jobs.
- **`MembershipSyncer` tokio task** — audit-log-tail driven;
  exponential backoff; boot-time replay; visible-failure
  surface via `registry_status`.
- **Three-disposition reconciliation** — `Purge` / `Tombstone`
  / `Historical` per spec §8.2; envelope sourced from
  `registry.rego` (default policy already in place).
- **RTBF override** — member-initiated `Purge` bypasses
  `min_disposition`; logged as
  `RegistryRecordPolicyOverride { reason: "rtbf" }` with
  HMAC-hashed identifier (§11.1).
- **RTBF batching** — `registry.rtbf_batch_window_hours`
  (default 24); restart-resilient.
- **Visible-failure surface** — `registry_status` field on
  `GET /v1/community/profile` + new
  `/v1/health/diagnostics` admin endpoint.
- **Cross-community recognition** — `POST
  /v1/auth/recognise` accepts a foreign VEC, runs the
  session-mint hardening invariants, and mints a local
  session with clamped TTL.
- **Audit variants**: `RegistryRecordPolicyOverride`,
  `RegistrySyncSucceeded`, `RegistrySyncFailed`,
  `CrossCommunitySessionMinted`.
- **Trust Task drafts** + `spec.md` + `schema.json` +
  `index.json` entries for every new endpoint.

### Out of scope

- Trust-registry **resolution** of arbitrary third-party
  DIDs beyond the recognition graph — Phase 3 only needs
  membership / non-membership of the foreign issuer.
- Recognition graph **management** endpoints (operator
  surfaces for editing which peers we recognise) — Phase 5
  admin UX.
- DIDComm sync transport — Phase 3 sticks to HTTP.
- Trust-registry **subscription** / push notifications —
  Phase 3 is poll/publish only.
- Member-initiated registry inspection
  (`/v1/community/registry`) — admin UX surface, Phase 5.

## Pre-implementation design decisions

Load-bearing. Defaults below; flag dissent before any code
lands.

### D1 — Trust-registry client shape

Spec §8.1 references `affinidi-trust-registry-rs`. As of
the planning window, that crate **is not published to
crates.io** (only `affinidi-trust-lists` is). Three options:

(a) **Git dependency** on the upstream GitHub repo. Fast
    to wire; pins the workspace to a moving target;
    cargo-audit can't reach a non-crates.io source.

(b) **In-tree minimal client** under
    `vtc-service/src/registry/client.rs`. Implements the
    publish + reconcile HTTP shapes the spec needs and
    nothing else. Replaceable when the upstream crate
    publishes.

(c) **Vendor** the upstream crate into the workspace
    `vendor/` directory. Heaviest option; keeps cargo-audit
    clean but doubles the workspace footprint.

**Default (per user decision): (a) — git dependency.**
Pinned to a specific commit so the workspace doesn't ride
`main`. Path:

```toml
[workspace.dependencies]
affinidi-trust-registry-rs = { git = "https://github.com/affinidi/affinidi-trust-registry-rs", rev = "<commit-sha>" }
```

Reasoning: the upstream crate already encodes the wire
shape decisions we'd otherwise have to re-litigate
ourselves; landing the real thing now means M3.5's
reconciliation tests exercise the actual HTTP surface peer
communities will use. When the crate publishes to crates.io
we move the dep up to the workspace `[workspace.dependencies]`
crates.io entry — same shape, different source.

**Mitigations for the git-dep downsides**:
- Pin to a `rev = "<sha>"`, never `branch` — the workspace
  shouldn't ride `main` upstream.
- Wrap the upstream client behind a `TrustRegistryClient`
  trait in `vtc-service/src/registry/client.rs` so the swap
  to crates.io is mechanical and the tests can substitute a
  `MockRegistryClient`.
- Lock-file commits travel with every rev bump so
  reviewers see the upstream surface change in the diff.
- Document the rev + the upstream commit message in
  `phase-3-plan.md` outcomes when M3.13 lands.

**Risk persists** that the upstream wire shape changes
between our pin and the eventual crates.io release. The
trait wrapper absorbs the change at swap time; tests
re-pin against the new shape.

### D2 — `SyncJob` row shape

Each registry-bound mutation lands as a row in
`sync_queue:<job_id>`. Proposed shape:

```rust
pub struct SyncJob {
    pub id: Uuid,
    pub kind: SyncJobKind,        // PublishMember | UpdateMember | DeleteMember
    pub member_did_hash: [u8;32], // HMAC-hashed actor (§11.1)
    pub member_did: String,       // plaintext — needed for the HTTP call
    pub disposition: Option<Disposition>, // set on Delete jobs
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    pub last_attempted_at: Option<DateTime<Utc>>,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub state: SyncJobState,      // Pending | InFlight | Complete | Failed
}
```

**Plaintext DID retention rationale**: registry calls need
the unhashed DID. The `member_did_hash` field exists for the
audit envelope's actor field, not for storage; the row is
deleted on success and ages out via the retention sweeper
on `Failed`.

Retry schedule: exponential backoff with jitter, capped at
1 hour between attempts:
`next_attempt = now + min(2^attempts seconds + jitter, 3600)`.

After `attempts > 16` (~ 18 hours of retries), the job
flips to `Failed` and surfaces in
`/v1/health/diagnostics`. Operator can manually retry or
clear.

### D3 — Audit-log-tail subscription

Spec §8.3 says the syncer is "subscribed to MemberAdded,
MemberRemoved, RoleChanged". Two implementation paths:

(a) **In-process channel** — emitters push to a
    `tokio::sync::mpsc::Sender<AuditEnvelope>` cloned from
    `AppState`. Lowest latency. Survives restarts because
    boot replays the audit-log tail.

(b) **Audit-log tail polling** — the syncer task polls the
    `audit:*` keyspace for new envelopes since its
    last-seen timestamp. No emitter changes. Slightly
    higher latency (polling interval) but lossless across
    syncer restarts.

**Proposed default: (b) — polling.** No emitter changes
means the existing `MemberAdded` + `MemberRemoved` +
`RoleChanged` call sites stay untouched. Poll interval
defaults to 5 seconds (configurable via
`registry.audit_poll_interval_seconds`). Boot-time replay
walks `audit:*` from a per-syncer cursor (stored in a new
`sync_cursor` keyspace).

Latency cost: a member removal takes up to 5s + the next
registry HTTP call to disappear from the registry. Within
the spec's "≥ 1 hour behind" degraded-flag threshold by
several orders of magnitude.

### D4 — RTBF batching trigger

Spec §8.2: "RTBF-triggered registry mutations are coalesced
into a daily batch". Three knobs:

(a) Boot-time only (drain queue at startup).

(b) Periodic timer (`tokio::time::interval`) — runs the
    batch every `rtbf_batch_window_hours`.

(c) Boot + periodic + manual-flush admin endpoint.

**Proposed default: (b) — periodic timer.** Boot-time
flush isn't load-bearing because RTBF jobs land in the
`sync_queue` with `next_attempt_at` set to the next batch
window; the syncer skips them until the window opens. The
periodic timer fires once per `rtbf_batch_window_hours`
(default 24h) + RTBF jobs in the queue are eligible for
dispatch when `now >= next_attempt_at`.

Manual flush (admin endpoint) is a Phase 5 admin UX
surface — not in Phase 3.

### D5 — Recognition cache stance

Spec §8.4 is emphatic: "Recognition is **not cached**;
every session mint re-runs the full policy + StatusList +
trust-registry check." This is intentional — a peer
community removed mid-session must not retain access on
refresh.

**Proposed default: ship the no-cache invariant verbatim.**
Per-mint cost (measured against a localhost mock):

- DID resolution of the foreign issuer: cached by the
  resolver-cache-sdk (existing). ~5ms steady state.
- HTTP fetch of the foreign issuer's status list: ~50ms +
  network. **Single biggest cost.**
- HTTP fetch of the trust-registry recognition graph:
  ~20ms + network.
- `cross_community_roles.rego` evaluation: <1ms (regorus
  per-call recompile budget).
- VEC + VMC proof verification: ~5ms.

Worst-case session mint: ~150ms. Within the spec's
auth-endpoint budget but worth surfacing in
`/v1/health/diagnostics` so operators can see the cost.

A future enhancement could add a **short-window cache**
(e.g. 60s) — the spec's "no caching" wording is about
*session-lifetime* caching, not within-request memoisation.
That's an enhancement for a future phase, not Phase 3.

### D6 — Failure-mode semantics

| Scenario | Spec'd behaviour | Implementation choice |
|---|---|---|
| Registry unreachable at boot | Publish failure non-fatal; `registry_status: "degraded"` | Best-effort publish; log warning; syncer task starts regardless and retries later. |
| Registry unreachable steady-state | Sync queue grows; `registry_status` flips at 1h-behind | `MembershipSyncer` retries with backoff; once oldest pending exceeds threshold, profile + diagnostics flip. |
| Failed `Purge` job | Escalated warning (silent privacy regression) | After 3 consecutive failures on a Purge, audit envelope `RegistrySyncFailed { kind: "purge_escalated" }` fires; admin UX status ping. |
| Foreign issuer unreachable at session mint | Spec implies deny | Return `503 Service Unavailable`; do NOT mint a session; do not cache the failure. |
| Foreign VEC's status list unreachable | Spec implies deny | Same as above. |
| Foreign VEC verify failure | Deny | `403 Forbidden` with audit `CrossCommunitySessionMinted { outcome: "denied", reason: "vec_verify_failed" }`. |

### D7 — `registry_records` keyspace shape

Local mirror of what the registry knows about each member.
Used by the reconciler to detect divergence (e.g. a registry
record we don't know about; a local member without a
registry record).

```rust
pub struct RegistryRecord {
    pub member_did: String,
    pub status: RegistryStatus,   // Active | Departed
    pub active_from: DateTime<Utc>,
    pub active_to: Option<DateTime<Utc>>,
    pub last_synced_at: DateTime<Utc>,
}
```

Storage key: `registry_records:<member_did>`. Mirrors the
spec §5.7 shape.

### D8 — Audit envelope names

Spec §8.2 names `RegistryRecordPolicyOverride`. Additional
variants Phase 3 needs:

| Variant | When emitted |
|---|---|
| `RegistryRecordPolicyOverride` | RTBF Purge bypasses `min_disposition`. |
| `RegistrySyncSucceeded` | `SyncJob` completes against the registry. |
| `RegistrySyncFailed` | `SyncJob` flips to `Failed` state. |
| `CrossCommunitySessionMinted` | `/v1/auth/recognise` mints a session (success **and** denial — `outcome: "minted" \| "denied"`). |
| `RegistryStatusChanged` | `registry_status` flips between `Active` ↔ `Degraded`. Helpful for SIEM hooks. |

All five share the same data-struct discipline as Phase 2's
variants: `camelCase` wire, `Option`s with
`skip_serializing_if`, round-trip tests.

### D9 — Foreign-issuer DID resolution

Cross-community recognition needs to resolve the foreign
issuer's DID document so we can:
1. Find its public key (for VEC + VMC proof verification).
2. Find its `#vtc-status-list` service entry (for the
   live StatusList fetch).

The existing `affinidi-did-resolver-cache-sdk` (already a
workspace dep) handles `did:webvh` + `did:key`. **Proposed
default: reuse the existing resolver.** Cache it on
`AppState` as `did_resolver` (already there).

### D10 — Trust Task IDs

Following the workspace-wide pattern:

| Operation | Trust Task ID |
|---|---|
| Cross-community session mint | `…/auth/recognise/1.0` |
| Health diagnostics | `…/health/diagnostics/1.0` |
| Registry status (community-profile surface) | (extends existing `community/profile/manage/1.0`) |

Two new Trust Task entries; the registry-status field
piggybacks on the existing community-profile surface.

## Dependency graph

```
M3.1 Trust-registry client + keyspaces
  │
  ▼
M3.2 Publish-on-boot + registry_status surface
  │
  │  [parallel branch: M3.9 cross-community starts here]
  ▼
M3.3 Audit-log-tail subscription + sync_queue helpers
  │
  ▼
M3.4 MembershipSyncer task + exponential backoff
  │
  ▼
M3.5 Three-disposition reconciliation (Purge / Tombstone /
     Historical) + registry.rego envelope consumption
  │
  ▼
M3.6 RTBF override + RegistryRecordPolicyOverride audit
M3.7 RTBF batching task
  │
  ▼
M3.8 GET /v1/health/diagnostics endpoint
  │
  │  [parallel since M3.2]
M3.9 Foreign-credential verifier (StatusList check +
     registry membership check + proof verify)
  │
  ▼
M3.10 POST /v1/auth/recognise — cross-community session mint
  │
  ▼
M3.11 Audit variants snapshot tests
M3.12 Trust Task drafts + index
M3.13 Phase 3 outcomes + spec amendments
M3.14 Phase 3 gate
```

Critical paths:
- **Reconciliation track** (M3.1 → M3.2 → M3.3 → M3.4 →
  M3.5 → M3.6 → M3.7 → M3.8). Sequential.
- **Recognition track** (M3.9 → M3.10). Sequential, but
  parallel with reconciliation from M3.2 onwards.
- **Closeout** (M3.11–M3.14) depends on both tracks.

## Parallelisation strategy

Within a milestone: vertical slice — each endpoint ships
with its Trust Task files + integration tests + audit
emission, not in batches.

PR slicing — proposed:

1. **PR-1**: M3.1 + M3.2 (trust-registry client + publish-
   on-boot + `registry_status` surface).
2. **PR-2**: M3.3 + M3.4 + M3.5 (`MembershipSyncer` + three-
   disposition reconciliation).
3. **PR-3**: M3.6 + M3.7 + M3.8 (RTBF override + batching +
   `/v1/health/diagnostics`).
4. **PR-4**: M3.9 + M3.10 (foreign-credential verifier +
   cross-community session mint).
5. **PR-5**: M3.11 + M3.12 + M3.13 + M3.14 (audit snapshots
   + Trust Tasks + outcomes + gate).

5 PRs across 14 milestones. Tighter than Phase 2 (6 PRs /
19 milestones) — Phase 3 has fewer independent surfaces.

## Checkpoints

- **After PR-1**: VTC publishes its issuer profile on boot
  + the community-profile response carries
  `registry_status`. No sync happens yet; existing surfaces
  unchanged.
- **After PR-2**: `MemberAdded` / `MemberRemoved` /
  `RoleChanged` events drive registry sync. Three
  dispositions resolve. Operators can see the queue depth
  in logs.
- **After PR-3**: RTBF + diagnostics live. Member-initiated
  Purge correctly batches; admins can see lag without
  grepping. **Reconciliation gate met here.**
- **After PR-4**: Foreign VEC can mint a local session
  (when policy + registry allow). **Recognition gate met
  here.**
- **After PR-5**: workspace gate green. Phase 3 closes.

## Risks

- **R1: upstream `affinidi-trust-registry-rs` ships from a
  git rev, not crates.io.** Pinned to a specific commit
  per D1, but cargo-audit can't reach a git source and the
  rev will eventually drift. Mitigation: trait-wrapped
  client (D1); rev bumps go through PR review with the
  Cargo.lock diff visible. When the crate publishes,
  switch to the crates.io entry under the same trait.
- **R2: audit-log-tail polling latency drift.** If the
  poll interval is too coarse, a high-volume community
  could fall behind. Mitigation: configurable interval +
  visible-failure surface flips at the 1h threshold so
  operators see it before users do.
- **R3: RTBF batching + emergency-removal interaction.**
  An RTBF Purge is held until the next batch; an operator
  who needs immediate registry removal can't currently
  force it. Mitigation: Phase 5's admin UX adds a manual-
  flush surface; Phase 3 documents the 24h max-latency
  ceiling clearly in the operator docs.
- **R4: cross-community session-mint latency.** ~150ms
  worst-case per mint (D5). Mitigation: surface in
  `/v1/health/diagnostics`; future short-window cache if
  operators flag it.
- **R5: registry recovery semantics.** A registry that comes
  back online after a long outage may have stale records
  the syncer's queue doesn't cover (e.g. operator-side
  drift). Mitigation: Phase 3 ships a passive reconcile;
  active drift detection is a Phase 5 admin UX surface.
- **R6: foreign-issuer DID resolution failures during
  recognition.** Networks fail. Mitigation: D6's
  fail-closed semantics — 503 on resolver failure, never
  cache the negative.

## Definition of done — Phase 3

After M3.14:

- `cargo build/clippy/fmt/test --workspace` clean.
- 2+ new Trust Tasks in `Draft` status with matching
  `spec.md` + `schema.json` files.
- Every Phase 3 milestone marked `[x]` in
  `phase-3-todo.md`.
- Memory entry `project_vtc_mvp.md` updated with the as-
  shipped outcomes for D1–D10.
- Integration tests cover the end-to-end registry flow:
  daemon boots → publishes profile → registry_status
  `"active"` → member joins → registry record appears →
  member removed (RTBF Purge) → batched delete fires →
  registry record absent → `registry_status` stays
  `"active"` throughout.
- Integration tests cover cross-community recognition:
  foreign VEC with valid chain → session minted →
  foreign issuer dropped from registry → refresh denied.

Phase 4 (VRC + personhood + custom endorsement) can start
after Phase 3's gate merges.

## Spec amendment surface

Recording up front so they're not surprises mid-
implementation:

- **§8.1**: confirm the in-tree client choice in D1; flag
  in spec if we adopt option (b).
- **§8.4**: confirm the worst-case ~150ms session-mint
  latency in the documented operator surface. Spec text
  doesn't quote a number today.
- **§14.2**: extend the "Remote-dependency breakers"
  section (M2.16 amended this) to spell out the trust-
  registry endpoint as a covered dependency.
- **§14.3**: add registry health + sync depth fields to the
  `/v1/health/diagnostics` documentation if not already
  present.

Any decision that drifts from the default during
implementation should be recorded in `phase-3-plan.md`
under a "Phase 3 outcomes" header (mirror of Phase 1 + 2's
pattern).

## Phase 3 outcomes

Recorded at M3.13 close-out. Each row links a pre-impl
decision (D1–D10) or risk (R1–R6) to the as-shipped reality.

### D1 — Trust-registry client shape

**As shipped with deviation**: the proposed git-dep on
`affinidi-trust-registry-rs` turned out to mean depending on
the *server* crate, which pulls in an `affinidi-tdk = "0.4"`
that conflicts with the workspace's `"0.7"`. Resolved
mid-implementation (PR #87 planning) by writing an in-tree
client wrapping the upstream's TRQP v2.0 HTTP surface +
DIDComm admin protocol. The `TrustRegistryClient` trait
keeps both transports opaque so future upstream changes
land in one place.

Follow-up landed post-closeout: `UpstreamRegistryClient::
recognise` now sends a real `POST /recognition` 4-tuple
(`entity_id`, `authority_id`, `action`, `resource`) and
parses `response.recognized`. 404 maps to `Ok(false)`
(clean not-found); 400 → `Permanent`; 5xx / connect-refused
→ existing classify path. End-to-end tests stand up an
in-process axum server. Mock-backed verifier tests in
`recognition::verify::tests` still cover the M3.9 trail
hermetically.

### D2 — `SyncJob` row shape

**As shipped as proposed**: `SyncJob { id, kind, member_did,
disposition?, created_at, attempts, last_attempted_at?,
next_attempt_at, last_error?, state, rtbf_batched }` in
`vtc_service::registry::model`. `state ∈
{Pending, InFlight, Complete, Failed}`. Exponential backoff
capped at 1h (M3.4); `rtbf_batched` flag drives the M3.7
batch-window logic.

### D3 — Audit-log-tail subscription

**As shipped as proposed**: M3.3's `walk()` polls the
`audit:` keyspace from a persisted `sync_cursor` row. The
cursor advances over every envelope (including ignored
variants) so a restart doesn't re-walk. Restart resilience
is the load-bearing property — the audit log IS the event
source of truth, and cursor-driven replay handles every
"daemon crashed mid-flight" case identically.

### D4 — RTBF batching trigger

**As shipped with simplification**: parked-job `next_attempt_at`
is set to `now + rtbf_batch_window_hours` (default 24h) at
walk time. The proposed separate `RtbfBatchTimer` task is
**not needed** — `SyncJob::is_dispatchable(now)` already
checks the field, so the main syncer's tick naturally picks
up parked jobs once their window expires. Configurable via
`registry.rtbf_batch_window_hours`; `0` disables (test
convenience).

### D5 — Recognition cache stance

**As shipped as proposed**: no caching anywhere. Every
`POST /v1/auth/recognise` re-runs the full
verifier (proof + status list + registry recognise +
validity). Cross-community sessions intentionally **don't
refresh** — the standard refresh path doesn't carry the
foreign credentials, so re-issuing without re-verifying
would defeat the "peer community removed mid-session loses
access" invariant. Sessions just expire.

### D6 — Failure-mode semantics

**As shipped as proposed**: fail-closed in M3.9 (every
check failure rejects); fail-open in M3.5's
`publish_on_join` policy evaluation (broken policies sync
rather than swallow membership). Registry unreachability at
mint time maps to `503`, every other recognition failure to
`403`. `RecognitionError::reason_code()` provides stable
discriminators for SIEM filters.

### D7 — `registry_records` keyspace shape

**As shipped as proposed**: `RegistryRecord { member_did,
status, active_from, active_to?, last_synced_at }` mirrors
what the registry has. Updated on successful `SyncJob`
dispatch; deleted on `DeleteMember` success.

### D8 — Audit envelope names

**As shipped as proposed**: five Phase 3 variants —
`RegistryStatusChanged` (M3.2), `RegistrySyncSucceeded` +
`RegistrySyncFailed` (M3.4), `RegistryRecordPolicyOverride`
(M3.6), `CrossCommunitySessionMinted` (M3.10). All five
have round-trip + discriminator-table coverage in
`vti-common/src/audit/event.rs`.

### D9 — Foreign-issuer DID resolution

**As shipped as proposed**: production wires
`DidResolverKeyResolver` over `DIDCacheClient` (reuses
existing AppState resolver). Tests inject a stub via the
`ForeignIssuerKeyResolver` trait — keeps the unit-test
matrix hermetic.

### D10 — Trust Task IDs

**As shipped as proposed**: `health/diagnostics/1.0` (M3.8)
+ `auth/recognise/1.0` (M3.10). Both `Draft` in
`index.json`; spec.md + schema.json on disk.

### R1 — Upstream git-dep drift

**Realised** — see D1. Pinned the trait abstraction;
production HTTP wiring deferred behind a clear marker until
the wire shape is pinned. cargo-audit on the trait is moot
because the implementation is in-tree.

### R2 — Tail-poll latency drift

**Not realised yet**. Default 5s tick; the 1h
visible-degraded threshold isn't currently surfaced via
`oldest_pending_age_seconds`. The diagnostics endpoint
exposes the metric; the flip-to-degraded threshold is left
to operator alerting (their SIEM picks 1h or whatever they
want). Phase 5 admin UX may bake it in.

### R3 — RTBF / emergency-removal interaction

**Not realised**. Phase 3 documents the 24h ceiling; admin
manual-flush deferred to Phase 5 admin UX as planned.

### R4 — Recognise latency

**Not measured at production scale.** No live `recognise`
HTTP call has been issued (see D1). Mock-backed
microbenchmark unmeasured. Follow-up after wire format pins.

### R5 — Registry recovery semantics

**As planned**: passive reconcile via the syncer's
restart-replay path. No active drift detection. Phase 5
admin UX surface deferred.

### R6 — DID resolution failures during recognition

**As shipped**: `RecognitionError::IssuerKeyUnresolved`
fails closed; route maps to `403` (caller's foreign issuer
DID is the problem from the VTC's perspective, even when
the underlying cause is network). No negative cache.

### Spec amendments applied at M3.13

- **§8.1**: in-tree TRQP client documented; `recognise`
  HTTP wire-shape deferral noted.
- **§8.4**: cross-community no-refresh path documented;
  no caching anywhere; session TTL clamp formula spelled
  out.
- **§14.2**: trust-registry endpoint added to the remote-
  dependency-breaker section (the M2.16 surface already
  carried the abstraction; §14.2 now names registry
  publish + recognise explicitly).
- **§14.3**: `/v1/health/diagnostics` payload now matches
  the as-shipped response (`registry_status`, `queue_depth`,
  `rtbf_batched_count`, `failed_count`,
  `oldest_pending_age_seconds`, + last-success/failure/
  error fields).
