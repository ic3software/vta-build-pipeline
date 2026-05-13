# Todo: VTC MVP — Phase 3

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Spec: `docs/05-design-notes/vtc-mvp.md` §§5.7, 6.1, 8, 11.1,
13, 14.3.
Plan: `tasks/vtc-mvp/phase-3-plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR —
soft gate per spec §9.4. Trust Task IDs per plan §D10.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy -- -D warnings`,
`cargo test`.

---

## M3.1 — Trust-registry client + keyspaces

### `[x]` M3.1.1 — `vtc_service::registry` skeleton

- **Acceptance**
  - Workspace dep added:
    `affinidi-trust-registry-rs = { git =
    "https://github.com/affinidi/affinidi-trust-registry-rs",
    rev = "<pinned-sha>" }`. Rev recorded in
    `phase-3-plan.md` outcomes at M3.13.
  - New module `vtc_service::registry` with:
    - `TrustRegistryClient` trait — async `publish_profile`,
      `publish_record`, `delete_record`. Trait wraps the
      upstream API so the future crates.io swap is
      mechanical (plan §D1).
    - `UpstreamRegistryClient` — adapter that wires the
      git-dep crate's client into the trait.
    - `MockRegistryClient` — in-memory + counts-each-call
      shim for tests.
  - `registry_records:<member_did>` keyspace + CRUD helpers
    (`get_record`, `store_record`, `delete_record`,
    `list_records`).
  - `sync_queue:<job_id>` keyspace + `SyncJob` model
    (plan §D2) + CRUD helpers.
  - `sync_cursor:` keyspace (singleton row) tracking the
    audit-log tail's last-seen timestamp per plan §D3.
  - Three new keyspace handles on `AppState`.
- **Verify** 8 unit tests:
  - Round-trip `RegistryRecord` (plan §D7 shape).
  - Round-trip `SyncJob` covering each state +
    `next_attempt_at` math.
  - Exponential-backoff schedule caps at 1h.
  - Mock client tracks call counts.
- **Files**
  - `Cargo.toml` (workspace `affinidi-trust-registry-rs`
    git-dep)
  - `vtc-service/Cargo.toml` (workspace dep)
  - `vtc-service/src/registry/mod.rs` (new)
  - `vtc-service/src/registry/client.rs` (new — trait +
    upstream adapter + mock)
  - `vtc-service/src/registry/model.rs` (new)
  - `vtc-service/src/registry/storage.rs` (new)
  - `vtc-service/src/server.rs` (3 new keyspace fields)
  - `vtc-service/src/lib.rs`
- **Deps**: none
- **Pre-impl decision**: **D1** (client shape — git dep),
  **D2** (SyncJob shape), **D7** (RegistryRecord shape).

---

## M3.2 — Publish-on-boot + `registry_status` surface

### `[x]` M3.2.1 — Boot-time idempotent profile publish

- **Acceptance**
  - `server::run` calls
    `registry_client.publish_profile(...)` after policies
    + status lists are seeded. Publish failure is
    non-fatal — daemon proceeds with `registry_status:
    "degraded"`.
  - Per-publish telemetry event
    (`registry_publish_succeeded` / `_failed`) emitted via
    the workspace's `TelemetrySink`.
  - `RegistryStatusChanged` audit envelope fires when the
    status flips between `"active"` ↔ `"degraded"` (plan
    §D8).
  - `RegistryStatus` field on `AppState` (`Arc<RwLock<...>>`
    so the syncer + the diagnostics endpoint can read it
    live).
- **Verify** Integration test against `MockRegistryClient`:
  successful publish → status `"active"`;
  intentional-failure mock → status `"degraded"` +
  daemon continues.
- **Files**
  - `vtc-service/src/registry/publisher.rs` (new)
  - `vtc-service/src/server.rs` (boot call + AppState
    field)
  - `vti-common/src/audit/event.rs`
    (`RegistryStatusChanged` variant)
- **Deps**: M3.1.1
- **Pre-impl decision**: **D6** (failure-mode semantics).

### `[x]` M3.2.2 — `registry_status` on community profile

- **Acceptance**
  - `CommunityProfile` response (`GET
    /v1/community/profile`) gains a `registryStatus:
    "active" | "degraded"` field, read live from
    AppState.
  - Existing `community/profile/manage/1.0` Trust Task
    schema extended (additive — no version bump).
  - Round-trip test confirms the field surfaces.
- **Files**
  - `vtc-service/src/community/profile.rs`
  - `vtc-service/src/routes/community/profile.rs`
  - `trust-tasks/community/profile/manage/1.0/schema.json`
- **Deps**: M3.2.1

---

## M3.3 — Audit-log-tail subscription + sync_queue helpers

### `[x]` M3.3.1 — Audit-log walker

- **Acceptance**
  - `vtc_service::registry::tail::AuditTailWalker` walks
    `audit:*` from the cursor stored in `sync_cursor:`,
    yields each `MemberAdded` / `MemberRemoved` /
    `RoleChanged` envelope, updates the cursor on success.
  - Cursor is RFC3339 timestamp (matches
    `envelope_storage_key`'s format).
  - Helper `enqueue_sync_job(ks, envelope, kind)` converts
    an envelope into a fresh `SyncJob` (state =
    `Pending`).
  - 5 unit tests cover: cursor advances; restart picks up
    where the prior run left off; only the three relevant
    audit variants enqueue; idempotency (re-walking the
    same envelope doesn't duplicate).
- **Files**
  - `vtc-service/src/registry/tail.rs` (new)
  - `vtc-service/src/registry/mod.rs`
- **Deps**: M3.1.1
- **Pre-impl decision**: **D3** (polling vs in-process
  channel).

---

## M3.4 — `MembershipSyncer` task

### `[x]` M3.4.1 — Tokio task with exponential backoff

- **Acceptance**
  - `vtc_service::registry::syncer::MembershipSyncer`
    spawns a tokio task on a new thread (mirrors
    storage/REST/DIDComm thread layout).
  - Tick loop: (1) walk audit tail to enqueue new jobs,
    (2) dispatch eligible `Pending` jobs (where
    `now >= next_attempt_at`), (3) per dispatch:
    `state = InFlight` → call client → on success
    `state = Complete` + delete the row + audit
    `RegistrySyncSucceeded`, on failure bump
    `attempts` + recompute `next_attempt_at` per
    backoff schedule; after `attempts > 16` flip to
    `Failed` + audit `RegistrySyncFailed`.
  - Graceful shutdown handle (same pattern REST/DIDComm
    threads use).
  - 6 unit tests: happy path; failure bumps backoff;
    Failed-state crossover at attempts threshold; In-flight
    crash recovery (boot finds `InFlight` rows + flips
    back to `Pending`).
- **Files**
  - `vtc-service/src/registry/syncer.rs` (new)
  - `vtc-service/src/server.rs` (spawn the syncer thread)
- **Deps**: M3.3.1
- **Pre-impl decision**: **D2** (retry schedule),
  **D8** (audit envelope names).

---

## M3.5 — Three-disposition reconciliation

### `[x]` M3.5.1 — Wire `registry.rego` into the syncer

- **Acceptance**
  - When dispatching a `DeleteMember` job, the syncer
    evaluates the active `registry.rego` to fetch the
    envelope (`publish_on_join`, `default_departure`,
    `departure_options`, `min_disposition`).
  - Member's `departure_preference` is clamped within
    the envelope; result drives:
    - `Purge` → `delete_record` HTTP call.
    - `Tombstone` → `publish_record(..., status:
      Departed, no date range)`.
    - `Historical` → `publish_record(..., status:
      Departed, dates populated)`.
  - The `MemberRemoved.disposition` field carries the
    resolved disposition (already set by Phase 2 — this
    milestone just plumbs the syncer to read it).
  - `JoinRequestApproved` → publish-on-join only when the
    policy says so.
  - Local `registry_records:<did>` row is updated to mirror
    the call's outcome.
- **Verify** Integration test: each disposition produces
  the expected `MockRegistryClient` call shape; refusing
  policy short-circuits with `Complete` + no HTTP call.
- **Files**
  - `vtc-service/src/registry/syncer.rs`
  - `vtc-service/src/registry/dispositions.rs` (new)
- **Deps**: M3.4.1

---

## M3.6 — RTBF override

### `[x]` M3.6.1 — Member-initiated Purge bypasses `min_disposition`

- **Acceptance**
  - When a `MemberRemoved` audit envelope has
    `actor_did == target_did` AND `disposition == "purge"`
    AND the policy's `min_disposition` resolves to
    something stricter than `Purge`, the syncer:
    - Honours the Purge request anyway (RTBF — spec §8.2).
    - Emits `RegistryRecordPolicyOverride { reason: "rtbf",
      member_did_hash, attempted_disposition,
      effective_disposition }` audit envelope. Actor field
      is the HMAC-hashed identifier per §11.1.
  - Non-self Purges (admin force-purge) do **not** trigger
    the override — they go through the normal envelope
    clamp.
- **Verify** Unit test on the override decision; integration
  test with a `registry.rego` that sets `min_disposition =
  "tombstone"` confirms a self-Purge still calls
  `delete_record`.
- **Files**
  - `vtc-service/src/registry/dispositions.rs`
  - `vti-common/src/audit/event.rs`
    (`RegistryRecordPolicyOverride` variant)
- **Deps**: M3.5.1
- **Pre-impl decision**: **D8** (override variant shape).

---

## M3.7 — RTBF batching

### `[x]` M3.7.1 — Daily coalesced batch

- **Acceptance**
  - RTBF-flagged `SyncJob` rows are enqueued with
    `next_attempt_at = now + rtbf_batch_window_hours`
    (default 24).
  - A `RtbfBatchTimer` tokio task (separate from the main
    syncer) ticks every
    `rtbf_batch_window_hours`; when it fires, it bumps
    eligible RTBF jobs to `next_attempt_at = now` so the
    main syncer picks them up.
  - Restart-resilient: the timer's interval is wall-clock,
    so a daemon restart inside the window doesn't reset the
    countdown — eligible-vs-not is computed off the
    `next_attempt_at` field, not the timer state.
  - Configurable via `registry.rtbf_batch_window_hours`
    (default 24, clamped to `1..=168`).
- **Verify** Integration test (clock-injected): RTBF job
  enqueued at t=0 with 1h window; at t=30min only
  non-RTBF jobs dispatch; at t=1h the RTBF job dispatches.
- **Files**
  - `vtc-service/src/registry/rtbf.rs` (new)
  - `vtc-service/src/server.rs` (spawn the RTBF timer)
  - `vtc-service/src/config.rs` (new
    `registry.rtbf_batch_window_hours` field)
- **Deps**: M3.6.1
- **Pre-impl decision**: **D4** (timer-only trigger).

---

## M3.8 — `GET /v1/health/diagnostics`

### `[x]` M3.8.1 — Admin diagnostics endpoint

- **Acceptance**
  - `AdminAuth`. Response shape:
    ```
    {
      "registryStatus": "active" | "degraded",
      "registryLastSuccessAt": "<rfc3339>" | null,
      "registryLastFailureAt": "<rfc3339>" | null,
      "syncQueueDepth": <integer>,
      "syncOldestPendingAge": <seconds> | null,
      "syncFailedJobs": <integer>,
      "statusListOccupancy": { "revocation": 0.12, "suspension": 0.0 },
      "activePolicies": [ { "purpose": "join", "id": "...", "sha256": "..." }, ... ],
      "telemetryRingBuffer": [ ...recent events... ]
    }
    ```
  - `syncOldestPendingAge` is the load-bearing metric for
    "≥ 1h behind" — when it exceeds the threshold the
    `registryStatus` flips to `"degraded"`.
  - Trust Task `health/diagnostics/1.0` ships.
- **Verify** Integration test: seed the queue with a 2h-old
  pending row + assert `registryStatus = "degraded"` +
  `syncOldestPendingAge > 7200`.
- **Files**
  - `vtc-service/src/routes/health.rs` (new `diagnostics`
    handler)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/health/diagnostics/1.0/{spec.md,schema.json}`
- **Deps**: M3.4.1, M3.2.1

---

## M3.9 — Foreign-credential verifier

### `[x]` M3.9.1 — Verify foreign VEC + StatusList + registry membership

- **Acceptance**
  - `vtc_service::recognition::verify_foreign_vec(vec, vmc,
    registry_client, did_resolver)` returns
    `Result<VerifiedForeignCredential, RecognitionError>`.
  - Checks (in order, fail-closed):
    1. VEC + VMC proofs verify against the resolved foreign
       issuer's public key.
    2. Live StatusList fetch for each credential —
       revocation bit must be `0`.
    3. Foreign issuer DID must be present in the trust-
       registry recognition graph (HTTP call).
    4. Both VEC + VMC `validUntil` must be in the future.
  - The returned `VerifiedForeignCredential` carries the
    parsed role claim + the earliest expiry across the
    chain (for TTL clamping).
- **Verify** 8 unit + integration tests covering each of
  the four failure modes + the happy path + invalid
  `validFrom`/`validUntil`.
- **Files**
  - `vtc-service/src/recognition/mod.rs` (new)
  - `vtc-service/src/recognition/verify.rs` (new)
- **Deps**: M3.1.1
- **Pre-impl decision**: **D5** (no-cache), **D6**
  (fail-closed), **D9** (resolver reuse).

---

## M3.10 — `POST /v1/auth/recognise` — cross-community session

### `[x]` M3.10.1 — Cross-community session mint

- **Acceptance**
  - `POST /v1/auth/recognise` accepts a foreign VEC + VMC
    in the body, runs M3.9.1's verifier, evaluates the
    active `cross_community_roles.rego` to map the
    foreign role onto a local role, then mints a session
    JWT with TTL = `min(jwt_default, vec.validUntil,
    vmc.validUntil)`.
  - Deny path: `403 Forbidden` with
    `CrossCommunitySessionMinted { outcome: "denied",
    reason }` audit envelope.
  - Allow path: `200 OK` with the session token +
    `CrossCommunitySessionMinted { outcome: "minted",
    foreign_issuer_did, mapped_role, ttl_seconds }`
    audit.
  - **No caching** — every refresh path
    (`POST /v1/auth/refresh`) re-runs the full check.
    This means cross-community sessions can't use the
    standard refresh-token path; the session expires when
    its clamped TTL expires.
  - Trust Task `auth/recognise/1.0` ships.
- **Verify** Integration test: foreign issuer in registry
  + valid VEC + permissive policy → 200; foreign issuer
  removed from registry between mint and refresh →
  refresh denied; clamped TTL is min of three.
- **Files**
  - `vtc-service/src/routes/auth.rs` (extend or new module)
  - `vti-common/src/audit/event.rs`
    (`CrossCommunitySessionMinted` variant)
  - `trust-tasks/auth/recognise/1.0/{spec.md,schema.json}`
- **Deps**: M3.9.1
- **Pre-impl decision**: **D5** (no-cache), **D8** (audit
  variant).

---

## M3.11 — Audit variants snapshot tests

### `[ ]` M3.11.1 — Round-trip + discriminator coverage

- **Acceptance**
  - The five Phase 3 audit variants
    (`RegistryRecordPolicyOverride`, `RegistrySyncSucceeded`,
    `RegistrySyncFailed`, `CrossCommunitySessionMinted`,
    `RegistryStatusChanged`) each gain a round-trip
    snapshot test in `vti-common/src/audit/event.rs`.
  - All five added to `variant_discriminator_strings`.
- **Verify** `cargo test -p vti-common audit::` passes.
- **Files**
  - `vti-common/src/audit/event.rs`
- **Deps**: M3.10.1 (last endpoint to land its variant)

---

## M3.12 — Trust Task drafts + index

### `[ ]` M3.12.1 — On-disk + index entries

- **Acceptance**
  - `trust-tasks/health/diagnostics/1.0/{spec.md,schema.json}`
    present.
  - `trust-tasks/auth/recognise/1.0/{spec.md,schema.json}`
    present.
  - `community/profile/manage/1.0/schema.json` extended
    with the new `registryStatus` field (additive — no
    version bump).
  - `trust-tasks/index.json` carries both new entries.
- **Files**
  - `trust-tasks/health/diagnostics/1.0/*`
  - `trust-tasks/auth/recognise/1.0/*`
  - `trust-tasks/community/profile/manage/1.0/schema.json`
  - `trust-tasks/index.json`
- **Deps**: M3.8.1, M3.10.1

---

## M3.13 — Phase 3 outcomes + spec amendments

### `[ ]` M3.13.1 — Document the as-shipped reality

- **Acceptance**
  - `tasks/vtc-mvp/phase-3-plan.md` gains a "Phase 3
    outcomes" header recording the as-shipped reality for
    D1–D10 + any deviations.
  - `docs/05-design-notes/vtc-mvp.md` §§8.1 / 8.4 / 14.2 /
    14.3 amended per the planning-time spec-amendment
    surface (see plan).
  - Memory entry `project_vtc_mvp.md` updated.
- **Files**
  - `tasks/vtc-mvp/phase-3-plan.md`
  - `docs/05-design-notes/vtc-mvp.md`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M3.10.1, M3.11.1

---

## M3.14 — Phase 3 gate

### `[ ]` M3.14.1 — Workspace gate green

- **Acceptance** (mirrors M2.19.1)
  - `cargo build --workspace` green.
  - `cargo test --workspace` green.
  - `cargo clippy --workspace --all-targets -- -D warnings`
    clean.
  - `cargo fmt --check` clean.
  - `trust-tasks/index.json` lists every Phase-3 Trust Task
    with matching on-disk files.
  - Memory entry `project_vtc_mvp.md` updated with the as-
    shipped outcomes for D1–D10.
  - Phase-3-todo milestones all flipped to `[x]`.
- **Verify** CI green on the merge commit.
- **Files**
  - `trust-tasks/index.json`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M3.11.1, M3.12.1, M3.13.1

### Checkpoint — Phase 3 gate met

After M3.14.1: a VTC publishes its issuer profile to the
trust registry, reconciles member changes asynchronously,
honours RTBF with daily-batched timing, surfaces health to
admins, and accepts foreign VECs to mint sessions with
strict invariants. Phase 4 (VRC + personhood + custom
endorsement) can start.

---

## Open questions surfaced during planning

Defaults in `phase-3-plan.md` §§D1–D10. Listed here so
they're findable from the todo:

- **D1**: Trust-registry client — **git dependency** on
  upstream (user decision). Pinned to a rev; wrapped in a
  `TrustRegistryClient` trait so the future crates.io
  swap is mechanical.
- **D2**: `SyncJob` shape — id/kind/did/attempts/state
  (proposed). Retry schedule: exponential, capped at 1h,
  Failed at attempts > 16.
- **D3**: Audit-log subscription — polling at 5s
  (proposed). Alternative: in-process channel.
- **D4**: RTBF trigger — periodic timer only (proposed).
- **D5**: Recognition cache — none, per spec verbatim
  (proposed). Worst-case ~150ms per mint.
- **D6**: Failure modes — fail-closed everywhere
  (proposed).
- **D7**: `RegistryRecord` shape mirrors spec §5.7.
- **D8**: Audit variants — 5 new (`RegistryRecordPolicyOverride`,
  `RegistrySyncSucceeded`, `RegistrySyncFailed`,
  `CrossCommunitySessionMinted`, `RegistryStatusChanged`).
- **D9**: Foreign-DID resolution — reuse existing
  `affinidi-did-resolver-cache-sdk`.
- **D10**: Trust Task IDs — `health/diagnostics/1.0` +
  `auth/recognise/1.0`. Plus an additive extension to
  `community/profile/manage/1.0`.
