# Todo: VTC MVP — Phase 1

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Each task lists: **acceptance** (what must be true), **verify** (how
to prove it), **files** (what's touched), **deps** (which task IDs
must land first). Tasks within a milestone that share `deps` can run
in parallel.

Spec: `docs/05-design-notes/vtc-mvp.md` §§5.2–5.5, §10.1–10.4
Plan: `tasks/vtc-mvp/phase-1-plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR — soft
gate per spec §9.4. Trust Task IDs per phase-1-plan §D7.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.

---

## M1.1 — Role enum extension (`vtc-service::acl::VtcRole`)

### `[x]` M1.1.1 — Introduce `VtcRole`

- **Acceptance**
  - New enum `vtc_service::acl::VtcRole { Admin, Moderator, Issuer,
    Member, Custom(String) }`. `Serialize`/`Deserialize` use
    `#[serde(tag = "type", content = "value")]` so custom values
    don't collide with the named variants on the wire.
  - `From<vti_common::acl::Role>` + `TryInto<vti_common::acl::Role>`
    helpers so the existing ACL helpers can keep working during the
    PR-1 transition.
  - 100% unit coverage on every variant + a snapshot test of the
    wire shape.
- **Verify** `cargo test --package vtc-service acl::role::` green.
- **Files**
  - `vtc-service/src/acl/role.rs` (new)
  - `vtc-service/src/acl/mod.rs` (re-export `VtcRole`)
- **Deps**: none
- **Pre-impl decision**: **D1** (role enum location — vtc-service-
  owned per the plan).

---

## M1.2 — ACL unification

### `[x]` M1.2.1 — `VtcAclEntry` + storage CRUD

- **Acceptance**
  - New struct `vtc_service::acl::VtcAclEntry { did, role: VtcRole,
    label, allowed_contexts, created_at, created_by, expires_at }`
    replacing `vti_common::acl::AclEntry` for vtc-side storage.
  - Helpers: `store_acl_entry`, `get_acl_entry`, `list_acl_entries`,
    `delete_acl_entry` (per-DID CRUD over `acl:<did>` key shape).
  - Pagination via `vti_common::pagination::Cursor`.
  - Backwards-compat decode: existing on-disk rows that carry a
    `vti_common::acl::Role::Admin` value continue to decode to
    `VtcRole::Admin` without migration. Other variants
    (`Initiator`, `Application`, `Reader`) currently don't appear
    in VTC ACL rows, but the decoder rejects them with a clear
    error pointing at the spec.
- **Verify**
  - Round-trip every `VtcRole` variant through store + list.
  - A row written by the Phase 0 `vti_common::acl::store_acl_entry`
    (with `Role::Admin`) decodes via the new
    `get_acl_entry` without panic.
- **Files**
  - `vtc-service/src/acl/entry.rs` (new — `VtcAclEntry`)
  - `vtc-service/src/acl/storage.rs` (new — CRUD over the new shape)
  - `vtc-service/src/acl/mod.rs`
- **Deps**: M1.1.1
- **Pre-impl decision**: **D2** (admin sister record loses role
  field; passkeys stay where they are).

### `[x]` M1.2.2 — Wire `VtcAclEntry` everywhere

- **Acceptance**
  - Every consumer of `vti_common::acl::store_acl_entry`,
    `get_acl_entry`, `list_acl_entries`, `delete_acl_entry` in
    `vtc-service` switches to the new `vtc_service::acl::storage::*`
    helpers.
  - `admin/passkeys/*` keeps its sister-record lookups; just stops
    treating the sister record's role as authoritative.
  - All admin bootstrap tests + admin passkey tests + emergency
    bootstrap tests stage `VtcAclEntry` instead of
    `vti_common::acl::AclEntry`.
- **Verify** Existing vtc-service tests green after the swap.
- **Files**
  - `vtc-service/src/routes/install.rs`
  - `vtc-service/src/routes/admin/bootstrap.rs`
  - `vtc-service/src/routes/admin/passkeys.rs`
  - `vtc-service/src/emergency.rs`
  - Every `vtc-service/tests/*.rs` fixture
- **Deps**: M1.2.1

---

## M1.3 — Member model + keyspace

### `[x]` M1.3.1 — `Member` struct + `members` keyspace

- **Acceptance**
  - `vtc_service::members::Member { did, joined_at, status_list_index:
    Option<u32>, publish_consent: bool, departure_preference:
    Disposition, current_vmc_id: Option<String>, current_role_vec_id:
    Option<String>, extensions: JsonValue }` per spec §5.2.
  - `extensions` capped at 16 KiB (D4 from M0.7.1).
  - New `members` keyspace registered in `AppState`.
  - CRUD helpers: `store_member`, `get_member`, `list_members`
    (paginated), `delete_member`.
  - `Disposition` enum: `{ Purge, Tombstone, Historical, PolicyDefault }`.
- **Verify** Round-trip every disposition + `extensions` size-limit test.
- **Files**
  - `vtc-service/src/members/mod.rs` (new)
  - `vtc-service/src/members/storage.rs` (new)
  - `vtc-service/src/server.rs` (AppState gains `members_ks`)
  - `vtc-service/src/store/mod.rs` (register keyspace)
- **Deps**: M1.1.1 (uses `VtcRole`)
- **Pre-impl decision**: **D3** (separate keyspaces from ACL).

---

## M1.4 — Member read endpoints

### `[x]` M1.4.1 — `GET /v1/members` + `GET /v1/members/{did}`

- **Acceptance**
  - List endpoint returns a `Paginated<Member>` using the cursor
    primitive. Filter params: `?role=Admin|Moderator|...` (server-
    side filter against the ACL join), `?cursor=...`, `?limit=...`
    (1..200 clamp).
  - Show endpoint returns the `Member` row + the matching
    `VtcAclEntry` for the same DID (joined response shape).
  - Auth: any authenticated session can list/show. Phase 1 has no
    privacy gating beyond auth; spec §12.3 PMF lands in Phase 2+.
  - Trust Task IDs: `members/list/1.0`, `members/show/1.0`.
- **Verify**
  - Integration tests: list returns seeded members, cursor walks
    correctly, show returns 404 for non-members.
- **Files**
  - `vtc-service/src/routes/members/mod.rs` (new)
  - `vtc-service/src/routes/members/read.rs` (new)
  - `vtc-service/src/routes/mod.rs` (mount + Trust Tasks)
  - `trust-tasks/members/list/1.0/{spec.md,schema.json}`
  - `trust-tasks/members/show/1.0/{spec.md,schema.json}`
- **Deps**: M1.3.1

---

## M1.5 — Member update

### `[x]` M1.5.1 — `PATCH /v1/members/{did}` (role + profile)

- **Acceptance**
  - Body shape: `{ role?: VtcRole, publish_consent?: bool,
    departure_preference?: Disposition, extensions?: JsonValue }`.
  - Refuses any `role` patch where the requested value is
    `VtcRole::Admin` — return 422 `AdminPromotionRequiresStepUp`
    with a hint pointing at `POST /v1/members/{did}/promote-to-admin`.
  - Auth: caller role ≥ `Moderator` for role changes; caller role ≥
    `Moderator` or `caller_did == did` for profile-only patches.
  - On success: ACL row + Member row updated under a single fjall
    transaction; emits `RoleChanged` (if role changed) or
    `MemberUpdated` (profile-only). 
  - Trust Task ID: `members/update/1.0`.
- **Verify** Integration tests cover happy path + role=Admin
  refusal + non-self profile patch from a non-admin (403) + concurrent
  PATCH under the per-DID CAS lock.
- **Files**
  - `vtc-service/src/routes/members/update.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/members/update/1.0/{spec.md,schema.json}`
- **Deps**: M1.4.1

---

## M1.6 — Admin promotion (step-up UV)

### `[x]` M1.6.1 — `POST /v1/members/{did}/promote-to-admin`

- **Acceptance**
  - Two-phase ceremony mirroring `admin/passkeys/register/{start,finish}`:
    - `start` returns a UV challenge against the caller's existing
      passkey.
    - `finish` verifies UV → atomically promotes the target DID's
      ACL role to `VtcRole::Admin`, copies the new admin DID into
      the passkey keyspace's sister record (empty `passkeys` list
      so the new admin enrols their device next), emits
      `AdminPromoted`.
  - Refused if the caller is not already an admin (403).
  - Refused if the target is not a current Member (404).
  - Refused if the target is already an admin (409).
  - Trust Task ID: `members/promote-to-admin/1.0`.
- **Verify**
  - Integration tests: happy path with step-up UV; refusals for
    non-admin caller, non-member target, already-admin target;
    audit envelope shape verified.
- **Files**
  - `vtc-service/src/routes/members/promote.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/members/promote-to-admin/1.0/{spec.md,schema.json}`
- **Deps**: M1.4.1, M1.2.2 (touches AclEntry + passkey sister record)

---

## M1.7 — JoinRequest model + retention

### `[x]` M1.7.1 — `JoinRequest` struct + `join_requests` keyspace

- **Acceptance**
  - `vtc_service::join::JoinRequest { id: Uuid, applicant_did, vp:
    JsonValue, submitted_at: DateTime<Utc>, status: JoinStatus,
    policy_decision: Option<JsonValue>, registry_consent: bool,
    extensions: JsonValue }` per spec §5.5.
  - `JoinStatus`: `{ Pending, Approved, Rejected, Withdrawn, Deferred }`.
  - CRUD helpers + paginated list with status filter.
  - Retention sweeper task that prunes `Rejected` + `Withdrawn` rows
    older than `config.join_requests.retention_days` (default 30).
    Sweeper runs hourly on the daemon's tokio runtime.
- **Verify**
  - Round-trip every status variant.
  - Retention sweeper test with seeded rows + clock injection.
- **Files**
  - `vtc-service/src/join/mod.rs` (new)
  - `vtc-service/src/join/storage.rs` (new)
  - `vtc-service/src/join/retention.rs` (new)
  - `vtc-service/src/server.rs` (AppState gains `join_requests_ks`,
    sweeper spawned at startup)
  - `vtc-service/src/config.rs` (`JoinRequestsConfig` with
    `retention_days`)
- **Deps**: M1.3.1
- **Pre-impl decision**: **D4** (VP shape — opaque JSON for Phase 1).

---

## M1.8 — Submit join request

### `[x]` M1.8.1 — `POST /v1/join-requests` (REST)

- **Acceptance**
  - Unauthenticated (rate-limited per spec §9 unauth-route policy).
  - Body shape: `{ applicant_did, vp: JsonValue, registry_consent?:
    bool, extensions?: JsonValue }`.
  - Verifies the VP signature + that the VP's `holder` equals
    `applicant_did` (D4 — holder-binding is the only check).
  - Persists as `JoinStatus::Pending`; emits `JoinRequestSubmitted`
    audit envelope.
  - Idempotency-Key header honoured (24h cache for the non-
    destructive request, per M0.1.3).
  - Trust Task ID: `join-requests/submit/1.0`.
- **Verify**
  - Happy path; malformed VP rejected with 400; mismatched holder
    rejected with 422.
- **Files**
  - `vtc-service/src/routes/join_requests/mod.rs` (new)
  - `vtc-service/src/routes/join_requests/submit.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/join-requests/submit/1.0/{spec.md,schema.json}`
- **Deps**: M1.7.1, M1.4.1

### `[x]` M1.8.2 — DIDComm twin for submit

- **Acceptance**
  - DIDComm message `type` =
    `https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0`.
  - Wallet sends an anoncrypt-packed envelope addressed to the
    VTC DID; the VTC unpacks, runs the same handler shape as
    REST, and replies with a `join-request-receipt` message
    carrying the request UUID + status.
  - The applicant_did MUST be the DIDComm `from` field (no
    separate VP holder field needed — the DIDComm envelope
    already binds the sender).
- **Verify** End-to-end test against the existing DIDComm test
  responder fixture (mirrors `vti-e2e-tests` pattern).
- **Files**
  - `vtc-service/src/messaging.rs` (handler dispatch)
  - `vta-sdk/src/protocols/join_requests/mod.rs` (new wire types)
- **Deps**: M1.8.1
- **Pre-impl decision**: **D5** (DIDComm scope per-endpoint).

---

## M1.9 — Join request read endpoints (admin)

### `[x]` M1.9.1 — `GET /v1/join-requests` + `/v1/join-requests/{id}`

- **Acceptance**
  - List endpoint requires admin or moderator role; returns
    `Paginated<JoinRequest>` filtered by `?status=Pending`
    (default), other statuses available.
  - Show endpoint requires admin or moderator role; returns the
    full JoinRequest including the opaque VP.
  - Trust Task IDs: `join-requests/list/1.0`,
    `join-requests/show/1.0`.
- **Verify** Integration tests: list filters by status, show 404s
  for unknown ids, non-admin/mod returns 403.
- **Files**
  - `vtc-service/src/routes/join_requests/read.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/join-requests/list/1.0/{spec.md,schema.json}`
  - `trust-tasks/join-requests/show/1.0/{spec.md,schema.json}`
- **Deps**: M1.7.1

---

## M1.10 — Join request decision

### `[x]` M1.10.1 — `POST /v1/join-requests/{id}/{approve,reject}`

- **Acceptance**
  - Admin or moderator role required.
  - **Approve**: atomically transitions JoinRequest status to
    `Approved`, writes ACL row (`VtcRole::Member` default), writes
    Member row, emits `JoinRequestApproved` + `MemberAdded`.
    Refuses if the `applicant_did` already has an ACL row (409).
  - **Reject**: transitions to `Rejected` with optional reason in
    body; emits `JoinRequestRejected`.
  - Idempotency-Key honoured (60s destructive-class TTL per M0.1.3).
  - Trust Task IDs: `join-requests/approve/1.0`,
    `join-requests/reject/1.0`.
- **Verify**
  - Happy path: pending → approved + ACL + Member written.
  - Approve a request whose `applicant_did` already has an ACL
    row → 409.
  - Reject is a clean state transition with no ACL/Member writes.
- **Files**
  - `vtc-service/src/routes/join_requests/decide.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/join-requests/approve/1.0/{spec.md,schema.json}`
  - `trust-tasks/join-requests/reject/1.0/{spec.md,schema.json}`
- **Deps**: M1.9.1, M1.4.1

---

## M1.11 — Self-removal

### `[x]` M1.11.1 — `DELETE /v1/members/me` (REST + DIDComm)

- **Acceptance**
  - Authenticated caller's `did` is the target. Body shape:
    `{ disposition: Purge | Tombstone | Historical | PolicyDefault }`
    — default `PolicyDefault` which resolves to `Tombstone` in
    Phase 1 per **D6**.
  - **No-last-admin invariant**: if the caller is the sole
    remaining admin, return 409 `LastAdminProtected`. Check inside
    a fjall transaction protected by a process-wide
    `LAST_ADMIN_LOCK` mutex (same shape as `ADMIN_PASSKEY_LOCK`).
  - Atomic: ACL row deleted, Member row anonymised (Tombstone) or
    purged (Purge) or retained (Historical); audit emits
    `MemberRemoved`. Status-list index flipping is Phase 2 — for
    now log a `TODO` line on the audit envelope.
  - Trust Task ID: `members/self-remove/1.0`.
- **Verify**
  - Integration tests: happy paths for each disposition; sole-admin
    self-removal returns 409; concurrent self-remove attempts
    under the mutex.
- **Files**
  - `vtc-service/src/routes/members/remove.rs` (new)
  - `vtc-service/src/messaging.rs` (DIDComm twin handler)
  - `trust-tasks/members/self-remove/1.0/{spec.md,schema.json}`
- **Deps**: M1.4.1
- **Pre-impl decision**: **D6** (disposition default).

---

## M1.12 — Admin removal

### `[x]` M1.12.1 — `DELETE /v1/members/{did}` (REST only)

- **Acceptance**
  - Admin role required.
  - Caller cannot remove themselves via this endpoint (use
    `/members/me` for that — refused with 422 pointing there).
  - Same no-last-admin invariant under the same `LAST_ADMIN_LOCK`.
  - Body shape: `{ disposition?: Disposition, reason?: String }`.
  - Effects identical to self-removal; audit envelope carries the
    `admin_did` as actor + the target DID as resource.
  - Trust Task ID: `members/admin-remove/1.0`.
- **Verify**
  - Happy path; remove-self refused; remove-last-admin refused;
    audit envelope distinguishes admin removal from self-removal
    via the `actor` vs `target` distinction.
- **Files**
  - `vtc-service/src/routes/members/remove.rs` (extended)
  - `trust-tasks/members/admin-remove/1.0/{spec.md,schema.json}`
- **Deps**: M1.11.1

---

## M1.13 — Audit event variants

### `[x]` M1.13.1 — Phase 1 audit event vocabulary

- **Acceptance**
  - `AuditEvent` enum (`vti_common::audit::envelope`) gains
    variants: `JoinRequestSubmitted`, `JoinRequestApproved`,
    `JoinRequestRejected`, `MemberAdded`, `MemberRemoved`,
    `MemberUpdated`, `RoleChanged`, `AdminPromoted`.
  - Each variant's `data` payload schema captured as a `data:
    JsonValue` per Phase 0's convention; per-variant snapshot test
    pins the wire shape.
  - Existing audit emitters (M1.5–M1.12) wire to the new variants.
- **Verify** Snapshot test per variant + round-trip every variant
  through `AuditWriter`.
- **Files**
  - `vti-common/src/audit/envelope.rs`
- **Deps**: every endpoint milestone (consumers wire after
  variants land)

---

## M1.14 — Trust Task drafts + index

### `[x]` M1.14.1 — Spec + schema files for Phase 1 surface

- **Acceptance**
  - All 11 Trust Tasks from plan §D7 have `spec.md` (request +
    response + error semantics) and `schema.json` (request +
    response shape) files.
  - `trust-tasks/index.json` extended with all 11 entries in
    `Draft` status.
- **Verify** `cargo test` validates Trust Task files (extant
  framework from M0.3); index.json round-trips through serde.
- **Files**
  - `trust-tasks/{join-requests,members}/...`
  - `trust-tasks/index.json`
- **Deps**: M1.8, M1.9, M1.10, M1.11, M1.12 (every endpoint must
  exist before its Trust Task file is non-stub)

---

## M1.15 — Phase 1 gate green

### `[x]` M1.15.1 — Workspace gate

Closed 2026-05-12.

- `cargo build --workspace` green ✓
- `cargo test --workspace` green ✓ (>200 vtc-service tests; full
  workspace passes)
- `cargo clippy --workspace --all-targets -- -D warnings` clean ✓
- `cargo fmt --check` clean ✓
- `trust-tasks/index.json` lists **31** Trust Tasks in `Draft`;
  each has matching `spec.md` + `schema.json` on disk (1:1).
  Phase 1's 11 new tasks: `members/{list,show,update,
  promote-to-admin,self-remove,admin-remove}/1.0` +
  `join-requests/{submit,list,show,approve,reject}/1.0`.
- 8 Phase 1 audit variants
  (`JoinRequestSubmitted`, `JoinRequestApproved`,
  `JoinRequestRejected`, `MemberAdded`, `MemberRemoved`,
  `MemberUpdated`, `RoleChanged`, `AdminPromoted`) each have a
  live emit site in vtc-service.
- Memory entry `project_vtc_mvp.md` updated with the Phase 1
  closure note + implementation-time deviations (VtcRole wire
  shape, M1.8.2 DIDComm routing, no-last-admin lock).

### Checkpoint — Phase 1 gate met

After M1.15.1: applicants can submit join requests (REST +
DIDComm); admins can list, approve, reject; members can self-
remove with no-last-admin protection; admin promotion uses
step-up UV. Phase 2 (policy engine + VMC/VEC) can start.

---

## Open questions surfaced during planning

Defaults in `phase-1-plan.md` §§D1–D8. Listed here so they're
findable from the todo:

- **D1**: Role enum location — vtc-service-owned (proposed).
- **D2**: AdminEntry → AclEntry — role merges, passkeys stay
  sister-record (proposed).
- **D3**: Member vs AclEntry — separate keyspaces (proposed).
- **D4**: JoinRequest VP shape — holder-binding only,
  additional VC content opaque (proposed).
- **D5**: DIDComm scope — applicant-facing endpoints only
  (proposed).
- **D6**: Removal disposition default — `PolicyDefault →
  Tombstone` in Phase 1 (proposed).
- **D7**: Trust Task ID naming — see plan §D7.
- **D8**: Member ID — DIDs for `members:`, UUIDs for
  `join_requests:` (proposed).

Any decision that drifts from the default during implementation
should be recorded in `phase-1-plan.md` under a "Phase 1
outcome" header (mirrors Phase 0's
`vta-driven-keys.md` `Resolution` pattern).
