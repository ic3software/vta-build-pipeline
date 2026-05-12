# VTC MVP — Phase 1 plan

> **Status:** draft, awaiting review.
> **Deliverable:** "Members can exist." Per spec §16 Phase 1:
> Role enum + custom roles, ACL extension, member CRUD with manual
> approval, self/admin removal (no-last-admin), audit envelope
> events for the new surface.
> **Spec:** `docs/05-design-notes/vtc-mvp.md` §§5.2–5.5, §10.1–10.4.

## Objective

After Phase 1, a freshly-bootstrapped VTC daemon can:

- Accept VP-framed `POST /v1/join-requests` from an applicant DID.
- Persist the request; an admin lists pending requests, approves
  or rejects, and on approval the applicant's DID is admitted to
  the ACL with the default `Member` role and a `members:<did>`
  metadata row.
- Surface `GET / PATCH /v1/members[/{did}]` so admins can read +
  edit member metadata, with role changes (except to `Admin`)
  applied via PATCH.
- Promote an existing member to `Admin` via the separate
  `POST /v1/members/{did}/promote-to-admin` endpoint, gated by
  a step-up WebAuthn UV ceremony.
- Process self-removal (`DELETE /v1/members/me`) and admin removal
  (`DELETE /v1/members/{did}`), with the no-last-admin invariant
  enforced under fjall CAS.
- Emit `JoinRequestSubmitted`, `JoinRequestApproved`,
  `JoinRequestRejected`, `MemberAdded`, `MemberRemoved`,
  `AdminPromoted`, `RoleChanged` audit envelopes.

Out of scope (deferred to Phase 2+):

- `regorus` policy engine, `join.rego` / `removal.rego` evaluation.
  Phase 1 join is **manual admin approval**; the VP's claims are
  recorded as opaque JSON on the JoinRequest for Phase 2 to score.
- VMC + role VEC issuance via the VTA oracle.
- Status-list allocation + flipping.
- DID rotation (both methods).
- Personhood; cross-community recognition; trust-registry sync.

## Scope (per spec §16, Phase 1 row)

### In scope

- **Role enum extension.** `vti_common::acl::Role` cannot grow VTC-
  specific variants without leaking into VTA — see **D1**. Per
  service, the role taxonomy is service-owned; vtc-service gets a
  `VtcRole` enum mirrored on the AclEntry shape it stores under
  `acl:<did>`.
- **ACL extension.** Phase 0's M0.6.1 stored admin metadata in a
  **sister record** under `admin:<did>` (since the shared
  `AclEntry.role` field was a `vti_common::acl::Role` and couldn't
  carry VTC-specific values). Phase 1 collapses that — see **D2**.
- **Member model** (`members:<did>`) — fields per spec §5.2 minus
  the Phase 2 credential pointers (`status_list_index`,
  `current_vmc_id`, `current_role_vec_id` ship as `Option<T>` slots
  populated by Phase 2 work).
- **JoinRequest model** (`join_requests:<id>`) + 30-day retention
  sweeper.
- **REST surface** for member CRUD + join requests + removal +
  admin promotion.
- **DIDComm twin** for the applicant-facing join-request submit
  endpoint — see **D5**.
- **Audit envelope events** for every state mutation on this
  surface.
- **Trust Task** stable IDs + `spec.md` + `schema.json` for every
  new endpoint.

### Out of scope

Everything in spec §16 Phase 2 and later. The Phase 0 hygiene
items the §16 table parks under Phase 1 (audit envelope, HMAC,
idempotency, `/v1/` versioning, cursor pagination) **already
shipped** in Phase 0 as M0.1.* and don't re-land here.

## Pre-implementation design decisions

These are **load-bearing** — Phase 1's whole shape depends on
them. Proposed defaults below. Flag dissent before any code lands.

### D1 — Role enum location

Two options for extending the role taxonomy:

- **(a)** Move VTC-specific variants into `vtc-service`. The shared
  `vti_common::acl::AclEntry` becomes generic over a service-owned
  role type (or vtc-service stops using vti_common's AclEntry and
  ships its own). VTA-side roles stay where they are.
- **(b)** Add `Moderator`, `Issuer`, `Member`, `Custom(String)`
  to the shared `vti_common::acl::Role` enum. VTA ignores those
  variants by documentation.

**Proposed default: (a).** Cleanest separation; VTA doesn't
inherit roles it has no semantics for; the `Role::Custom(String)`
variant is genuinely community-specific and shouldn't pollute
VTA. Implementation: vtc-service gets `vtc_service::acl::VtcRole`
and a parallel `VtcAclEntry` that wraps it, replacing the
vti-common-rooted `AclEntry` for VTC-facing storage. VTA-side
storage uses vti-common as before.

### D2 — AdminEntry → AclEntry unification

Phase 0 shipped `AdminEntry` as a sister record under
`admin:<did>` in the passkey keyspace because the shared
`AclEntry.role` couldn't carry VTC-specific values. After D1, the
VTC's AclEntry can grow `passkeys: Vec<RegisteredPasskey>`
directly — at which point `admin:<did>` is dead weight.

**Proposed default: collapse, but only at the role level.** Move
the role enum into the unified `VtcAclEntry`. **Keep passkeys in
their own sister record** — they're admin-only metadata with
distinct ownership (the passkey routes manage them, not the
member-CRUD routes) and bloating every `AclEntry` lookup with
a passkey list is wasteful when most rows aren't admins. The
sister record stays under `admin:<did>` but loses its role field
(role is now canonically on the AclEntry).

### D3 — Member vs AclEntry

Spec §5.2's `Member` carries `joined_at`, `status_list_index`,
`publish_consent`, `departure_preference`, etc. — much richer than
`AclEntry`'s auth-gate role + label.

**Proposed default: separate keyspaces.** `acl:<did>` (auth) and
`members:<did>` (community-membership metadata) are 1:1 by DID
but logically distinct. Hash-only joins via the DID. Creating
the Member record is one atomic transaction with the ACL row
write; deletion is the same — `MemberRemoved` audit fires on the
last delete of the pair.

### D4 — JoinRequest VP shape

Without `regorus` (Phase 2), the join VP can carry whatever the
applicant wants — Phase 1 has no policy to score it against.

**Proposed default: Phase 1 requires only the holder-binding
proof.** The VP's `holder` must match `applicant_did`; the VP
signature must verify. Any additional VC content the VP includes
is recorded **verbatim as opaque JSON** on the JoinRequest record
so Phase 2's policy step has the input it needs without an
intermediate re-submit. PII concern noted (spec §5.5) — same
30-day retention rule applies regardless of VP content shape.

### D5 — DIDComm vs REST surface

The §16 Phase 1 row implicitly asks for DIDComm parity. Spec §4.3
explicitly forbids passkey ops over DIDComm; the rest of the
surface is open.

**Proposed default: DIDComm only for applicant-facing endpoints.**

| Endpoint | REST | DIDComm |
|---|---|---|
| `POST /v1/join-requests` | ✓ | ✓ |
| `GET / PATCH / DELETE /v1/members[/{did}]` | ✓ | — |
| `POST /v1/members/{did}/promote-to-admin` | ✓ | — |
| `GET / POST /v1/join-requests/{id}/{approve,reject}` | ✓ | — |
| `DELETE /v1/members/me` | ✓ | ✓ |

Rationale: admins typically operate via the admin UX (web/REST);
applicants and self-removing members frequently come from
wallets (DIDComm). The asymmetric scope avoids building DIDComm
admin twins that nobody actually uses in Phase 1.

### D6 — Removal disposition default

Spec §5 lists `Purge | Tombstone | Historical | PolicyDefault`.
`PolicyDefault` resolves via `removal.rego`'s
`min_disposition` output — Phase 2.

**Proposed default: `PolicyDefault → Tombstone` in Phase 1.** The
boring middle ground (member record anonymised, audit retained).
Operators explicitly picking `Purge` or `Historical` get that
behavior. Phase 2 swaps the resolver to read
`removal.rego.min_disposition`.

### D7 — Trust Task ID naming for the new surface

Following the Phase 0 pattern (stable IDs from day one, soft gate
on the `Draft` status):

| Operation | Trust Task ID |
|---|---|
| Submit join request | `https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0` |
| List join requests (admin) | `…/join-requests/list/1.0` |
| Show join request | `…/join-requests/show/1.0` |
| Approve | `…/join-requests/approve/1.0` |
| Reject | `…/join-requests/reject/1.0` |
| List members | `…/members/list/1.0` |
| Show member | `…/members/show/1.0` |
| Update member | `…/members/update/1.0` |
| Self-remove | `…/members/self-remove/1.0` |
| Admin remove | `…/members/admin-remove/1.0` |
| Promote to admin | `…/members/promote-to-admin/1.0` |

### D8 — Member ID — DID vs UUID

Spec §5.2 doesn't pin this. PR-A of Phase 0 used DIDs as primary
keys throughout (`acl:<did>`, `admin:<did>`). Phase 1's
JoinRequest needs an ID before the DID is admitted; that ID has
to be a UUID (or similar opaque token).

**Proposed default**: DIDs as primary keys for `members:` (the
DID is the stable identifier); UUIDs for `join_requests:` (no DID
binding until approval). The applicant_did **does** appear inside
the JoinRequest payload, but the row's key stays UUID-shaped.

## Dependency graph

```
M1.1 Role enum extension (vtc_service::acl::VtcRole)
  │
  ▼
M1.2 ACL unification (drop AdminEntry sister role field)
  │     [parallel: M1.3 Member model]
  ▼
M1.3 Member model + members keyspace + CRUD primitives
  │
  ▼
M1.4 GET /v1/members + /v1/members/{did}
M1.5 PATCH /v1/members/{did} (role change, profile edit)
M1.6 POST /v1/members/{did}/promote-to-admin (step-up UV)
  │
  │     [parallel: M1.7 JoinRequest model]
  ▼
M1.7 JoinRequest model + keyspace + retention sweeper
  │
  ▼
M1.8 POST /v1/join-requests (REST + DIDComm)
M1.9 GET /v1/join-requests + /v1/join-requests/{id}
M1.10 POST /v1/join-requests/{id}/{approve,reject}
  │
  ▼
M1.11 DELETE /v1/members/me (REST + DIDComm, no-last-admin)
M1.12 DELETE /v1/members/{did} (REST only, no-last-admin)
  │
  ▼
M1.13 Audit event variants for Phase 1 surface
M1.14 Trust Task spec.md + schema.json for every new endpoint
  │
  ▼
M1.15 Phase 1 gate (workspace green + memory updated)
```

Strict dependency order: M1.1 → M1.2 (both touch ACL). M1.3 can
start in parallel with M1.2 (separate keyspace). The member-CRUD
endpoints (M1.4–M1.6) need M1.2 + M1.3 done. JoinRequest
endpoints (M1.7–M1.10) need M1.3 done for the approval path. The
removal endpoints (M1.11–M1.12) need M1.4–M1.6 in tree (they
share the member-CRUD primitives). Audit + Trust Task work
trails behind the endpoints.

## Parallelisation strategy

Within a milestone, vertical slice — each endpoint ships with its
trust task files + integration tests + audit emission, not in
batches.

Cross-milestone parallel tracks:
- **M1.2 + M1.3** can run in parallel after M1.1.
- **M1.5 + M1.6** can run in parallel after M1.4.
- **M1.8 + M1.9 + M1.10** can run in parallel after M1.7.
- **M1.11 + M1.12** can run in parallel after M1.6 (different
  no-last-admin CAS shapes, but same primitive).
- **M1.13 + M1.14** can run in parallel after every endpoint is
  in tree.

Phase 1 splits cleanly into ~3 PR batches:
1. **PR-1**: M1.1 + M1.2 + M1.3 (foundation — Role + ACL + Member).
2. **PR-2**: M1.4–M1.6 (member CRUD + admin promotion).
3. **PR-3**: M1.7–M1.10 (join requests).
4. **PR-4**: M1.11 + M1.12 (removal).
5. **PR-5**: M1.13 + M1.14 + M1.15 (audit + trust tasks + gate).

5 PRs feels about right for the scope. Phase 0 was 12 PRs across
12 milestones; Phase 1's 15 milestones bundle more cleanly because
the dependency graph is shallower.

## Checkpoints

After each PR batch, a "smoke" sanity check that doesn't require
the next batch to land:

- **After PR-1**: `cargo test -p vtc-service` green. AdminEntry's
  role field gone; passkey routes still pass. No new endpoint.
- **After PR-2**: list/show/update + admin promotion green;
  step-up UV works against the existing passkey state.
- **After PR-3**: applicant can submit (REST + DIDComm); admin
  can approve → ACL row + Member row + audit envelope all land.
- **After PR-4**: no-last-admin invariant tested under
  concurrent removal attempts (mutex shape mirrors
  ADMIN_PASSKEY_LOCK).
- **After PR-5**: M1.15 workspace gate identical to M0.12.3's
  pattern. Phase 1 closes.

## Risks

- **R1: AclEntry migration breaks Phase 0 fixtures.** Every
  integration test in vtc-service stages an AclEntry today. M1.2
  changes the shape. Need a migration helper + fixture flip in
  the same PR (PR-1).
- **R2: DIDComm twin scope creep.** Spec §16 Phase 1 says "member
  CRUD" without specifying transport. D5 restricts DIDComm to
  applicant-facing endpoints. Operator UX may push for DIDComm
  admin variants — defer to Phase 1.5 if surfaced.
- **R3: No-last-admin CAS correctness.** Mutex covers single-
  process; fjall isn't multi-process-safe (architectural
  invariant per project memory). Single-process is fine but
  document the assumption.
- **R4: VP verification dep choice.** JoinRequest VP signatures
  need a verifier. PR-A of Phase 0 used `affinidi-data-integrity`
  via vta-sdk's provision-integration path. Phase 1 should reuse
  the same verifier rather than introduce a parallel one — pin
  this in M1.8 implementation.
- **R5: `audit_key` rotation under member churn.** Phase 0
  baseline rotates on RTBF. Phase 1's removal paths trigger that;
  make sure the rotation hook actually fires when removal
  disposition is `Purge`.

## Definition of done — Phase 1

After M1.15:

- `cargo build/clippy/fmt/test --workspace` clean.
- 11 new Trust Tasks (D7) in `Draft` status with matching
  `spec.md` + `schema.json` files.
- Every Phase 1 milestone marked `[x]` in `phase-1-todo.md`.
- Memory entry `project_vtc_mvp.md` updated with any
  implementation-time tweaks discovered along the way (mirrors
  Phase 0's pattern).
- Integration tests cover: applicant join → admin approve → ACL +
  Member row written → self-remove with no-last-admin protection
  → admin promotion with step-up UV.

Phase 2 (policy engine + VMC/VEC issuance + status list) can
start after Phase 1's gate merges.
