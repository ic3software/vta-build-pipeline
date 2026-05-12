# VTC MVP — Phase 2 plan

> **Status:** draft, awaiting review.
> **Deliverable:** "Live policy + credentials." Per spec §16
> Phase 2: `regorus`, policy upload + activate, `join.rego` +
> `removal.rego`, VMC + VEC issuance, status-list with reserved-
> index discipline, renewal, DID rotation.
> **Spec:** `docs/05-design-notes/vtc-mvp.md` §§5.4, 6.1–6.3,
> 7, 10.5, 14.2.

## Objective

After Phase 2, a VTC issues real credentials backed by real
policy:

- Admins upload, test, and activate `join.rego` /
  `removal.rego` / friends. Default policies ship and apply on
  install.
- `POST /v1/join-requests` (existing) consults `join.rego`
  before persisting; on `allow`, the approve path mints a VMC +
  role VEC and seals them to the applicant. On `deny`, the
  decision is recorded with the policy's rationale.
- Removal (existing) consults `removal.rego` for admin-initiated
  removals; the disposition resolver reads the policy's
  `min_disposition` output.
- The VTC publishes two `BitstringStatusListCredential`s
  (revocation + suspension), allocates indices with privacy-
  preserving decoys, never reallocates flipped slots.
- `POST /v1/members/me/renew` re-issues a member's VMC + role
  VEC unconditionally on ACL membership (spec §6.3).
- DID rotation works for both `did:webvh` (native via
  `did.jsonl` history) and `did:key` (co-signed attestation,
  domain-tag-prefixed).

Out of scope (deferred to Phase 3+):

- Trust-registry publication (`MembershipSyncer`,
  `registry.rego` consumption, three-disposition reconciliation).
- Cross-community recognition.
- Personhood (`personhood.rego` deny-all stub ships in §6.4 but
  the assert/revoke endpoints land in Phase 4).
- VRC / RCard issuance — Phase 4.

## Scope (per spec §16, Phase 2 row)

### In scope

- **`regorus` integration** — embedded Rego compiler/evaluator
  in vtc-service. No OPA sidecar.
- **Policy CRUD + activation** — upload, compile, test, activate
  endpoints. `policies:` keyspace.
- **Bundled default policies** for `join`, `removal`,
  `role_definitions`, plus the deny-all stubs for
  `personhood`, `cross_community_roles`,
  `cross_community_relationships`.
- **VC builder** using `affinidi-vc` + `affinidi-data-integrity`
  for VMC + VEC issuance.
- **Local VTC signing** (per **D1** below) — VTC's `#key-0`
  Ed25519 signs VMCs/VECs/status-list credentials directly.
- **Status-list infrastructure** — BitstringStatusList VC build,
  reserved-index allocator, `status_lists:` keyspace, public
  `GET /v1/status-lists/{purpose}` route.
- **VMC + VEC issuance on approve** — `join-requests/approve`
  mints + seals on a policy `allow`.
- **`POST /v1/members/me/renew`** — re-mint VMC + role VEC.
- **Status-list flip on removal** — `MemberRemoved` writes the
  revocation bit.
- **DID rotation** — `did:webvh` native + `did:key` co-signed.
- **Trust Tasks** + spec.md/schema.json for every new endpoint.

### Out of scope

- Trust registry — Phase 3.
- Cross-community recognition — Phase 3.
- VRC issuance — Phase 4.
- Personhood `assert`/`revoke` endpoints — Phase 4 (the
  `personhood.rego` stub ships in Phase 2 as default-deny per
  spec §7.1; only the **assert/revoke endpoints** are deferred).
- Reactor / chaining of status-list capacity (v2 per spec §17).

## Pre-implementation design decisions

Load-bearing. Defaults below; flag dissent before any code lands.

### D1 — Signing surface: cached-locally, VTA-controlled

Spec §3-A wording — "VTC has no key custody; every signature
delegates to the VTA signing oracle" — is overloaded.
**Custody** could read as "no key storage at all" or as "no
key minting / rotation authority". The working architecture
matches the `affinidi-messaging-mediator` +
`affinidi-webvh-services` pattern: **the VTA is the key
controller; the VTC caches a working copy in its secret
store and signs locally**.

The post-PR-A `VtcKeyBundle` shape is correct under this
reading — the VTA mints the integration DID's keys, seals
them to the VTC at first-boot via the `vtc-host`
provision-integration flow, and the VTC retains the cached
copy in its secret store for the lifetime of the deployment.
The VTA remains the authority for **key minting** +
**rotation**; the VTC is just a cached signer.

**Proposed default: VTC signs locally.** Every VMC / VEC /
status-list credential / install-token JWT / DIDComm
outbound message is signed with the cached `#key-0` Ed25519
already in the secret store. No per-call VTA round-trip.

The breaker pattern still has value for **non-VMC remote
dependencies** — trust-registry publish in Phase 3,
did:webvh resolution during member-DID rotation in M2.15.2.
Those truly are remote operations. The pattern stays in the
codebase; only the wiring to VMC issuance is dropped.

**Spec clarification, not deviation** (M2.16): §3-A is
amended to spell out the cached-locally / VTA-controlled
model — "no key custody" was always meant as "no key minting
/ rotation authority", not "no key storage". §14.2's
VTA-oracle timeout + breaker parameters retain their names
but document which operations actually use them (Phase 3
trust-registry, M2.15.2 did:webvh resolver). VMC issuance
is not among them.

### D2 — `regorus` location

- **(a)** New module `vti_common::policy` — would let VTA
  consume it later if VTA grows policy needs.
- **(b)** `vtc_service::policy` — VTC-only.

**Proposed default: (b)**. VTA has no policy story today;
promoting regorus into vti-common is speculative. If VTA later
needs Rego, the move from vtc-service → vti-common is
mechanical.

### D3 — Policy storage shape

`policies:<id>` rows hold the full Policy + compiled bytecode.
`active_policies:<purpose>` rows hold a pointer to the
currently-active id. Activation rewrites the pointer; archived
versions retained for audit + rollback. Compiled bytecode is
**recomputed at boot** (regorus binaries aren't versioned
across releases) — the on-disk row carries only the Rego
source + SHA-256.

### D4 — Policy `input` extraction from a JoinRequest

Phase 1 records the join VP as opaque JSON. Phase 2's policy
step needs `vp_claims` — the verified subset of the VP's
`verifiableCredential` array. **Proposed default**: the
`submit_inner` path verifies the VP at submit time (Phase 2
upgrade from Phase 1's holder-binding-only check), extracts a
canonical `vp_claims` JsonValue, and stores it on the
JoinRequest alongside the raw `vp`. On approve, the policy step
reads the extracted claims directly.

Phase 2 keeps did:key applicants only at the VP-verify layer;
did:webvh applicants land in a follow-up once the
`affinidi-did-resolver-cache-sdk` integration grows the
member-DID hot path.

### D5 — Status-list crypto

The BitstringStatusList credential is itself a VC. It's signed
by `#key-0` (same as VMCs), data-integrity proof, hosted at a
public URL under the VTC's deployment. The DID document's
`#vtc-status-list` service entry already advertises the URL
(`{URL}/v1/status-lists` per the `vtc-host` template).

**Proposed default**: one `BitstringStatusListCredential` per
purpose at `GET /v1/status-lists/{purpose}`, where `purpose ∈
{revocation, suspension}`. Capacity 131_072 (2^17) each, hardcoded
for MVP. Re-issued lazily on every flip — there's no separate
"sign the status list" job.

### D6 — Renewal idempotency

`POST /v1/members/me/renew` is non-destructive (it issues a new
credential without flipping any state). Idempotency cache: 24h
non-destructive class per M0.1.3. Repeated renewals within
24h of the same `Idempotency-Key` return the cached VMC + VEC
pair.

### D7 — DID rotation path split

`did:webvh` and `did:key` rotations are operationally and
cryptographically distinct (spec §10.5). They share the **same
external surface** (`POST /v1/members/me/rotate/challenge` +
`POST /v1/members/me/rotate`) but the verification step
branches on the new DID's method.

**Proposed default**: ship the `did:key` path first
(`vtc-did-rotation/v1\0` domain tag, both-keys co-signed
attestation) since it's the simpler crypto. `did:webvh`
rotation needs `affinidi-did-resolver-cache-sdk` to walk the
`did.jsonl` history; that resolver is already a workspace
dep, but the integration is non-trivial. Both paths in scope
for Phase 2 but `did:webvh` is the riskier slice.

### D8 — Policy hot-swap atomicity

Spec §7.2: "atomically swaps the active policy for its purpose;
in-flight requests against the old policy complete; new
requests use the new."

**Proposed default**: the active pointer is an `Arc<CompiledPolicy>`
held on AppState. `activate` swaps the Arc via
`tokio::sync::RwLock` write; in-flight evaluators hold their
own clone. fjall's `active_policies:<purpose>` row is updated
in the same transaction so a daemon restart picks up the new
active without a separate apply step.

### D9 — Personhood-policy default placement

Spec §6.4 + §7.1: `personhood.rego` ships deny-all. The
**stub ships in Phase 2** (so renewal's §6.3 step 3
`personhood` re-eval has something to call), but the
operator-facing `POST /v1/members/{did}/personhood/{assert,revoke}`
endpoints are Phase 4 work. Phase 2's renewal pipeline just
records `personhood: false` on every renewed VMC.

### D10 — Trust Task ID naming

Following the workspace-wide pattern:

| Operation | Trust Task ID |
|---|---|
| Upload policy | `…/policies/upload/1.0` |
| Activate policy | `…/policies/activate/1.0` |
| Test policy | `…/policies/test/1.0` |
| List policies | `…/policies/list/1.0` |
| Show policy | `…/policies/show/1.0` |
| Renew VMC | `…/members/renew/1.0` |
| Rotation challenge | `…/members/rotate-challenge/1.0` |
| Rotation finish | `…/members/rotate/1.0` |
| Status-list show | `…/status-lists/show/1.0` (exempt from header check — verifier-facing) |

## Dependency graph

```
M2.1 regorus harness in vtc_service::policy
  │
  ▼
M2.2 Policy model + policies keyspace
  │
  ▼
M2.3 POST /v1/policies (upload + activate + test)
M2.4 GET  /v1/policies (list + show)
  │
  ▼  [parallel: M2.9 VC builder]
M2.5 Bundle default policies (join, removal, role_definitions,
     personhood deny-all, cross_community_*, relationships,
     directory, registry)
  │
  ▼
M2.6 Wire join.rego into submit_inner
M2.7 Wire removal.rego into remove_inner
  │
  │  [parallel branch: M2.9 → M2.10 → M2.11]
  ▼
M2.9 VC builder (affinidi-vc + affinidi-data-integrity) +
     local Ed25519 signer (D1) — `vtc_service::credentials`
  │
  ▼
M2.10 Status-list keyspace + reserved-index allocator +
      BitstringStatusList VC builder
  │
  ▼
M2.11 GET /v1/status-lists/{purpose} route
  │
  ▼
M2.12 VMC + VEC issuance wired into join-requests/approve
M2.13 POST /v1/members/me/renew (D6)
M2.16 Status-list flip on removal
  │
  │  [parallel: M2.15 DID rotation]
  ▼
M2.15a did:key rotation (D7)
M2.15b did:webvh rotation
  │
  ▼
M2.17 Phase 2 audit variants
M2.18 Trust Task spec.md + schema.json for every new endpoint
  │
  ▼
M2.19 Phase 2 gate (M2.13's workspace-green check)
```

Critical paths:
- **Policy track** (M2.1 → M2.2 → M2.3 → M2.5 → M2.6 / M2.7).
  Sequential.
- **Credentials track** (M2.9 → M2.10 → M2.11). Sequential but
  parallel with policy track.
- **Issuance integration** (M2.12, M2.13) joins both tracks.
- **DID rotation** (M2.15) is independent — can land in
  parallel with M2.12.

## Parallelisation strategy

Within a milestone: vertical slice — each endpoint ships with
its Trust Task files + integration tests + audit emission, not
in batches.

PR slicing — proposed:

1. **PR-1**: M2.1 + M2.2 + M2.3 + M2.4 (regorus + policy
   CRUD).
2. **PR-2**: M2.5 + M2.6 + M2.7 (default policies + wire
   into existing endpoints).
3. **PR-3**: M2.9 + M2.10 + M2.11 (VC builder +
   status-list infrastructure).
4. **PR-4**: M2.12 + M2.13 + M2.16 (VMC/VEC on approve +
   renew + status-list flip on remove).
5. **PR-5**: M2.15 (DID rotation — did:key + did:webvh).
6. **PR-6**: M2.17 + M2.18 + M2.19 (audit + Trust Tasks + gate).

6 PRs across 19 milestones. Larger phase than Phase 1's
15 milestones / 5 PRs — the credentials track adds substantial
surface.

## Checkpoints

- **After PR-1**: policy admin endpoints work; no policy is
  active by default. Existing surfaces unaffected.
- **After PR-2**: default `join` allows; existing
  join-request submit flow continues to work because the
  Phase 1 path stayed authoritative until the policy step
  formally lands. Removal flow likewise. A rejected join
  request now carries a policy-decision payload.
- **After PR-3**: status-list VCs publish; no VMCs reference
  them yet.
- **After PR-4**: approve mints VMC + role VEC; renewal works;
  removal flips the revocation bit. **Gate "Live credentials"
  effectively met here** — the rest is rotation polish.
- **After PR-5**: members can rotate their DIDs.
- **After PR-6**: workspace gate green. Phase 2 closes.

## Risks

- **R1: regorus version churn.** `regorus` is in active
  development; pin a minor + plan to bump deliberately.
- **R2: affinidi-vc API surface.** The data-integrity proof
  shape is well-tested in vta-sdk (provision-integration uses
  it). Reuse the same crate-feature set to minimise duplicate
  config.
- **R3: status-list privacy.** The reserved-index discipline
  (spec §6.2) is load-bearing for privacy. Tests must
  exercise: never reallocate a flipped slot; capacity warning
  fires at 75% live+reserved; index allocation is
  cryptographically random not sequential.
- **R4: did:webvh rotation correctness.** Walking `did.jsonl`
  + verifying prior-key signatures is fiddly. The
  `affinidi-did-resolver-cache-sdk` covers it but its hot path
  isn't well-trodden. Land did:key first to de-risk; did:webvh
  may need its own follow-up PR.
- **R5: policy auth-gating drift.** Once the auth layer
  consumes `role_definitions.rego` (planned Phase 2), the
  Phase 1 AuthClaims-vs-VtcRole degradation is no longer
  workable. Either rewrite AuthClaims to be `VtcRole`-aware
  (broad change), or scope role-policy evaluation to **route
  handlers only** (narrower, defer AuthClaims rewrite to
  Phase 3+). Proposed: route-handler-only Phase 2.
- **R6: signing-surface spec clarification (D1).** Recording it
  as a Phase 2 outcome — §3-A's "no key custody" line gets
  amended to spell out the cached-locally / VTA-controlled
  model (= no key minting / rotation authority, not no key
  storage).

## Definition of done — Phase 2

After M2.19:

- `cargo build/clippy/fmt/test --workspace` clean.
- 9+ new Trust Tasks in `Draft` status with matching `spec.md`
  + `schema.json` files.
- Every Phase 2 milestone marked `[x]` in `phase-2-todo.md`.
- Memory entry `project_vtc_mvp.md` updated with the seven
  pre-impl decisions' as-shipped outcomes.
- Integration tests cover the end-to-end membership lifecycle:
  applicant submits → policy allows → admin approves → VMC +
  VEC sealed-transferred → renewal succeeds → admin removes →
  revocation bit flipped → status-list VC reflects the flip.

Phase 3 (trust-registry + cross-community recognition) can
start after Phase 2's gate merges.

## Spec amendment surface

Recording up front so they're not surprises mid-implementation:

- **§3-A "VTC has no key custody"** — amended per D1 to
  spell out the cached-locally / VTA-controlled model: VTA
  mints + controls the keys; VTC caches a working copy in
  its secret store and signs locally. "No custody" was
  always meant as "no minting / rotation authority", not
  "no key storage" (mediator / webvh-service pattern).
- **§14.2 "VTA signing oracle dependence"** — VTA-oracle
  timeout + breaker stay in the spec but apply to other
  remote dependencies (trust-registry, did:webvh resolver),
  not VMC issuance.
- **§6.2 status-list URL** — confirm the URL the
  `vtc-host` template renders into `#vtc-status-list` is the
  one the VTC daemon serves at
  `GET /v1/status-lists/{purpose}`. Phase 0's template
  uses `{URL}/v1/status-lists` (substring) and the VTC routes
  per-purpose. May need a `{purpose}` in the template's
  service-endpoint URL — flag for M2.11.

Any decision that drifts from the default during
implementation should be recorded in `phase-2-plan.md` under a
"Phase 2 outcome" header (mirror of Phase 1's pattern).
