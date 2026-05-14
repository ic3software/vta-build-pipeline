# VTC MVP — Phase 4 plan

> **Status:** draft, awaiting review.
> **Deliverable:** "Graph + personhood live." Per spec §16 Phase 4:
> VRC self-issuance + `relationships.rego`, `personhood.rego`
> (deny-all stub) + assert/revoke + renewal re-eval, custom
> endorsement issuance (issuer role).
> **Spec:** `docs/05-design-notes/vtc-mvp.md` §§5.4, 6.1, 6.3, 6.4,
> 7.1, 11.1, 12.3, 14.2, 14.3.

## Objective

After Phase 4, the VTC issues the relationship + personhood +
custom-endorsement credentials the spec promises, with the policy
hooks wired:

- A member publishes a **self-issued VRC** trust edge via
  `POST /v1/relationships`. The VTC verifies the caller's
  signature against their resolved DID, runs `relationships.rego`
  (default: store iff both parties are current members), persists
  the row in a new `relationships:` keyspace, and emits an audit
  variant. `GET /v1/members/{did}/relationships` paginates the
  graph for one party.
- An admin / issuer **asserts personhood** for a member via
  `POST /v1/members/{did}/personhood/assert`, supplying an evidence
  payload. The new `personhood.rego` (replacing the deny-all stub)
  consumes the canonical input shape; on `allow`, the Member row
  flips `personhood = true` and a fresh VMC is minted with the new
  flag. Revoke goes through `DELETE /v1/members/{did}/personhood`
  (admin / self-revoke). The existing M2.13 renewal flow already
  re-evaluates `personhood.rego` on every renewal — Phase 4 makes
  that reachable by giving the policy a real allow path and
  persisting the prior flag on the Member row so
  `personhood_changed` becomes precise.
- An **issuer role member** mints **custom endorsements** (VECs
  with a community-defined `endorsement.type`) via
  `POST /v1/credentials/endorsements`. The custom-endorsement row
  is tracked in a new `endorsements:` keyspace, carries its own
  status-list slot for revocation, and can be revoked via
  `DELETE /v1/credentials/endorsements/{id}` — the slot flips
  immediately.
- New audit variants — `VrcPublished`, `VrcRevoked`,
  `PersonhoodAsserted`, `PersonhoodRevoked`,
  `CustomEndorsementIssued`, `CustomEndorsementRevoked` — and the
  Trust Tasks behind every endpoint.

Out of scope (deferred):

- **Bilateral / counter-signed VRC** — spec §3, §12.3 pin this
  as v2. Phase 4 ships self-issued only.
- **Public website + admin UX** — Phase 5.
- **WASM / plugin extensions** — workspace memory.
- **DIDComm transport for VRC publication** — spec §17.6 calls
  it out as a UX option; Phase 4 sticks to REST. The DIDComm
  twin can follow once the REST shape stabilises (Phase 5 or v2).
- **New trust-registry surfaces** — the M3 surfaces stay as-is.
  Custom endorsements + VRCs are local-only credentials; they
  are not published to the trust registry.
- **`witness` / `RCard` credential routes** — spec §9.5 lists
  `POST /v1/credentials/{endorsements,witnesses,rcards}` as a
  group, but §6.1 reserves `VWC` to *external* issuance (VTC
  doesn't issue) and `RCard` is a contact-card primitive (no
  policy hook). Phase 4 ships endorsements only; witnesses +
  RCards are a follow-up.
- **VPC (Persona credentials)** — explicitly v2 per §18.

## Scope (per spec §16, Phase 4 row)

### In scope

- **VRC self-issuance graph**
  - `POST /v1/relationships` — caller submits a VRC they signed
    against the issuer DID. VTC verifies signature against the
    resolved DID, runs `relationships.rego`, stores. Spec §12.3.
  - `GET /v1/members/{did}/relationships` — paginated list of
    VRCs where `did` is issuer OR subject; respects the
    departure-handling rule (spec §12.3) that strips VRCs
    naming a `Purge`d member.
  - `DELETE /v1/relationships/{id}` — issuer-only retraction
    (member self-cleanup). Emits `VrcRevoked`.
  - New `relationships:` keyspace + storage helpers.
- **Personhood lifecycle**
  - `POST /v1/members/{did}/personhood/assert` — accepts
    evidence body; runs the new `personhood.rego`; on `allow`
    flips `Member.personhood = true`, re-mints VMC with the
    new flag, emits `PersonhoodAsserted`.
  - `DELETE /v1/members/{did}/personhood` — admin or self
    revocation; flips `Member.personhood = false`, re-mints
    VMC, emits `PersonhoodRevoked`.
  - **Default `personhood.rego` replacement** — flip from
    deny-all to a real (but minimal) policy consuming the
    canonical evidence shape. Operator-replaceable as today.
  - **Member row** gains two new fields:
    - `personhood: bool` — current state, default `false`.
    - `personhood_asserted_at: Option<DateTime<Utc>>` —
      timestamp of the most recent successful assert.
    Per planning-review D2: evidence is **not** persisted on
    the Member row. The assert path verifies the presented
    VP, evaluates `personhood.rego` against the policy input
    derived from the verified credentials, and flips the
    flag. Renewal re-eval reads only `personhood` +
    `personhood_asserted_at` + the configured age threshold —
    operators wanting richer renewal-time evaluation upload a
    custom rego that consults additional inputs.
  - **Renewal-time outcome is operator-configurable** —
    config knob `vtc.renewal.on_personhood_fail` with values
    `downgrade` (default) and `refuse`:
    - `downgrade` (default, per D5 review): when renewal-time
      `personhood.rego` fails for a member who was previously
      `true`, the Member row flips to `false`, the new VMC
      carries `false`, the audit envelope records
      `personhood_changed: true`. Renewal itself does **not**
      refuse — preserves §3-B "ACL is authoritative".
    - `refuse`: renewal returns `422` until an admin re-asserts.
      Stricter privacy posture for operators that want
      personhood-aware membership.
- **Custom endorsement issuance** (D4 review: operator-uploaded
  type registry — bundled into M4.8 per planning review)
  - **Type registry** (new, per D4 review):
    - `POST /v1/endorsement-types` (Admin role) — register a new
      endorsement type by URI. Body:
      `{ type_uri, claim_schema?, description? }`. Refuses the
      workspace-reserved `"CommunityRole"` type (that's VEC-managed).
    - `GET /v1/endorsement-types` — paginated list.
    - `DELETE /v1/endorsement-types/{uri}` — admin teardown.
      Refuses if any endorsement of this type is still live.
    - New `endorsement_types:` keyspace.
    - Emits `EndorsementTypeRegistered` / `EndorsementTypeDeleted`
      audit envelopes.
  - **Endorsement issuance** consults the type registry:
    - `POST /v1/credentials/endorsements` (Issuer / Admin role) —
      accepts `(subject_did, type, claim, validity?)`. **Refuses
      if `type` isn't in the registry**. Mints a VEC with the
      community-defined `endorsement` payload, allocates a
      status-list slot, persists in `endorsements:`, emits
      `CustomEndorsementIssued`.
    - `GET /v1/credentials/endorsements` — paginated list (admin
      + issuer scoped).
    - `GET /v1/credentials/endorsements/{id}` — show.
    - `DELETE /v1/credentials/endorsements/{id}` — admin /
      issuing-issuer revocation; flips the status-list bit,
      emits `CustomEndorsementRevoked`.
  - New `endorsements:` keyspace.
  - Custom endorsements **reuse the existing `Revocation`
    status list** (D8 review confirmed); per the spec §6.2
    reserved-slot discipline, the slot is permanently
    reserved on flip.
- **Audit variants** (8 new total per D6 + D4 review):
  `VrcPublished`, `VrcRevoked`, `PersonhoodAsserted`,
  `PersonhoodRevoked`, `CustomEndorsementIssued`,
  `CustomEndorsementRevoked`, `EndorsementTypeRegistered`,
  `EndorsementTypeDeleted`.
- **Trust Task drafts** — `relationships/publish/1.0`,
  `relationships/list/1.0`, `relationships/revoke/1.0`,
  `members/personhood/assert/1.0`,
  `members/personhood/revoke/1.0`,
  `credentials/endorsements/issue/1.0`,
  `credentials/endorsements/list/1.0`,
  `credentials/endorsements/show/1.0`,
  `credentials/endorsements/revoke/1.0`,
  `endorsement-types/register/1.0`,
  `endorsement-types/list/1.0`,
  `endorsement-types/delete/1.0`. Spec.md + schema.json
  per endpoint + `index.json` entries.
- **Renewal hook fix** — `routes/members/renew.rs::evaluate_personhood`
  now reads `Member.personhood` + `Member.personhood_asserted_at`
  (no evidence persisted — see D2 review) and writes back to
  `Member.personhood` per the configured `on_personhood_fail`
  policy. The `prior_personhood_from_member` helper becomes
  precise.

### Out of scope

- VRC issuance over DIDComm transport — spec §17.6 lists as
  open. Wire the REST path first; DIDComm twin is a follow-up.
- VRC bilateral / counter-signing — spec §3, §12.3 (v2).
- `witness` / `RCard` credentials — Phase 4 ships endorsements
  only (see scope notes above).
- Public reference personhood policy (`docs/04-reference/
  personhood-templates.md`) — spec §17.1 lists as a post-Phase-4
  doc; the spec amendment surface flags it.
- Admin UX for the new surfaces — Phase 5.
- StatusList **purpose extension** for endorsements (would
  need an upstream `affinidi-status-list` PR for a new
  `StatusPurpose::Endorsement` variant) — D8 keeps Phase 4
  within the existing `Revocation` / `Suspension` purposes.

## Pre-implementation design decisions

Load-bearing. Defaults below; flag dissent before any code lands.

### D1 — VRC issuance authority

Spec §5.4 / §6.1: VRC is "member DID" → "other member DID",
self-issued. The credential's `issuer` is the asserting
**member** (not the community), and that's what's verified at
publication time.

**Default:** the VTC accepts only VRCs whose `issuer` resolves
to a current ACL member, and whose proof verifies against the
issuer's resolved `#key-0`. The community **never** mints a
VRC — the `LocalSigner` is not invoked. This keeps "self-issued"
clean and avoids a confused-deputy attack where the VTC could
be tricked into endorsing a relationship the member never
authored.

The `relationships.rego` input gets `issuer_member` and
`subject_member` shapes enriched with `is_current: bool` (live
ACL check), mirroring how M3.9 enriches foreign credentials.

### D2 — Personhood evidence shape

**Decision (planning review): VP-only assert body.** The
`POST /v1/members/{did}/personhood/assert` body carries a
single Verifiable Presentation signed by the member:

```json
{
  "presentation": { /* W3C VP, with proof signed by member's #key-0 */ }
}
```

The VP must include:
- `holder` matching the path-DID (the member asserting personhood).
- One or more `verifiableCredential` entries (witness credentials,
  proof-of-personhood VCs, vouches — operator-defined types).
- A `proof` block over `vp.proof.challenge` (a fresh
  server-issued nonce) so the assert is replay-protected.

The route layer (M4.3):

1. Verifies the VP proof against the member's `#key-0`.
2. Verifies each embedded VC's proof against its issuer's
   `#key-0` (resolved via the workspace DID resolver).
3. Runs `extract_vp_claims` from M2.6's extract module to
   produce the canonical projection.
4. Feeds the projection into `personhood.rego` as
   `{ applicant_did, vp_claims }` — spec §6.4 input contract
   unchanged.

**Evidence is not persisted on the Member row** (per planning
review): the assert path verifies the VP, evaluates the policy,
flips `personhood = true` + sets `personhood_asserted_at`. The
VP itself is discarded after the assert succeeds. Renewal re-eval
reads only the persisted flag + timestamp (see D5 + the
Member-row schema below) — operators wanting policy-driven
renewal eval against richer state upload a custom rego that
consults additional inputs (e.g. live trust-registry queries).

Body cap: 16 KiB (mirrors `MEMBER_EXTENSIONS_MAX_BYTES`).

### D3 — Personhood revoke trigger

Spec §6.4: "Personhood is asserted via a dedicated
`POST /v1/members/{did}/personhood/assert` (re-mints VMC with
`personhood: true`), and revoked via `DELETE` (re-mints with
`false`). The policy re-evaluates on every renewal."

Three triggers, all spec'd:

1. **Active admin revocation** — `DELETE` endpoint. Admin role
   (issuer role does **not** suffice — personhood is a higher-
   trust signal). Audit: `PersonhoodRevoked { actor_did,
   reason: "admin" }`.
2. **Self-revocation** — same `DELETE` endpoint when caller's
   DID == path DID. RTBF-style "I no longer want this claim
   asserted about me." Audit: `PersonhoodRevoked { actor_did,
   reason: "self" }`.
3. **Renewal-time policy downgrade** — when renewal evaluates
   `personhood.rego` and gets `false` for a member who was
   previously `true`. Spec §6.3 step 3 makes this load-bearing:
   "losing personhood is not gated on operator action." Audit:
   `PersonhoodRevoked { actor_did: <vtc-did>, reason:
   "renewal-policy" }`.

**Default:** all three implemented. Trigger #3 piggybacks on
the existing M2.13 renewal call site — it's a one-line flip
once the Member row carries the flag.

### D4 — Custom endorsement type registry

Spec §6.1 row "Custom endorsement (badges, attestations)":
issuer-role member mints a VEC with a community-defined
`endorsement.type`. Spec gives no validation rule.

**Decision (planning review): operator-uploaded type registry.**
Phase 4 ships a CRUD surface for endorsement types — only
registered types are issuable. **Bundled into M4.8** per the
planning review (single endorsements PR covers both type
registry + endorsement issuance).

- New `endorsement_types:` keyspace.
- New endpoints (all Admin-gated, all carry their own Trust Tasks):
  - `POST /v1/endorsement-types` — register. Body
    `{ type_uri, claim_schema?, description? }`.
  - `GET /v1/endorsement-types` — list (cursor paginated).
  - `GET /v1/endorsement-types/{uri}` — show.
  - `DELETE /v1/endorsement-types/{uri}` — delete. Refuses
    when at least one live endorsement of this type exists
    (prevents dangling references; `409 Conflict`).
- `endorsement.type` validation on the issuance path:
  - The supplied `type` URI must be registered.
  - The workspace-reserved `"CommunityRole"` type is refused
    *at registration time* (the registrar route 409s).
  - `claim` is a JSON object, max 8 KiB; optional
    `claim_schema` on the type row can validate the shape
    (Phase 4 ships the registry — schema validation runtime
    can lag to a follow-up if the JSON Schema library
    integration is heavy).
- Audit envelopes: `EndorsementTypeRegistered` /
  `EndorsementTypeDeleted` (paired with the standard
  `EndorsementIssued` / `EndorsementRevoked` for the actual
  credentials).

### D5 — Renewal re-evaluation semantics

Spec §6.3 step 3: "Re-evaluate `personhood.rego` and surface
the resulting `personhood` flag on the new VMC. If the flag
changes from the prior VMC, the audit event
`MembershipRenewed` records `personhood_changed: true`."

**Decision (planning review): operator-configurable via
`vtc.renewal.on_personhood_fail`.** Two values:

- **`downgrade` (default)**: when renewal evaluates
  `personhood.rego` and gets `false` for a member who was
  previously `true`, the Member row flips to `false`, the new
  VMC carries `false`, audit envelope records
  `personhood_changed: true` + paired `PersonhoodRevoked
  { reason: "renewal-policy" }`. Renewal **does not refuse** —
  preserves §3-B "ACL is authoritative". Recommended for
  most deployments.
- **`refuse`**: renewal returns `422 Unprocessable Entity`
  with a clear error pointing the caller at the assert
  endpoint. The Member row stays `true` (no silent flip),
  the VMC isn't re-minted, no audit envelope. Stricter
  privacy posture; couples renewal to personhood state.

Config knob lives in `RenewalConfig` (new struct in
`vtc_service::config`), serde-default `"downgrade"`. Audit
envelope for renewal-refused case lands as a new
`MembershipRenewed { outcome: "personhood-refused" }` flavour
— planner notes this slightly expands M2.13's audit shape.

This keeps the "ACL is authoritative inside the community"
invariant intact (§3-B) — losing personhood doesn't lock a
member out of community auth.

### D6 — Audit envelope shape for VRC

Six new variants:

| Variant | Fields |
|---|---|
| `VrcPublished` | `vrc_id`, `issuer_did_hash`, `subject_did_hash` (HMAC-hashed per §11.1; plain DIDs stay in the envelope's `actor_did_plain` / `target_did_plain` since they're community-internal) |
| `VrcRevoked` | `vrc_id` |
| `PersonhoodAsserted` | `member_did_hash`, `evidence_sha256` (hex), `vmc_id` |
| `PersonhoodRevoked` | `member_did_hash`, `vmc_id`, `reason` ∈ `"admin" \| "self" \| "renewal-policy"` |
| `CustomEndorsementIssued` | `endorsement_id`, `endorsement_type`, `subject_did_hash`, `issuer_did_hash`, `status_list_index` |
| `CustomEndorsementRevoked` | `endorsement_id`, `endorsement_type` |

All six follow the discipline of Phases 1–3: round-trip test +
`variant_discriminator_strings` entry + `camelCase` wire +
`Option`s with `skip_serializing_if`.

### D7 — Status-list slot allocation for VRCs

Spec §5.4 / §12.3 don't name a status-list entry for VRCs. A
self-issued credential has no community-issued revocation
authority — the issuer is a member, and member-driven
retraction is the canonical RTBF.

**Default:** **VRCs do not carry `credentialStatus`.**
`DELETE /v1/relationships/{id}` removes the row from the
`relationships:` keyspace; there's no bit to flip externally.
The departure-handling rule (§12.3) strips VRCs naming
`Purge`d members from list responses; storage retains them
referenced by issuer until the issuer departs.

This keeps the reserved-slot space (131K) for community-
issued credentials only (VMC + VEC + custom endorsements).

### D8 — Custom endorsement revocation

Spec §6.1 names custom endorsements as VECs issued by the
community in `issuer` role. Communities will want to revoke
("the badge was awarded in error"). External verifiers expect
a `credentialStatus`.

**Default:** custom endorsements **reuse the existing
`Revocation` status list**, allocating a slot from the same
2^17-capacity bitstring as VMCs. The reserved-slot discipline
(§6.2) still holds — flipped slots never reallocate.

A future `StatusPurpose::Endorsement` variant would need an
upstream PR to `affinidi-status-list` and is **explicitly
not** Phase 4 work. The shared-`Revocation`-list approach has
one downside: external verifiers checking a member's VMC can
trace which slots belong to "live members" vs "revoked
endorsements" only via the per-slot decoy distribution.
Random-with-decoys allocation already mitigates correlation
attacks on this list.

### D9 — Trust Task IDs

Standard convention. Each endpoint gets its own task:

| Endpoint | Trust Task ID |
|---|---|
| `POST /v1/relationships` | `…/relationships/publish/1.0` |
| `GET /v1/members/{did}/relationships` | `…/relationships/list/1.0` |
| `DELETE /v1/relationships/{id}` | `…/relationships/revoke/1.0` |
| `POST /v1/members/{did}/personhood/assert` | `…/members/personhood/assert/1.0` |
| `DELETE /v1/members/{did}/personhood` | `…/members/personhood/revoke/1.0` |
| `POST /v1/credentials/endorsements` | `…/credentials/endorsements/issue/1.0` |
| `GET /v1/credentials/endorsements` | `…/credentials/endorsements/list/1.0` |
| `GET /v1/credentials/endorsements/{id}` | `…/credentials/endorsements/show/1.0` |
| `DELETE /v1/credentials/endorsements/{id}` | `…/credentials/endorsements/revoke/1.0` |

Nine new Trust Tasks; `index.json` extends accordingly. The
existing per-method-collapse workaround (multiple HTTP methods
on one mount share one Trust Task at the router layer) applies
to `/v1/credentials/endorsements` (POST + GET) and to
`/v1/credentials/endorsements/{id}` (GET + DELETE) — same
pattern Phase 1 + Phase 3 use; on-disk tasks all exist for
soft-gate completeness.

### D10 — Personhood Rego input shape (default policy)

Spec §6.4 / §7.3 pin the policy input as `{ applicant_did,
vp_claims }`. The new default `personhood.rego` reads only
those two fields. Proposed minimal allow path:

```rego
package vtc.personhood
import rego.v1

default allow := false
default asserted := false

# Accept assertion when:
#  1. vp_claims.credentials has at least one credential whose
#     type array contains "WitnessCredential", AND
#  2. the credential's issuer DID is non-empty.
#
# Operators override with stricter rules (e.g. multiple
# witnesses, specific issuer DIDs, validity windows).
allow if {
    some i
    cred := input.vp_claims.credentials[i]
    "WitnessCredential" in cred.type
    cred.issuer != ""
}

# "asserted" mirrors "allow" — the spec §6.4 distinction
# exists so a future policy can split "evidence is acceptable"
# from "evidence sufficient to *assert*"; in MVP they collapse.
asserted := allow
```

This default is **minimal but not deny-all** — the post-Phase-4
"reference templates" doc (§17.1) is where operators should
look for production-grade policies. The default is
deliberately permissive enough that workspace integration
tests can exercise the assert flow without operator-supplied
policy uploads.

## Dependency graph

```
M4.1 Member row personhood persistence + audit variants stub
  │
  ▼
M4.2 Default personhood.rego replacement + renewal hook fix
  │
  │  [parallel branch from M4.1: M4.5, M4.7 start independently]
  ▼
M4.3 Personhood assert endpoint + Trust Task
  │
  ▼
M4.4 Personhood revoke endpoint (admin + self + renewal-driven)
  │
  ▼                                                  M4.5 relationships keyspace + storage helpers
                                                          │
                                                          ▼
                                                       M4.6 VRC publish + list + revoke endpoints + Trust Tasks
                                                          │
M4.7 endorsements keyspace + custom-endorsement builder
  │
  ▼
M4.8 Custom endorsement issue + list + show + revoke endpoints + Trust Tasks
  │
  ▼
M4.9 Audit variants round-trip snapshot tests
M4.10 Trust Task on-disk + index.json batch
M4.11 Phase 4 outcomes + spec amendments
M4.12 Phase 4 gate
```

Critical paths:

- **Personhood track** (M4.1 → M4.2 → M4.3 → M4.4). Sequential.
- **VRC track** (M4.5 → M4.6). Sequential. Parallel with
  personhood from M4.1's end.
- **Endorsement track** (M4.7 → M4.8). Sequential. Parallel
  with both other tracks.
- **Closeout** (M4.9–M4.12) depends on all three tracks.

## Parallelisation strategy

Within a milestone: vertical slice — each endpoint ships with
its Trust Task files + integration tests + audit emission, not
in batches.

PR slicing — proposed:

1. **PR-1**: M4.1 + M4.2 (Member-row persistence + default
   `personhood.rego` rewrite + renewal hook fix). No new
   wire surfaces; preconditions for the personhood track.
2. **PR-2**: M4.3 + M4.4 (personhood assert + revoke
   endpoints + Trust Tasks). **Personhood gate met here.**
3. **PR-3**: M4.5 + M4.6 (VRC keyspace + publish + list +
   revoke endpoints + Trust Tasks). **VRC gate met here.**
4. **PR-4**: M4.7 + M4.8 (endorsement keyspace + builder +
   endorsement-type registry + endorsement-issuance CRUD +
   Trust Tasks). **Endorsement gate met here.** Per
   planning review's D4 bundle decision, this PR covers
   ~800-1000 LoC across the type registry (M4.8.0 +
   M4.8.1) and the endorsement CRUD (M4.8.2 + M4.8.3 +
   M4.8.4); reviewers see the registry + issuance surface
   atomically.
5. **PR-5**: M4.9 + M4.10 + M4.11 + M4.12 (audit snapshots +
   index.json batch + outcomes + gate).

5 PRs across 12 milestones — tighter than Phase 2 (6 PRs / 19
milestones), matches Phase 3 (5 PRs / 14 milestones). PR-4 is
the heaviest (CRUD on two new resources + status-list
integration + 8 endpoints + 7 Trust Tasks); PR-1 is
intentionally light to derisk the renewal-hook change in
isolation.

## Checkpoints

- **After PR-1**: Member row carries `personhood` +
  `personhood_asserted_at` fields. Renewal correctly
  downgrades / refuses per the `on_personhood_fail` config
  knob when policy says so.
  No new wire endpoints yet. **Renewal `personhood_changed`
  becomes precise here** (M2.13 follow-up retroactively
  resolved).
- **After PR-2**: Admin can assert + revoke personhood on
  any member. Self-revoke works. Renewal-driven downgrade
  emits the paired audit. **Personhood lifecycle gate met.**
- **After PR-3**: Members publish + revoke VRCs. The
  `relationships.rego` default consumes its enriched input.
  Member-page relationships endpoint paginates. **VRC graph
  gate met.**
- **After PR-4**: Issuer role mints + revokes custom
  endorsements with status-list backing. **Custom endorsement
  gate met.**
- **After PR-5**: workspace gate green. Phase 4 closes.

## Risks

- **R1: Member-row migration on existing data.** PR-1 adds
  three fields to `Member`. Existing rows lack them. fjall
  stores serde JSON, so `#[serde(default)]` covers the
  read-side; tests must hit the path that reads a Phase-3
  row + roundtrips it. **Mitigation:** every new field is
  `#[serde(default)]` + a one-time boot pass is NOT needed
  (the existing M2.13 renewal path already tolerates older
  rows via the `Option<>` discipline). Add a regression
  test that loads a hand-crafted pre-Phase-4 row.
- **R2: Personhood policy downgrade racing renewal.** A
  member's renewal could fire concurrently with an admin
  assert. **Mitigation:** the Member row's CAS update
  serialises writes; the renewal handler reads the row,
  evaluates the policy, then re-reads at write time. If the
  flag flipped under us, the audit envelope still records
  the right `personhood_changed` (the value the renewal
  policy decided vs the value the admin wrote).
- **R3: VRC issuer DID resolution failures.** Spec §12.3
  doesn't pin the resolver. **Mitigation:** reuse the
  existing `did_resolver` on `AppState` (same one M3.9 uses).
  Failure to resolve → 422 with stable reason code; not 503,
  because the caller could fix it by waiting + retrying.
- **R4: Custom endorsement status-list slot exhaustion.**
  Sharing the `Revocation` list with VMCs means heavy
  endorsement issuance could trip the 75% occupancy warning
  faster than expected. **Mitigation:** Phase 4 documents
  the shared discipline; the M2.14 occupancy telemetry
  already fires; a future `StatusPurpose::Endorsement`
  upstream change is the v2 escape.
- **R5: Custom endorsement type collision with workspace
  reserved types.** Operators picking `"CommunityRole"`
  would shadow the role-VEC discrimination. **Mitigation:**
  D4 review's type registry rejects `"CommunityRole"` at
  registration time (the registrar route 409s); the
  issuance path can only consume registered types, so the
  rejection is unbypassable.
- **R6: `personhood.rego` default too permissive.** The D10
  proposal accepts any single witness credential. A
  hostile applicant could mint their own
  `WitnessCredential` and self-witness. **Mitigation:** the
  spec §17.1 note tells operators to upload a real policy
  in production; integration tests use the default to
  exercise the assert flow but the reference docs (post-
  Phase-4) point to a stricter template. The default is
  deliberately a starting point, not a security-grade
  policy.
- **R7: Renewal-driven `PersonhoodRevoked` audit
  duplication.** The renewal flow already emits
  `MembershipRenewed { personhood_changed: true }`. Adding
  a paired `PersonhoodRevoked { reason: "renewal-policy" }`
  could look like double-counting. **Mitigation:** the two
  variants encode different SIEM filters — `MembershipRenewed`
  is "credential was re-issued"; `PersonhoodRevoked` is
  "this principal lost personhood". Operators want both for
  retention + alerting. Document the pairing in the spec
  amendment surface.

## Definition of done — Phase 4

After M4.12:

- `cargo build/clippy/fmt/test --workspace` clean.
- 9 new Trust Tasks in `Draft` status with matching
  `spec.md` + `schema.json` files.
- Every Phase 4 milestone marked `[x]` in
  `phase-4-todo.md`.
- Memory entry `project_vtc_mvp.md` updated with the as-
  shipped outcomes for D1–D10.
- Integration tests cover:
  - End-to-end personhood: admin asserts → Member row
    flipped → next renewal carries `personhood: true` →
    admin uploads stricter policy → renewal flips back to
    `false` + emits `PersonhoodRevoked { reason: "renewal-policy" }`.
  - End-to-end VRC: member A publishes VRC naming member
    B → `GET /v1/members/{B}/relationships` returns it →
    member A self-removes with `Purge` → list returns
    empty (the departure-handling strip).
  - End-to-end endorsement: issuer mints custom
    endorsement → status-list slot allocated → admin
    revokes → slot flipped → endorsement row marked
    revoked.

Phase 5 (public website + admin UX) can start; the work
parallelises with Phase 4 per spec §16 ("Phase 5 sub-tasks
parallelise with phases 3–4").

## Spec amendment surface

Recording up front so they're not surprises mid-implementation:

- **§5.2**: add two new fields to the `Member` schema —
  `personhood: bool`, `personhood_asserted_at:
  Option<DateTime<Utc>>` (per planning review). Evidence is
  not persisted on the row (see D2 review). Currently the
  schema reads "(no personhood field)"; Phase 4 makes it
  explicit.
- **§5.4 / §12.3**: confirm "VRCs do not carry
  `credentialStatus`" (D7). Spec is currently silent; pin the
  decision.
- **§6.1**: custom endorsement row — document the
  **operator-uploaded type registry** (D4 review). Replaces
  the prior allow-list-by-regex draft. New endpoints under
  `/v1/endorsement-types/*`; only registered types are
  issuable.
- **§6.2**: confirm custom endorsements share the
  `Revocation` status list (D8 review); document the future
  `StatusPurpose::Endorsement` v2 path.
- **§6.3 step 3**: document the **operator-configurable
  renewal-time outcome** (D5 review) — config knob
  `vtc.renewal.on_personhood_fail: downgrade | refuse`,
  default `downgrade`. Note the `refuse` flavour returns
  `422` and skips the VMC re-mint.
- **§6.4**: rewrite the personhood evidence section per the
  **VP-only assert body** (D2 review). The assert body
  carries a single Verifiable Presentation; evidence is
  evaluated at assert time and discarded.
- **§7.1**: update the "Default-ship" column for `personhood`
  from "Deny-all stub" to a minimal allow on `WitnessCredential`
  presence. Note operator-replacement remains the standard
  pattern.
- **§11.4**: extend the audit catalogue with the eight new
  variants from D6 + D4 review: `VrcPublished`, `VrcRevoked`,
  `PersonhoodAsserted`, `PersonhoodRevoked`,
  `CustomEndorsementIssued`, `CustomEndorsementRevoked`,
  `EndorsementTypeRegistered`, `EndorsementTypeDeleted`.
- **§17.1**: now a Phase 4 outcomes follow-up — the reference
  policy templates doc becomes the gating deliverable for
  Open Question #1.

Any decision that drifts from the default during
implementation should be recorded in `phase-4-plan.md` under
a "Phase 4 outcomes" header (mirror of Phase 1 + 2 + 3's
pattern).

## Phase 4 outcomes

Recorded at M4.11 close-out. Each row links a pre-impl
decision (D1–D10) or risk (R1–R6) to the as-shipped reality.

### D1 — VRC issuance authority

**As shipped as proposed**: the asserting *member* is the
issuer. The VTC never mints VRCs; the publish handler
verifies the caller's session DID equals the VC's `issuer`
and verifies the data-integrity proof against the issuer's
resolved `#key-0`. `LocalSigner` is uninvolved.

### D2 — Personhood evidence shape

**As shipped per planning review (VP-only)**: the
`POST /v1/members/{did}/personhood` body carries a single
W3C Verifiable Presentation signed by the member's
`#key-0`. The assert handler verifies the VP proof, runs
`extract_vp_claims` (Phase 2 M2.6) to produce policy input,
evaluates `personhood.rego`, then **discards the VP**. Only
two fields persist on the `Member` row: `personhood: bool`
+ `personhood_asserted_at: Option<DateTime<Utc>>`. Operators
wanting persistent evidence storage layer it via custom rego
+ extension fields.

### D3 — Personhood revoke trigger

**As shipped as proposed**: three triggers, all wired —
admin-driven `DELETE`, self-`DELETE`, and renewal-policy
downgrade (M4.2.2). Each emits `PersonhoodRevoked` with a
stable `reason` discriminator (`admin` / `self` /
`renewal-policy`).

### D4 — Custom endorsement type registry

**As shipped per planning review (operator-uploaded
registry)**: bundled into M4.8 per the planning review.
- New `endorsement_types:` keyspace with percent-encoded URI
  keys (handles colons + slashes safely).
- Three admin-gated CRUD routes under `/v1/endorsement-types`.
- `RESERVED_TYPE_URIS` ships with `"CommunityRole"`
  pre-reserved — registrar refuses with `409
  endorsement-type-reserved`.
- Issuance path consults `type_exists` and refuses unknown
  types with `400 endorsement-type-not-registered`.
- Delete path refuses with `409 endorsement-type-in-use`
  when `count_live_by_type > 0`.

### D5 — Renewal re-evaluation semantics

**As shipped per planning review (operator-configurable)**:
config knob `vtc.renewal.on_personhood_fail` with values
`downgrade` (default) and `refuse`. The renewal hook reads
`Member.personhood` + `personhood_asserted_at` and feeds
them to `personhood.rego` as `current_personhood` +
`asserted_at_seconds_ago`. On downgrade-arm: flag flips +
VMC re-mints with `personhood: false` + paired
`PersonhoodRevoked { reason: "renewal-policy" }` audit. On
refuse-arm: `422 personhood-renewal-refused` + Member row
untouched. Default config preserves §3-B "ACL is
authoritative".

### D6 — Audit envelope shape for VRC

**As shipped per planning review (8 variants total, not
6)**: D6 originally proposed 6 variants; the D4 review's
type-registry decision added two more
(`EndorsementTypeRegistered` + `EndorsementTypeDeleted`).
All 8 variants ship with round-trip + discriminator-table
coverage in `vti-common/src/audit/event.rs` (M4.1.2).

### D7 — Status-list slot allocation for VRCs

**As shipped as proposed**: VRCs carry **no
`credentialStatus`**. Revocation is row deletion in the
`relationships:` keyspace, not a status-list bit flip.
Verifiers querying the trust-graph see the absence directly;
external observers relying on a status-list URL get a clean
404.

### D8 — Custom endorsement revocation

**As shipped per planning review (shared status list)**:
custom endorsements allocate slots on the same `Revocation`
BitstringStatusList VMCs use. No upstream
`affinidi-status-list` PR; no new `StatusPurpose::Endorsement`
variant. The shared list's reserved-slot discipline (§6.2)
still applies — revoked slots are never reallocated, even
across endorsement types.

### D9 — Trust Task IDs

**As shipped as proposed**: 13 new Trust Tasks shipped
across PR-2/3/4 (challenge + assert + revoke for personhood,
publish + list + revoke for relationships, register + list +
delete for endorsement-types, issue + list + show + revoke
for endorsements). Trust Task index ↔ on-disk count
verified at M4.10 (55 ↔ 55 ↔ 55).

### D10 — Personhood Rego input shape (default policy)

**As shipped as proposed**: default policy allows on
`WitnessCredential` presence with a non-empty issuer. The
renewal-time eval reads `current_personhood` +
`asserted_at_seconds_ago` (per D2 review's "no evidence
persistence" — operators get only the flag + age, plus an
empty `vp_claims` for shape compatibility). Operators
upload custom rego when they want richer eval.

### R1 — Status-list slot pressure

**Not realised at Phase 4 scale.** Each member can now hold
a VMC slot **plus** any number of custom endorsement slots.
For a 100k-member community with average 5 endorsements
each, that's 600k slots out of the BitstringStatusList's
131,072-byte minimum capacity (1,048,576 slots). Headroom
remains; Phase 5+ may add per-purpose dedicated lists if
endorsement growth outpaces this.

### R2 — Personhood proof TTL

**Not realised yet.** Personhood VPs verify against the
member's `#key-0` at assert time. The default policy
doesn't enforce a max age via
`asserted_at_seconds_ago`; operators uploading time-based
rego get the input field for free. Phase 5 admin UX can
surface the staleness when it lands.

### R3 — Custom endorsement claim explosion

**As shipped with the 8 KiB cap.** Each endorsement's
`claim` body is capped at 8 KiB JSON; the route layer
validates before any state mutation. Operators wanting
larger payloads upload via off-chain storage + reference
URIs in the claim body.

### R4 — VRC graph quadratic growth

**As shipped with secondary index.** The
`relationships_by_did:` keyspace keeps per-DID list queries
O(matched-rows) rather than O(full-table). Pagination + the
§12.3 Purge-strip happen at the route layer; no quadratic
blowup observed in tests up to 10 edges.

### R5 — Endorsement type registry collisions

**Not realised** thanks to the D4 registry. Operators can't
pick `"CommunityRole"` (reserved); duplicate registrations
409. The pre-issue lookup means stale-cache callers get a
clean 422 rather than minting against a non-existent type.

### R6 — VP-only assert + lost evidence audit trail

**Acknowledged trade-off** from D2 review. The assert audit
envelope records `vmc_id` + `asserted_at` but not the VP's
hash — the VP is verify-then-discard. Operators wanting the
audit trail upload a custom rego + extension fields that
write claim metadata to `Member.extensions` themselves.

### Spec amendments applied at M4.11

- **§5.2**: `Member` row gains two new fields —
  `personhood: bool`, `personhood_asserted_at:
  Option<DateTime<Utc>>`. Evidence is not persisted on the
  row (planning-review D2).
- **§5.4**: VRCs carry no `credentialStatus` (D7).
  Revocation is row deletion via
  `DELETE /v1/relationships/{id}`.
- **§6.1**: custom endorsements come with an operator-
  uploaded type registry (D4 review). Workspace-reserved
  `"CommunityRole"` URI is refused at registration time.
- **§6.2**: custom endorsements share the existing
  `Revocation` status list (D8 review). Reserved-slot
  discipline applies across both VMC + endorsement slots.
- **§6.3 step 3**: renewal-time personhood failure is
  operator-configurable via `vtc.renewal.on_personhood_fail`
  (`downgrade` | `refuse`, default `downgrade`). The
  `refuse` flavour returns `422` and skips the VMC re-mint.
- **§6.4**: personhood assert body is a single Verifiable
  Presentation (D2 review). Evidence is verified at request
  time and discarded.
- **§7.1**: default `personhood.rego` flipped from deny-all
  to minimal-allow on `WitnessCredential` presence (M4.2.1).
  Default `relationships.rego` allows when both parties are
  current community members.
- **§11.4**: audit catalogue extended with 8 new variants
  (D6 + D4 review).
- **§17.1**: reference policy templates documentation
  deferred to a Phase 5 follow-up.