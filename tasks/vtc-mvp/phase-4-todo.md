# Todo: VTC MVP — Phase 4

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Spec: `docs/05-design-notes/vtc-mvp.md` §§5.2, 5.4, 6.1, 6.3, 6.4,
7.1, 11.1, 12.3, 14.2, 14.3.
Plan: `tasks/vtc-mvp/phase-4-plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR —
soft gate per spec §9.4. Trust Task IDs per plan §D9.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`.

---

## M4.1 — Member row personhood persistence + audit variant stubs

### `[x]` M4.1.1 — Extend `Member` with personhood state

- **Acceptance**
  - `vtc_service::members::Member` gains **two** fields, both
    `#[serde(default)]` (per planning review of D2):
    - `personhood: bool` (default `false`).
    - `personhood_asserted_at: Option<DateTime<Utc>>` (default
      `None`).
  - **Evidence is not persisted on the Member row** (D2 review:
    VP-only assert body; evidence is verified at assert time
    and discarded).
  - `Member::fresh` writes the new fields with defaults
    (`false`, `None`).
  - `routes/members/read.rs::MemberSummary` surfaces
    `personhood` (only) in the response — `personhood_asserted_at`
    is operator-private.
  - Regression test: load a hand-crafted JSON row from
    pre-Phase-4 (no `personhood` field) → round-trips +
    field reads as `false`.
- **Verify** 4 unit tests:
  - `Member::fresh()` carries defaults.
  - Round-trip serialise/deserialise.
  - Backward-compat: hand-crafted pre-Phase-4 JSON deserialises.
  - `MemberSummary` exposes `personhood` but not asserted-at.
- **Files**
  - `vtc-service/src/members/mod.rs`
  - `vtc-service/src/routes/members/read.rs`
- **Deps**: none
- **Pre-impl decision**: **D2** (planning-review VP-only assert).

### `[x]` M4.1.2 — Audit variant stubs (no emitters yet)

- **Acceptance**
  - **Eight** new variants added to
    `vti_common::audit::event::AuditEvent` (D6 + D4 review):
    `VrcPublished`, `VrcRevoked`, `PersonhoodAsserted`,
    `PersonhoodRevoked`, `CustomEndorsementIssued`,
    `CustomEndorsementRevoked`, `EndorsementTypeRegistered`,
    `EndorsementTypeDeleted`.
  - Per-variant data structs (`VrcPublishedData`, etc.) with
    `#[serde(rename_all = "camelCase")]`,
    `Option<T> + skip_serializing_if`. Eight structs total.
  - **No call sites yet** — emitters land alongside their
    endpoints (M4.3, M4.4, M4.6, M4.8).
  - Variants added to `variant_discriminator_strings` table
    so the discriminator panic-test catches typos.
- **Verify** 8 round-trip snapshot tests + the discriminator
  table extension.
- **Files**
  - `vti-common/src/audit/event.rs`
- **Deps**: none
- **Pre-impl decision**: **D6** + **D4** review.

---

## M4.2 — Default `personhood.rego` rewrite + renewal hook fix

### `[x]` M4.2.1 — Replace deny-all stub with minimal-allow default

- **Acceptance**
  - `vtc-service/policies/default/personhood.rego` is
    replaced per plan §D10. New default:
    - `allow := true` iff `input.vp_claims.credentials[_]`
      contains a credential with `"WitnessCredential" in cred.type`
      AND non-empty `issuer`.
    - `asserted := allow`.
  - `policy::default::install_defaults` still ships this
    purpose (existing M2.5 path; no changes needed there).
  - The 4 input contract round-trips in `policy/default.rs`
    `personhood_default_*` tests are **rewritten**:
    - Empty input → deny.
    - VP with no `WitnessCredential` → deny.
    - VP with `WitnessCredential` + empty issuer → deny.
    - VP with `WitnessCredential` + non-empty issuer → allow.
- **Verify** 4 rewritten unit tests in `policy/default.rs`.
- **Files**
  - `vtc-service/policies/default/personhood.rego`
  - `vtc-service/src/policy/default.rs` (test rewrites)
- **Deps**: M4.1.1
- **Pre-impl decision**: **D10** (default policy shape).

### `[x]` M4.2.2 — Renewal hook reads Member.personhood

- **Acceptance**
  - `routes/members/renew.rs::evaluate_personhood` feeds
    `personhood.rego` an input drawn from the Member's
    current state (per D2 review: evidence is not persisted):
    ```json
    { "applicant_did": "<did>",
      "current_personhood": <member.personhood>,
      "asserted_at_seconds_ago": <now - member.personhood_asserted_at | null>,
      "vp_claims": { "holder": "<did>", "credentials": [] } }
    ```
    The `vp_claims` block is empty by default — operators
    needing richer renewal-time eval upload a custom rego.
  - `prior_personhood_from_member` reads
    `member.personhood` (now precise, not always-`false`).
  - New config knob `vtc.renewal.on_personhood_fail`
    (`downgrade` | `refuse`, default `downgrade`) gates the
    failure arm (D5 review).
  - When `personhood_changed` flips `true → false` at
    renewal time:
    - **`downgrade` (default)**: `member.personhood = false`,
      `member.personhood_asserted_at = None`. Re-mint VMC
      with `personhood: false`. Paired `PersonhoodRevoked
      { actor_did: <vtc-did>, reason: "renewal-policy", vmc_id }`
      audit alongside the existing `MembershipRenewed`.
    - **`refuse`**: return `422 Unprocessable Entity` with
      stable reason `personhood-renewal-refused`. Member row
      stays `true`; no VMC re-mint; no audit envelope (the
      operator chose this path; not surprising). Caller
      retries via `POST .../personhood/assert`.
  - When `personhood_changed` flips `false → true` at
    renewal time (rare — the policy allows on a stale
    state): **no paired** `PersonhoodAsserted` emitted. The
    renewal path doesn't carry an actor intent; the
    existing `MembershipRenewed { personhood_changed: true }`
    is sufficient. (Documented in code comment.)
- **Verify** 6 integration tests:
  - Renewal with `personhood: false` → flag stays `false`.
  - Renewal with `personhood: true` matching new default →
    flag stays `true`.
  - Renewal under a stricter operator policy + default
    `downgrade` → flag flips to `false` + paired
    `PersonhoodRevoked` audit + renewal succeeds.
  - Renewal under stricter policy + `refuse` config →
    `422 personhood-renewal-refused` + Member row unchanged
    + no audit envelope.
  - Renewal preserves `personhood_asserted_at` when flag
    stays `true`.
  - Renewal clears `personhood_asserted_at` when flag flips
    to `false` (downgrade arm).
- **Files**
  - `vtc-service/src/routes/members/renew.rs`
  - `vtc-service/src/config.rs` (new `RenewalConfig`)
- **Deps**: M4.1.1, M4.1.2, M4.2.1
- **Pre-impl decision**: **D3** (renewal-policy revoke
  trigger), **D5** review (operator-configurable outcome).

---

## M4.3 — `POST /v1/members/{did}/personhood/assert`

### `[x]` M4.3.1 — Personhood assert endpoint

- **Acceptance**
  - `POST /v1/members/{did}/personhood/assert` — handler in
    `vtc-service/src/routes/members/personhood.rs` (new).
  - **Auth**: `AdminAuth` OR `IssuerAuth` (admin + issuer
    roles per spec §5.3 "Issue VEC / VWC / RCard"). The
    spec's permission matrix doesn't list personhood
    explicitly — plan §D3 maps it to the issuer tier.
  - **Body** (D2 review — VP-only):
    ```json
    {
      "presentation": { /* W3C VP, holder == path-did,
                            proof signed by member's #key-0 */ }
    }
    ```
    Cap 16 KiB; reject larger bodies with 413.
  - **Challenge requirement**: the VP's
    `proof.challenge` must equal a fresh server-issued
    nonce from a paired `POST /v1/members/{did}/personhood/challenge`
    endpoint (10-minute TTL, single-use). Refuses replay.
  - **Flow**:
    1. Resolve target DID → load Member row (404 if absent).
    2. Consume + verify the challenge.
    3. Verify the VP proof against the member's `#key-0`
       (resolved via the workspace DID resolver). Refuse on
       proof failure with `403 personhood-proof-invalid`.
    4. For each embedded `verifiableCredential`, verify its
       proof against the issuer's `#key-0`. Refuse on any
       failure with `403 personhood-evidence-invalid`.
    5. Run `extract_vp_claims` (M2.6's extractor) to produce
       the canonical projection.
    6. Run `personhood.rego` with
       `{ applicant_did: target, vp_claims: <projection> }`.
       On `deny` → `403 personhood-policy-denied`.
    7. Write Member row: `personhood = true`,
       `personhood_asserted_at = now`.
       **Evidence (the VP itself) is not persisted** per
       D2 review — discarded after the verify+evaluate.
    8. Re-mint VMC + role VEC (same status-list slot;
       reuse `evaluate_personhood` output `true`).
    9. Emit `PersonhoodAsserted { member_did_hash,
       vmc_id, asserted_at }`. Actor on the envelope is
       the caller; target is the member. (No
       `evidence_sha256` field — there's nothing persisted
       to hash, and surfacing a hash from the discarded
       VP would imply persistence.)
  - **Trust Task** `members/personhood/assert/1.0` ships.
    Paired `members/personhood/challenge/1.0` for the
    nonce mint.
  - **Idempotency**: standard `Idempotency-Key` per §9.1;
    same-body retries return the cached response. Note the
    challenge is single-use, so a true retry needs a fresh
    challenge — the idempotency cache provides the
    server-side dedup within the cache TTL.
- **Verify** 6 integration tests:
  - Happy path: admin asserts → Member flag flips → new VMC
    has `personhood: true` → audit envelope emitted.
  - Default policy denial → 403 + no Member-row write.
  - Body too large → 413.
  - Target not found → 404.
  - Idempotent re-assert with same evidence → 200 with the
    same vmc_id (no new VMC minted).
  - Non-admin / non-issuer caller → 403.
- **Files**
  - `vtc-service/src/routes/members/personhood.rs` (new)
  - `vtc-service/src/routes/members/mod.rs`
  - `vtc-service/src/routes/mod.rs` (route attach)
  - `trust-tasks/members/personhood/assert/1.0/{spec.md,schema.json}`
- **Deps**: M4.2.2
- **Pre-impl decision**: **D2** (evidence shape), **D3**
  (admin/issuer auth).

---

## M4.4 — `DELETE /v1/members/{did}/personhood`

### `[x]` M4.4.1 — Personhood revoke endpoint

- **Acceptance**
  - `DELETE /v1/members/{did}/personhood` — handler in
    same `routes/members/personhood.rs`.
  - **Auth**: `AdminAuth` OR caller's session DID matches
    path DID (self-revoke).
  - **Flow**:
    1. Load Member row (404 if absent; 200 no-op if already
       `personhood: false` — idempotent, mirrors
       `Member-not-asserted`).
    2. Write Member row: `personhood = false`,
       `personhood_asserted_at = None`.
    3. Re-mint VMC + role VEC with `personhood: false`.
    4. Emit `PersonhoodRevoked { member_did_hash, vmc_id,
       reason: <"admin" | "self"> }`.
  - **Trust Task** `members/personhood/revoke/1.0` ships.
  - **Idempotency cache TTL**: 60s (destructive op per §9.1).
- **Verify** 4 integration tests:
  - Admin revokes asserted member → flag flips → audit
    `reason: "admin"`.
  - Self-revoke (member calls on own DID) → flag flips →
    audit `reason: "self"`.
  - Revoke when already `false` → 200 no-op.
  - Non-admin revoke of someone else's personhood → 403.
- **Files**
  - `vtc-service/src/routes/members/personhood.rs`
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/members/personhood/revoke/1.0/{spec.md,schema.json}`
- **Deps**: M4.3.1
- **Pre-impl decision**: **D3** (revoke triggers).

### Checkpoint — Personhood gate met

After M4.4.1: admin + self + renewal-driven revocation all
work; assert flips the flag + re-mints; renewal downgrades.

---

## M4.5 — `relationships:` keyspace + storage helpers

### `[ ]` M4.5.1 — Relationships keyspace + Relationship model

- **Acceptance**
  - New keyspace `relationships` registered in
    `server::run` alongside `members_ks`.
  - New module `vtc_service::relationships` with:
    - `Relationship` struct: `id` (Uuid), `issuer_did`,
      `subject_did`, `vrc_jsonld` (the verified VC body),
      `vrc_sha256` (hex), `created_at: DateTime<Utc>`.
    - Storage helpers: `store_relationship`, `get_relationship`,
      `delete_relationship`, `list_for_did(did, cursor, limit)`
      (paginated; returns rows where issuer OR subject = did).
    - Optional secondary index keyspace
      `relationships_by_did:<did>:<id>` for the per-DID
      list query (CAS-paired writes with the primary row).
  - 4 unit tests: round-trip, list-by-issuer, list-by-subject,
    cursor pagination across 10 rows.
- **Files**
  - `vtc-service/src/relationships/mod.rs` (new)
  - `vtc-service/src/relationships/storage.rs` (new)
  - `vtc-service/src/server.rs` (1 new keyspace field +
    boot wiring)
- **Deps**: none (parallel with M4.1+)
- **Pre-impl decision**: **D1** (issuer is the member, not
  the community).

---

## M4.6 — VRC publish + list + revoke endpoints

### `[ ]` M4.6.1 — `POST /v1/relationships`

- **Acceptance**
  - Handler in `vtc-service/src/routes/relationships.rs` (new).
  - **Auth**: `AuthClaims` (any authenticated member).
  - **Body**: `{ vrc: <signed VC body> }`.
  - **Flow**:
    1. Parse the VC; reject malformed bodies (422
       `MalformedVrc`).
    2. Caller's session DID **must equal** the VC's `issuer`
       (self-issued only, per plan §D1). Otherwise 403.
    3. Resolve `issuer_did` via the existing
       `did_resolver`; verify the VC's data-integrity proof
       against the resolved `#key-0`. Failure → 422
       `VrcProofInvalid`.
    4. Look up `is_current` for both issuer + subject (live
       ACL row + non-tombstoned Member row). Build the
       enriched policy input.
    5. Run `relationships.rego` (existing default already
       reads `is_current`). Deny → 403 `RelationshipPolicyDenied`.
    6. Compute `vrc_sha256 = sha256(canonical_json(vrc))`.
       Idempotent: if a relationship with the same hash
       already exists, return its id (200).
    7. Store the row.
    8. Emit `VrcPublished { vrc_id, issuer_did_hash,
       subject_did_hash }`.
  - **Trust Task** `relationships/publish/1.0` ships.
- **Verify** 6 integration tests:
  - Happy path: member A publishes VRC naming member B →
    row stored → audit emitted.
  - Caller != issuer → 403.
  - Tampered proof → 422.
  - One party not a current member → 403 (default policy).
  - Idempotent same-hash re-publish → 200 with same id.
  - Subject DID unresolvable → 422.
- **Files**
  - `vtc-service/src/routes/relationships.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/relationships/publish/1.0/{spec.md,schema.json}`
- **Deps**: M4.5.1, M4.1.2
- **Pre-impl decision**: **D1** (member-as-issuer).

### `[ ]` M4.6.2 — `GET /v1/members/{did}/relationships`

- **Acceptance**
  - Handler in `routes/members/relationships.rs` (new).
  - Cursor pagination per §9.1 (`?cursor=&limit=` clamped
    1..=200).
  - **Departure-handling strip per §12.3**: the response
    excludes any VRC where one party is `Purge`d (i.e., the
    Member row is absent AND the ACL row is absent —
    `Purge` is the only disposition that deletes both).
    Tombstoned + Historical members still appear.
  - **Auth**: any authenticated session can list (matches
    the spec §12.3 "optionally published" + the
    directory.rego default of "DID + role only"); operator
    can tighten via `directory.rego`.
  - **Trust Task** `relationships/list/1.0` ships.
- **Verify** 4 integration tests:
  - List for an issuer → returns issued VRCs.
  - List for a subject → returns received VRCs.
  - List after one party Purge-removes → that VRC stripped.
  - Pagination with 10 rows + limit 3 → 4 pages, last
    `next_cursor: null`.
- **Files**
  - `vtc-service/src/routes/members/relationships.rs` (new)
  - `vtc-service/src/routes/members/mod.rs`
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/relationships/list/1.0/{spec.md,schema.json}`
- **Deps**: M4.6.1
- **Pre-impl decision**: **D1**.

### `[ ]` M4.6.3 — `DELETE /v1/relationships/{id}`

- **Acceptance**
  - Handler in `routes/relationships.rs`.
  - **Auth**: caller's session DID must equal the row's
    `issuer_did` (issuer-only retraction). Admins can also
    revoke (for moderation).
  - **Flow**:
    1. Load the row (404 if absent).
    2. Auth check.
    3. Delete row + secondary-index entries (CAS).
    4. Emit `VrcRevoked { vrc_id }`.
  - **Trust Task** `relationships/revoke/1.0` ships.
- **Verify** 3 integration tests:
  - Issuer revokes own VRC → row gone + audit.
  - Subject (non-admin) attempts revoke → 403.
  - Admin revokes any VRC → row gone + audit.
- **Files**
  - `vtc-service/src/routes/relationships.rs`
  - `trust-tasks/relationships/revoke/1.0/{spec.md,schema.json}`
- **Deps**: M4.6.1
- **Pre-impl decision**: **D1**.

### Checkpoint — VRC graph gate met

After M4.6.3: members publish + list + revoke VRCs; the
default policy + departure-strip both work.

---

## M4.7 — `endorsements:` keyspace + custom-endorsement builder

### `[ ]` M4.7.1 — Endorsements keyspace + Endorsement model

- **Acceptance**
  - New keyspace `endorsements` registered in `server::run`.
  - New module `vtc_service::endorsements` with:
    - `Endorsement` struct: `id` (Uuid), `endorsement_type`,
      `issuer_did` (community DID), `subject_did`,
      `claim: JsonValue`, `status_list_index: u32`,
      `vec_id`, `created_at`, `revoked_at:
      Option<DateTime<Utc>>`.
    - Storage helpers: `store_endorsement`,
      `get_endorsement`, `list_endorsements(cursor, limit)`,
      `mark_revoked(id, now)`.
  - 3 unit tests: round-trip, list pagination, mark_revoked
    sets timestamp without deleting the row.
- **Files**
  - `vtc-service/src/endorsements/mod.rs` (new)
  - `vtc-service/src/endorsements/storage.rs` (new)
  - `vtc-service/src/server.rs` (1 new keyspace field)
- **Deps**: none (parallel with other tracks)
- **Pre-impl decision**: **D4** review (operator-uploaded
  type registry), **D8** review (shared revocation list).

### `[ ]` M4.7.2 — Custom endorsement VC builder

- **Acceptance**
  - `vtc_service::credentials` extends with
    `custom_endorsement.rs`:
    - `CustomEndorsementParams { subject_did, type,
      claim, status_ref, validity }`.
    - `build_custom_endorsement(signer, params) ->
      VerifiableCredential`.
    - VC `type` array carries `VerifiableEndorsementCredential`
      (same VEC type) — wire-compatible with role VECs.
    - `endorsement` payload: `{ type: <registered>,
      claim: <object>, communityDid: <signer.issuer_did> }`.
  - **Type validation deferred to the route layer** (D4
    review — type registry consultation happens at the
    REST handler, not in the builder, so the builder
    stays a pure transformer). Builder still enforces:
    - `claim` is a JSON object, ≤ 8 KiB.
    - `type` is a non-empty string.
- **Verify** 4 unit tests:
  - Builds + signs + verifies for a sample type.
  - `claim` too large rejected.
  - `claim` not an object rejected.
  - `claim` body present in the credential subject.
- **Files**
  - `vtc-service/src/credentials/custom_endorsement.rs` (new)
  - `vtc-service/src/credentials/mod.rs`
- **Deps**: M4.7.1
- **Pre-impl decision**: **D4** review (type validation in
  route layer via registry).

---

## M4.8 — Endorsement type registry + custom endorsement REST surface

> **Bundled per planning review (D4):** M4.8 covers both the
> operator-uploaded endorsement-type registry **and** the
> endorsement issuance / list / show / revoke endpoints. The
> issuance endpoint consults the registry. ~800-1000 LoC total,
> reviewed atomically.

### `[ ]` M4.8.0 — `endorsement_types:` keyspace + storage

- **Acceptance**
  - New keyspace `endorsement_types` registered in `server::run`.
  - New module `vtc_service::endorsement_types` with:
    - `EndorsementType` struct: `type_uri` (String, primary
      key — URL-encoded into the keyspace key),
      `claim_schema: Option<JsonValue>` (reserved for
      future per-type validation),
      `description: Option<String>`, `created_at`,
      `created_by_did: String`.
    - Storage helpers: `store_type`, `get_type`,
      `list_types(cursor, limit)`, `delete_type`,
      `type_exists` (used by M4.8.2 issuance path).
  - 3 unit tests: round-trip, list pagination, delete.
- **Files**
  - `vtc-service/src/endorsement_types/mod.rs` (new)
  - `vtc-service/src/endorsement_types/storage.rs` (new)
  - `vtc-service/src/server.rs` (new keyspace field)
- **Deps**: none (parallel with other tracks)
- **Pre-impl decision**: **D4** review.

### `[ ]` M4.8.1 — Endorsement type registry endpoints

- **Acceptance** — three endpoints under
  `/v1/endorsement-types`:
  - `POST /v1/endorsement-types` (Admin) — body
    `{ type_uri, claim_schema?, description? }`. Refuses:
    - The workspace-reserved `"CommunityRole"` URI
      (409 `endorsement-type-reserved`).
    - Already-registered URIs (409 `endorsement-type-exists`).
    - Empty / oversized URI (422).
    Emits `EndorsementTypeRegistered`.
  - `GET /v1/endorsement-types` (Admin / Issuer) — cursor
    paginated.
  - `DELETE /v1/endorsement-types/{uri}` (Admin) — refuses
    when at least one **live** endorsement (not yet
    revoked) of this type exists in the `endorsements:`
    keyspace (409 `endorsement-type-in-use`). Emits
    `EndorsementTypeDeleted`.
  - **Trust Tasks** ship: `endorsement-types/register/1.0`,
    `endorsement-types/list/1.0`,
    `endorsement-types/delete/1.0`.
- **Verify** 7 integration tests:
  - Happy register → row persisted + audit.
  - Reserved `"CommunityRole"` rejected.
  - Duplicate URI rejected.
  - Oversized URI rejected.
  - List paginated.
  - Delete with live endorsement → 409.
  - Delete with no live endorsements → row gone + audit.
- **Files**
  - `vtc-service/src/routes/endorsement_types.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/endorsement-types/{register,list,delete}/1.0/...`
- **Deps**: M4.7.1, M4.8.0, M4.1.2
- **Pre-impl decision**: **D4** review.

### `[ ]` M4.8.2 — `POST /v1/credentials/endorsements`

- **Acceptance**
  - Handler in `routes/credentials/endorsements.rs` (new).
  - **Auth**: `AdminAuth` OR caller's ACL role is `Issuer`.
  - **Body**:
    ```json
    {
      "subject_did": "<did>",
      "type": "<community-defined>",
      "claim": { … <= 8 KiB JSON object … },
      "validity_seconds": <optional, default 30d>
    }
    ```
  - **Flow**:
    1. Look up `body.type` in the `endorsement_types:`
       keyspace via `type_exists`. Refuse with `422
       endorsement-type-not-registered` when missing (D4
       review).
    2. Validate `claim` is a JSON object ≤ 8 KiB.
    3. Allocate a slot from the `Revocation` status list
       (shared with VMC slots — D8 review).
    4. Build + sign the custom-endorsement VEC via
       `build_custom_endorsement`.
    5. Persist `Endorsement` row.
    6. Emit `CustomEndorsementIssued { endorsement_id,
       endorsement_type, subject_did_hash, issuer_did_hash,
       status_list_index }`.
    7. **Also emit** `VecIssued` (re-using the existing
       Phase 2 variant) so credential-issuance accounting
       stays uniform.
  - **Trust Task** `credentials/endorsements/issue/1.0`
    ships.
- **Verify** 5 integration tests:
  - Happy path issuer (type registered) → endorsement
    persisted + slot allocated + audit emitted.
  - Admin can issue (auth check).
  - Non-issuer / non-admin → 403.
  - Type NOT registered → 422
    `endorsement-type-not-registered`.
  - Subject DID unresolvable → 422.
- **Files**
  - `vtc-service/src/routes/credentials/mod.rs` (new module)
  - `vtc-service/src/routes/credentials/endorsements.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/credentials/endorsements/issue/1.0/{spec.md,schema.json}`
- **Deps**: M4.7.2, M4.8.1
- **Pre-impl decision**: **D4** review, **D8** review.

### `[ ]` M4.8.3 — `GET /v1/credentials/endorsements` + `GET /{id}`

- **Acceptance**
  - List handler: `AdminAuth` OR `IssuerAuth`. Cursor
    pagination per §9.1.
  - Show handler: same auth.
  - List response includes `revoked: bool` (computed from
    `revoked_at.is_some()`); show response includes the
    full `claim`.
  - **Trust Tasks** `credentials/endorsements/list/1.0`
    and `credentials/endorsements/show/1.0` ship.
- **Verify** 3 integration tests:
  - List 10, paginated by 3.
  - Show by id.
  - Show 404 on unknown id.
- **Files**
  - `vtc-service/src/routes/credentials/endorsements.rs`
  - `trust-tasks/credentials/endorsements/list/1.0/{spec.md,schema.json}`
  - `trust-tasks/credentials/endorsements/show/1.0/{spec.md,schema.json}`
- **Deps**: M4.8.2

### `[ ]` M4.8.4 — `DELETE /v1/credentials/endorsements/{id}`

- **Acceptance**
  - **Auth**: `AdminAuth` OR the original issuer's DID
    (per audit envelope's `actor_did_plain`). Issuer
    self-revocation is the canonical "I awarded this in
    error" path.
  - **Flow**:
    1. Load the row (404 if absent; 200 no-op if already
       revoked).
    2. Flip the `Revocation` status-list bit at
       `row.status_list_index` (immediate, locally — same
       primitive M2.14 uses).
    3. `mark_revoked(id, now)`.
    4. Emit `CustomEndorsementRevoked { endorsement_id,
       endorsement_type }`.
    5. Also emit `StatusListFlipped { purpose: "revocation",
       index, revoked: true }` (reuses existing variant).
  - Idempotency cache TTL: 60s (destructive op).
  - **Trust Task** `credentials/endorsements/revoke/1.0`
    ships.
- **Verify** 4 integration tests:
  - Admin revokes → bit flipped + row marked revoked +
    audit emitted.
  - Issuer self-revokes own endorsement → same outcome.
  - Non-admin / non-original-issuer → 403.
  - Re-revoke already-revoked → 200 no-op (idempotent).
- **Files**
  - `vtc-service/src/routes/credentials/endorsements.rs`
  - `trust-tasks/credentials/endorsements/revoke/1.0/{spec.md,schema.json}`
- **Deps**: M4.8.2, M4.8.3

### Checkpoint — Custom endorsement gate met

After M4.8.4: type registry, issuer issuance, admin/issuer
revocation, status-list backing all live.

---

## M4.9 — Audit variants snapshot tests

### `[ ]` M4.9.1 — Round-trip + discriminator coverage

- **Acceptance**
  - The **eight** Phase 4 audit variants (D6 + D4 review:
    `VrcPublished`, `VrcRevoked`, `PersonhoodAsserted`,
    `PersonhoodRevoked`, `CustomEndorsementIssued`,
    `CustomEndorsementRevoked`,
    `EndorsementTypeRegistered`,
    `EndorsementTypeDeleted`) each gain a round-trip
    snapshot test in `vti-common/src/audit/event.rs`.
  - All eight added to `variant_discriminator_strings`
    coverage table.
- **Verify** `cargo test -p vti-common audit::` passes.
- **Files**
  - `vti-common/src/audit/event.rs`
- **Deps**: M4.3.1, M4.4.1, M4.6.3, M4.8.1, M4.8.4 (last
  endpoints to land their variants)

---

## M4.10 — Trust Task drafts + index

### `[ ]` M4.10.1 — On-disk + index entries

- **Acceptance**
  - **Thirteen** new Trust Task directories per plan §D9 +
    D4 review (added the three `endorsement-types/*` +
    the `members/personhood/challenge/1.0`) with `spec.md`
    + `schema.json`:
    - `relationships/publish/1.0`
    - `relationships/list/1.0`
    - `relationships/revoke/1.0`
    - `members/personhood/challenge/1.0`
    - `members/personhood/assert/1.0`
    - `members/personhood/revoke/1.0`
    - `endorsement-types/register/1.0`
    - `endorsement-types/list/1.0`
    - `endorsement-types/delete/1.0`
    - `credentials/endorsements/issue/1.0`
    - `credentials/endorsements/list/1.0`
    - `credentials/endorsements/show/1.0`
    - `credentials/endorsements/revoke/1.0`
  - `trust-tasks/index.json` carries all thirteen new
    entries.
  - Each Trust Task ID is `exact_matched` at route attach
    in `routes/mod.rs`.
- **Files**
  - All `trust-tasks/{...}/1.0/*` directories above.
  - `trust-tasks/index.json`
- **Deps**: M4.3.1, M4.4.1, M4.6.1, M4.6.2, M4.6.3, M4.8.1,
  M4.8.2, M4.8.3, M4.8.4

---

## M4.11 — Phase 4 outcomes + spec amendments

### `[ ]` M4.11.1 — Document the as-shipped reality

- **Acceptance**
  - `tasks/vtc-mvp/phase-4-plan.md` gains a "Phase 4
    outcomes" header recording the as-shipped reality for
    D1–D10 + any deviations + R1–R7 realisation status.
  - `docs/05-design-notes/vtc-mvp.md` §§5.2 / 5.4 / 6.1 /
    6.2 / 6.3 / 6.4 / 7.1 / 11.4 / 17.1 amended per the
    planning-time spec-amendment surface (see plan).
  - Memory entry `project_vtc_mvp.md` updated.
- **Files**
  - `tasks/vtc-mvp/phase-4-plan.md`
  - `docs/05-design-notes/vtc-mvp.md`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M4.8.4, M4.9.1, M4.10.1

---

## M4.12 — Phase 4 gate

### `[ ]` M4.12.1 — Workspace gate green

- **Acceptance** (mirrors M3.14.1)
  - `cargo build --workspace` green.
  - `cargo test --workspace` green.
  - `cargo clippy --workspace --all-targets -- -D warnings`
    clean.
  - `cargo fmt --check` clean.
  - `trust-tasks/index.json` lists every Phase 4 Trust Task
    with matching on-disk files.
  - Memory entry `project_vtc_mvp.md` updated with the as-
    shipped outcomes for D1–D10.
  - Phase-4-todo milestones all flipped to `[x]`.
- **Verify** CI green on the merge commit.
- **Files**
  - `trust-tasks/index.json`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M4.9.1, M4.10.1, M4.11.1

### Checkpoint — Phase 4 gate met

After M4.12.1: members publish + revoke VRC trust edges,
admin / issuer / self assert + revoke personhood,
issuer-role members mint + revoke custom endorsements with
status-list backing, renewal precisely tracks personhood
state. Phase 5 (public website + admin UX) can proceed
fully (the M3-onwards parallel branch lands its final
sequential dependency here).

---

## Resolved decisions (planning review)

All decisions confirmed before plan PR was opened. Listed
here so they're findable from the todo:

- **D1**: VRC issuer is the asserting *member*, not the
  community. VTC verifies the member's signature against
  the resolved DID; never mints VRCs itself.
- **D2** (planning review): **VP-only assert body**. The
  assert endpoint accepts a single W3C Verifiable
  Presentation signed by the member's `#key-0` with a
  fresh server-issued challenge. Embedded VC proofs are
  verified before policy evaluation. **Evidence is NOT
  persisted** on the Member row — verify-then-discard.
- **D3**: Personhood revoke triggers — three: admin-driven
  `DELETE`, self-`DELETE`, renewal-policy downgrade. All
  three emit `PersonhoodRevoked` with stable `reason`
  discriminators.
- **D4** (planning review): **Operator-uploaded type
  registry**, bundled into M4.8. Only registered types are
  issuable. New CRUD surface under
  `/v1/endorsement-types`. Workspace-reserved
  `"CommunityRole"` URI is refused at registration time.
- **D5** (planning review): Renewal-time personhood
  failure is **operator-configurable** via
  `vtc.renewal.on_personhood_fail` (`downgrade` |
  `refuse`, default `downgrade`). `downgrade` preserves
  §3-B "ACL is authoritative"; `refuse` returns `422` and
  the member must re-assert.
- **D6** (+ D4 review): **Eight** new audit variants
  (`VrcPublished`, `VrcRevoked`, `PersonhoodAsserted`,
  `PersonhoodRevoked`, `CustomEndorsementIssued`,
  `CustomEndorsementRevoked`, `EndorsementTypeRegistered`,
  `EndorsementTypeDeleted`).
- **D7**: VRCs carry **no** `credentialStatus`. Revocation
  is row-deletion via `DELETE /v1/relationships/{id}`.
- **D8** (review confirmed): Custom endorsements reuse the
  existing `Revocation` status list. No upstream
  `affinidi-status-list` PR in MVP.
- **D9**: 13 new Trust Task IDs (D9's 9 + 3 endorsement-
  types + 1 personhood/challenge).
- **D10**: Default `personhood.rego` allows on any VC with
  `"WitnessCredential" in type` + non-empty issuer.
  Reference templates ship post-Phase-4.
- **Member schema** (planning review): two new fields only
  — `personhood: bool`, `personhood_asserted_at:
  Option<DateTime<Utc>>`. No `personhood_evidence` field.