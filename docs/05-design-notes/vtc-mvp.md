# Spec: Verifiable Trust Community (VTC) — MVP

Status: **Draft**
Owner: Glenn Gore
Last updated: 2026-05-11

## 1. Objective

Turn the existing skeletal `vtc-service` crate (auth, ACL, sessions,
DIDComm, setup, did:webvh) into a minimum-viable **Verifiable Trust
Community** capable of standing up a self-governing community on top
of an existing VTA. A VTC manages community lifecycle, policy-driven
join/leave, role-based access, DTG credential issuance, optional
public hosting, and integrates with a trust-registry so other
communities can verify cross-community membership.

The product is a Rust backend service; an admin web UX lives in a
separate sibling repository and consumes the VTC's REST API.

### Why this matters

The VTA gives an operator key-management and DID-management
infrastructure. It does not give them a *community*. Without a VTC,
each operator has to invent their own membership model, their own
policy engine, their own cross-community trust story. The VTC ships
that as opinionated, composable infrastructure that stays inside the
DTG credential catalog and the wider workspace doctrine.

### Non-goals

* **Multi-tenant VTC.** One VTC binary hosts exactly one community.
  Multi-community hosts are out of scope for MVP.
* **Custom credential types.** The VTC issues and consumes only the
  credentials defined in
  [`openvtc/dtg-credentials`](https://github.com/OpenVTC/dtg-credentials)
  (VMC, VRC, VIC, VPC, VEC, VWC, RCard). Communities extend behavior
  via Rego + opaque JSON metadata blobs, not by adding new credential
  shapes.
* **TEE/Nitro deployment.** VTC ships as a regular service for MVP.
  Enclaved variant follows the VTA's later TEE arc.
* **N-of-M admin approvals**, **webhooks**, **bulk operations**,
  **WASM plugins**, **i18n at the resource layer**. Each is a
  defensible retrofit (see §16 and §17).

## 2. Tech stack & codebase context

* Rust workspace, edition 2024, MSRV 1.94.0.
* `vtc-service` already provides: auth (challenge-response, JWT
  audience `"VTC"`), ACL (with role enum to be extended),
  session-mgmt, DIDComm bridge, fjall-backed storage, `did:webvh`
  setup, OS-keyring secret backend.
* New dependencies:
  * `dtg-credentials = "0.1"` — closed credential catalog.
  * `affinidi-trust-registry-rs` (TRQP v2.0 client) — entity-level
    membership recognition.
  * `affinidi-status-list = "0.1"` (from `affinidi-tdk-rs`) — W3C
    Bitstring Status List v1.0 for per-VMC revocation.
  * `regorus` — embedded Rego engine.
  * `webauthn-rs` — passkey enrolment for admin login.
* Existing dependencies stay: `vti-common` (Store, AppError, telemetry
  sink, identifier validation), `vta-sdk` (REST + DIDComm client,
  sealed-transfer, attestation, protocol types),
  `affinidi-messaging-didcomm-service`, `fjall`, `axum`.

## 3. Architectural decisions (pinned)

These are settled. Do not re-litigate during implementation; raise an
ADR if circumstances change.

| Decision | Rationale |
|---|---|
| **1 VTC ⇄ 1 VTA topology** | The VTC has no key custody; every signature goes to the VTA signing oracle. Multi-VTA-per-VTC explodes the trust path without clear gain. |
| **VTC is always authoritative for its own state** | ACL + keyspaces are source of truth. VMC/VEC are *projections* of that state, useful when the member operates outside the VTC. VTC's own authz code never reads the VCs it issued. |
| **Credentials limited to DTG catalog** | VMC (membership), VEC (role + endorsement), VIC (invitation), VRC (relationship edge), VWC (witness, consumed only), RCard (contact), VPC (persona, v2). New credential types go upstream into dtg-credentials, not local extensions. |
| **Embedded regorus, no OPA sidecar** | Single deploy artifact, lower latency, TEE-compatible later. Policy reload is explicit (`POST /v1/policies/{id}/activate`); no hot-reload watchers. |
| **Trust-registry and StatusList are complementary** | StatusList answers "is this VC revoked?". Trust-registry answers "is this entity an active member?". A robust verifier consults both. |
| **DTG VMC `validUntil` is mandatory and finite** | Per-community config; default 30 days. External verifiers MUST see a non-perpetual VMC. Inside the community, ACL is authoritative — expired VMC does not lock the member out. |
| **Membership renewal is unconditional inside the community** | A member whose VMC expired three months ago can mint a fresh one any time, as long as ACL still says they're a member. No grace logic, no admin re-approval. |
| **Admin UX is a separate sibling repository** | VTC ships pure backend. CORS configurable. |
| **Public community website is feature-gated** | Cargo feature `website`. Operators who use an external host disable the feature; routes 404. |
| **Extensibility model = Rego + opaque JSON blobs** | Communities customize *behavior* via policies and *data* via `extensions: JsonValue` slots. No plugin loader, no WASM hooks, no custom REST modules. |
| **Hygiene baked in from day one** | Versioned audit events, idempotency keys, `/v1/` URL prefix, cursor pagination on lists, multi-passkey-per-admin. These are load-bearing retrofits, not features. |

## 4. Bootstrap and setup

### 4.1 CLI setup wizard — minimal handoff to web UX

```text
$ vtc setup
? Public VTC URL [https://vtc.example.com]:
? Public admin UX URL [https://admin.example.com]:
? VTA URL for provisioning [https://vta.example.com]:

✓ Minted VTC seed
✓ Provisioned VTC DID via VTA (template: vtc-host)
✓ Initialised keyspaces (sessions, acl, policies, members,
  join_requests, status_lists, registry_records, audit,
  idempotency, relationships)

  Open this URL within 1 hour to finish setup:

    https://admin.example.com/install#token=eyJhbGc…
```

The CLI does the bare minimum to make the daemon answerable. All
human-facing configuration (community profile, policies, admin
identity) happens in the admin UX.

What the CLI actually does:

1. Mints a 24-word BIP-39 seed via `affinidi-secrets-resolver`
   (default backend: OS keyring; AWS/GCP/Azure available via feature
   flags, same pattern as VTA).
2. Calls VTA's `POST /provision-integration` with the
   `vtc-host` DID template (new built-in template — see §4.4).
   Receives a sealed bundle containing the VTC's `did:webvh`, signing
   key references, and the VTA trust bundle. Opens the bundle locally
   and persists secrets.
3. Initializes all fjall keyspaces (§13).
4. Mints a single-use **install token**: signed JWT with
   `aud="vtc-install"`, `exp=now+1h`, `iat`, `jti`, plus an embedded
   ephemeral Ed25519 keypair the install flow uses for the
   challenge-response binding.
5. Prints the install URL and starts the daemon listening on the
   configured port.

### 4.2 Install flow (admin UX side)

1. Operator opens the install URL. The admin UX exchanges the install
   token for a setup session via `POST /v1/install/claim` (kills the
   install token atomically; carve-out pattern mirrors VTA's
   `BOOTSTRAP_CARVEOUT_CLOSED_KEY`).
2. WebAuthn passkey registration on the operator's authenticator
   (`webauthn-rs`). The passkey's public key is bound to a fresh
   `did:key` derived from it. This is the admin's DID.
3. Operator enters community profile in the UX: `name`, `description`,
   `logo_url`, `public_url`, `contact_email`, `language`.
4. Operator picks a seed policy template (`policies.open`,
   `policies.invite_only`, `policies.kyc_required`) which the UX
   uploads via `POST /v1/policies` then activates via
   `POST /v1/policies/{id}/activate`. Operators can edit policies
   later through the UX.
5. Operator chooses trust-registry behaviour: publish-on-join default,
   default departure disposition (Purge / Tombstone / Historical),
   whether to publish the VTC's own issuer profile on startup.
6. Admin UX calls `POST /v1/admin/bootstrap` with the admin DID. VTC
   writes the first ACL entry (`role: Admin`), permanently closes the
   install token carve-out, and emits a `CommunityInstalled` audit
   event.

After step 6 the install URL is dead. All subsequent admin operations
require an authenticated session against the admin DID's passkey.

### 4.3 Multi-passkey per admin DID

Admin entry shape in the `acl` keyspace for admin-role entries:

```rust
struct AdminEntry {
    did: String,
    role: VtcRole,
    passkeys: Vec<RegisteredPasskey>,  // 1..N
    joined_at: DateTime<Utc>,
    extensions: Value,                  // opaque per-community blob
}

struct RegisteredPasskey {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    transports: Vec<AuthenticatorTransport>,
    label: String,                      // e.g., "MacBook Air Touch ID"
    registered_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}
```

Operations:

* `POST /v1/admin/passkeys/register` — initiate WebAuthn ceremony for
  an additional device. Requires an authenticated session (the
  operator is logged in on device A and registering device B).
* `DELETE /v1/admin/passkeys/{credential_id}` — revoke a lost
  device. Refuses if it would leave the admin DID with zero passkeys
  (use emergency-bootstrap instead).
* `GET /v1/admin/passkeys` — list registered devices.

Each passkey operation emits a versioned audit event
(`AdminPasskeyRegistered`, `AdminPasskeyRevoked`).

### 4.4 The `vtc-host` DID template

New built-in DID template shipped with `vta-sdk`'s
`did_templates::builtin` set. Mirrors the existing `webvh-control` /
`webvh-daemon` shapes:

* `kind: "vtc-host"`
* Required vars: `vtc_url` (REST advertisement),
  `community_name` (for service entry label).
* Key shapes: one `assertionMethod` Ed25519 (for credential
  signatures), one `authentication` Ed25519 (for session/DID auth),
  one `keyAgreement` X25519 (for DIDComm + sealed-transfer reception).
* Service entries: `#vtc-rest` (REST endpoint), `#vtc-status-list`
  (where the BitstringStatusListCredential is hosted — see §6.2).
* No DIDComm service entry by default — communities that need a
  mediator add it later via the existing `services didcomm enable`
  runtime-service-management flow against their VTA.

### 4.5 Emergency bootstrap (recovery)

If all admin passkeys are lost: `vtc admin emergency-bootstrap` on a
stopped daemon emits a new install token (1h TTL) and re-opens the
install carve-out exactly once. Documented as a destructive operator
action: it writes a loud audit event
(`EmergencyBootstrapInvoked { operator_host, timestamp }`) on next
daemon start, visible in `GET /v1/audit?type=EmergencyBootstrapInvoked`.

## 5. Core domain model

### 5.1 Community profile

Stored as a singleton record in the `community` keyspace.

```rust
struct CommunityProfile {
    community_did: String,           // immutable; set at install
    name: String,
    description: String,
    logo_url: Option<String>,
    public_url: Option<String>,
    contact_email: Option<String>,
    language: String,                // BCP 47, default "en"
    created_at: DateTime<Utc>,
    extensions: Value,               // arbitrary community-defined fields
}
```

Editable by `admin` role. Stored under a stable key
(`community/profile`) for cheap reads.

### 5.2 Member

```rust
struct Member {
    did: String,                     // did:key or did:webvh
    role: VtcRole,
    joined_at: DateTime<Utc>,
    status_list_index: u32,          // stable for member's lifetime
    publish_consent: bool,           // trust-registry consent
    departure_preference: Option<DepartureDisposition>,
    current_vmc_id: Option<String>,  // latest issued VMC id
    current_role_vec_id: Option<String>,
    extensions: Value,
}
```

ACL entry references the `Member` for non-admin roles. Admin entries
carry `passkeys` directly (§4.3).

### 5.3 Roles

```rust
enum VtcRole {
    Admin,
    Moderator,
    Issuer,
    Member,
    Custom(String),   // community-defined; permissions via role_definitions.rego
}
```

Default permissions (rough matrix; final permissions defined by
`role_definitions.rego` and consulted on each authorized request):

| Action | Admin | Moderator | Issuer | Member |
|---|---|---|---|---|
| Edit community profile | ✓ | | | |
| Author / activate policies | ✓ | | | |
| Approve/reject join requests | ✓ | ✓ | | |
| Issue VEC / VWC / RCard on behalf of community | ✓ | | ✓ | |
| Issue VMC | (only via join flow) | | | |
| Remove other members | ✓ | ✓ (policy-gated) | | |
| Self-remove | ✓ | ✓ | ✓ | ✓ |
| Renew own VMC | ✓ | ✓ | ✓ | ✓ |
| Publish self-issued VRC | ✓ | ✓ | ✓ | ✓ |
| Rotate own DID | ✓ | ✓ | ✓ | ✓ |

Custom roles must define their permissions in `role_definitions.rego`;
unspecified actions default-deny.

### 5.4 Policy bundle

A `Policy` is a single Rego module plus metadata:

```rust
struct Policy {
    id: Uuid,
    name: String,                    // e.g., "join", "removal"
    purpose: PolicyPurpose,
    rego_source: String,
    compiled: Vec<u8>,               // regorus pre-compiled bytecode
    sha256: [u8; 32],
    activated_at: Option<DateTime<Utc>>,
    author_did: String,
}

enum PolicyPurpose {
    Join,
    Removal,
    Personhood,
    Registry,
    Directory,
    RoleDefinitions,
    CrossCommunityRoles,
    CrossCommunityRelationships,
    Relationships,
}
```

Exactly one Policy per `purpose` may be active at any time.
Activating a new policy supersedes the prior one atomically; the prior
is retained in the `policies` keyspace (archived) for audit.

### 5.5 Join request

```rust
struct JoinRequest {
    id: Uuid,
    applicant_did: String,
    vp: serde_json::Value,           // raw VP
    submitted_at: DateTime<Utc>,
    status: JoinStatus,
    policy_decision: Option<PolicyDecision>,
    registry_consent: Option<RegistryConsentRequest>,
    extensions: Value,
}

enum JoinStatus { Pending, Approved, Rejected, Withdrawn, Deferred }
```

### 5.6 Status-list state

```rust
struct StatusListState {
    purpose: StatusListPurpose,      // Revocation | Suspension
    capacity: u32,                   // default 2^17 = 131_072
    next_random_seed: u64,           // for random index allocation
    occupied: u32,                   // count for the 75% alert
    list_credential_id: String,
}
```

### 5.7 Trust-registry record

```rust
struct RegistryRecord {
    record_id: String,               // assigned by trust-registry
    member_did: String,
    status: RegistryStatus,
    active_from: DateTime<Utc>,
    active_to: Option<DateTime<Utc>>,
    last_synced_at: DateTime<Utc>,
}

enum RegistryStatus { Active, Departed }
```

## 6. Credentials — DTG catalog mapping

### 6.1 The closed catalog

The VTC issues, consumes, or stores only credentials from
`dtg-credentials`. The full mapping:

| Use | Type | Issuer | Subject | Notes |
|---|---|---|---|---|
| Membership | **VMC** | community DID | member DID | `personhood: bool` gated by `personhood.rego`. `validUntil` mandatory (community config). `credentialStatus` points to community's BitstringStatusListCredential. |
| Role grant | **VEC** | community DID | member DID | `endorsement = { type: "CommunityRole", role, communityDid }`. Issued alongside VMC at join; re-issued on role change. |
| Invitation (gated communities) | **VIC** | community DID (admin/issuer) | applicant DID | Holder presents in VP at join. Policy can mandate. |
| Member ↔ member trust edge | **VRC** | member DID | other member DID | Self-issued. Published to VTC for discoverability. |
| Community ↔ community trust edge (v2) | VRC | community DID | other community DID | Pairs with trust-registry recognition. |
| Member contact card | **RCard** | member or community | member | jCard value. Member-driven; VTC stores opaquely. |
| Event/proximity witness | **VWC** | external | applicant | Consumed in join VPs; never issued by VTC. |
| Custom endorsement | **VEC** | community (issuer role) | any DID | Community-defined `endorsement` value. The hook for badges, attestations, etc. — without inventing new credential types. |
| Persona binding | VPC | community | member | **v2**. Not in MVP. |

### 6.2 Status-list integration

* On install, VTC mints two `BitstringStatusListCredential`s
  (purpose `revocation`, purpose `suspension`), each with capacity
  131,072 (configurable). Hosted at
  `https://{vtc_public_url}/v1/status-lists/{purpose}` and referenced
  in the VTC DID document via the `#vtc-status-list` service entry.
* Index allocation is **random** with decoys (affinidi-status-list's
  privacy mode).
* Every VMC issued carries `credentialStatus = { id: ".../status-lists/revocation#<idx>", type: "BitstringStatusListEntry", purpose: "revocation", statusListIndex: <idx>, statusListCredential: ".../status-lists/revocation" }`.
* On member departure: flip the bit at the member's index. Same index
  is reused across the member's lifetime (renewals re-issue VMCs that
  point to the same index).
* On `Purge` disposition: bit flipped *and* index removed from the
  member record; the slot becomes a decoy.
* **Alert** when any status list crosses 75% occupancy (telemetry
  event `StatusListOccupancyWarning`); MVP does **not** chain to a
  second list — that's a v2 problem documented in §16.

### 6.3 Renewal model

Endpoint: `POST /v1/members/me/renew` (REST) and
`community/1.0/renew-vmc` (DIDComm).

Behavior:

1. Auth check: member's session must match an active ACL entry.
   No expiry/grace test.
2. Mint new VMC (`validFrom = now, validUntil = now + community.membership.validity`)
   via VTA signing oracle. Same `credentialStatus` index. Same
   `subject` (member DID).
3. Mint refreshed role VEC if any of: role changed since last issuance,
   community profile changed (issuer DID renamed), policy version
   updated such that role permissions changed.
4. Sealed-transfer the credentials to the member's DID.
5. Audit event `MembershipRenewed { member_did, vmc_id, validUntil }`.

### 6.4 Personhood

* New Rego policy `personhood.rego`. Ships as a **deny-all stub** by
  default. Community admins author the actual rule (e.g., "require N
  VWCs from event X plus M endorsements from existing personhood
  holders").
* Personhood is asserted via a separate explicit operation:
  `POST /v1/members/{did}/personhood/assert`. Re-mints the member's
  VMC with `personhood: true` (which adds the
  `PersonhoodCredential` type marker per dtg-credentials).
* Revoking personhood: `DELETE /v1/members/{did}/personhood` re-mints
  the VMC with `personhood: false`. Audit logged.
* Policy input contract: `data.input = { applicant_did, vp_claims }`.
  Communities extend via additional `data.*` namespaces they populate
  through custom REST hooks they wire up server-side (each
  implementer reinvents — workspace doctrine).

### 6.5 DID rotation per method

| Member DID method | Mechanism |
|---|---|
| **did:webvh** | Native. VTC resolves the new DID, walks its `did.jsonl` history, finds the prior key matching the old ACL entry, verifies the rotation signature against the prior key. No additional credential required. |
| **did:key** | Co-signed rotation attestation. Payload `{ old_did, new_did, vtc_did, rotation_id, expires_at: now+10m }` signed by **both** old-DID and new-DID keys. VTC verifies both signatures, atomically updates ACL (key change), reuses status-list index, re-issues VMC + role VEC to the new DID. Old DID's session invalidated. |

Wire: `POST /v1/members/me/rotate` + `community/1.0/rotate-did`.
Authentication is via the *new* DID's session (caller proves
possession of the new key).

In-flight VRCs keyed on the old DID are left intact (graph history
preservation). Members who want continuity issue a fresh VRC linking
new → old as a `controller-rotation` relationship.

Members are expected to use `did:key` or `did:webvh` (workspace
doctrine). Other DID methods are not supported in MVP.

## 7. Policy engine (regorus)

### 7.1 Required policies

| Name | Purpose | Default-ship behavior |
|---|---|---|
| `join` | Decide on join requests | Template: `policies.open` (accept any signed VP) |
| `removal` | Decide admin-initiated removals | Default: any admin may remove any non-admin |
| `personhood` | Decide personhood assertion | **Deny-all stub** — admin must replace |
| `registry` | Decide trust-registry publish + departure disposition | Default: publish on join, default disposition = Tombstone |
| `directory` | Decide member-directory visibility | Default: members can see other members' DID + role only |
| `role_definitions` | Map roles (incl. custom) to permissions | Default: the matrix in §5.3 |
| `cross_community_roles` | Decide if external VEC role grants are honoured | **Deny-all** by default |
| `cross_community_relationships` | Decide if external VRCs are stored | **Deny-all** by default |
| `relationships` | Decide if a published VRC is stored / surfaced | Default: store if both parties are current members |

### 7.2 Activation lifecycle

* Upload via `POST /v1/policies` (`admin` role). Body includes Rego
  source + metadata. VTC compiles via `regorus`, returns 400 with
  compilation errors on failure.
* Activate via `POST /v1/policies/{id}/activate`. Atomic swap: in-flight
  requests against the old policy complete; new requests use the new
  one. Old policy retained in `policies` keyspace as archived (audit).
* Test via `POST /v1/policies/{id}/test` — evaluates the policy against
  a provided input without activating.
* No file-watching, no auto-reload. Reloads are deliberate.

### 7.3 Input contracts

All Rego policies receive `data.input` plus, for some, additional
`data.*` namespaces.

| Policy | `input` shape |
|---|---|
| `join` | `{ applicant_did, vp_claims, action: "join", now }` |
| `removal` | `{ actor_did, target_did, target_role, reason, action: "remove", now }` |
| `personhood` | `{ applicant_did, vp_claims }` (community extends) |
| `registry` | `{ member, action: "join"\|"leave", requested_disposition? }` |
| `directory` | `{ viewer_did, viewer_role, target_member, fields_requested }` |
| `role_definitions` | `{ role, action, resource? }` |
| `cross_community_roles` | `{ foreign_vec, target_role, vtc_state }` |
| `relationships` | `{ vrc, issuer_member, subject_member }` |

Communities adding policy-specific context inject it via REST hooks
they author themselves; the workspace ships the contracts above and
does not standardize extension shapes.

## 8. Trust-registry integration

### 8.1 Startup behaviour

On daemon start (after install completes), VTC publishes its issuer
profile to the configured trust-registry via
`affinidi-trust-registry-rs`. Idempotent: re-publishing updates the
existing record. Publish failures are non-fatal — the daemon logs and
continues; the `MembershipSyncer` retries.

### 8.2 Three departure dispositions

| Disposition | Record state | Use case |
|---|---|---|
| **Purge** | Record deleted | Right-to-be-forgotten; private communities |
| **Tombstone** | `status: Departed`, no date range | "Was a member, no longer" — minimal disclosure |
| **Historical** | `status: Departed`, `active_from`/`active_to` populated | Audit / retroactive verification of attestations made during membership |

Decision flow:

1. **Community policy** (`registry.rego`) sets allowed envelope:
   `publish_on_join`, `departure_options`, `default_departure`,
   `min_disposition` (floor).
2. **Member preference** (set at join, or at leave), clamped to the
   policy's allowed set.
3. **Right-to-be-forgotten override**: a member-initiated `Purge`
   request *always wins* over `min_disposition`. Logged as
   `RegistryRecordPolicyOverride { reason: "rtbf" }` with a hashed
   member DID so the override is auditable without re-leaking the
   identifier.

### 8.3 MembershipSyncer

A `MembershipSyncer` (Tokio task, analogous to `DrainSweeper` in
vta-service) drives reconciliation:

* Subscribes to local lifecycle events (`MemberAdded`, `MemberRemoved`,
  `RoleChanged`).
* For each event, computes the desired trust-registry + status-list
  state and enqueues a `SyncJob`.
* Retries with exponential backoff on registry-side failures.
* Emits `RegistrySyncPending`, `RegistrySyncFailed`,
  `StatusListUpdatePending`, `StatusListUpdateFailed` telemetry
  events.
* Boot-time replay of any outstanding jobs in the `sync_queue`
  keyspace.

### 8.4 Cross-community recognition

A `cross_community_roles.rego` policy decides whether a foreign VEC's
role claim should map to a local ACL role at this VTC. Default
deny-all. Communities opt in to federated trust via Rego.

Implementation hook: the auth extractor, when handed a session minted
from a foreign VEC, runs `cross_community_roles.rego` to compute the
effective local role. Empty result → 403.

## 9. Wire protocols

### 9.1 URL versioning

All REST endpoints live under `/v1/`. Adding `/v2/` is the explicit
mechanism for breaking changes. No unversioned routes other than
`/health`.

### 9.2 Idempotency keys

Every mutating endpoint (`POST`, `PUT`, `DELETE`) accepts
`Idempotency-Key: <uuid>`. VTC stores `(key, request_hash) → response`
for 24 hours in the `idempotency` keyspace. Retries with the same key
return the cached response; retries with the same key but a different
request body return 422 `IdempotencyKeyConflict`.

Required on: all bootstrap, install, member-lifecycle, policy,
credential, and rotation endpoints. Optional but accepted on read
endpoints (no-op).

### 9.3 Cursor pagination

Standard contract on every list endpoint:

```
GET /v1/<collection>?cursor=<opaque>&limit=<1..200>

→ 200 OK
{
  "items": [...],
  "next_cursor": "<opaque>" | null,
  "total_estimate": <u64 | null>   // optional
}
```

Cursor is opaque (server picks; typically a base64-encoded
`(last_key, snapshot_id)` tuple). `next_cursor: null` means end of
collection.

### 9.4 CORS

`config.toml` carries an `allowed_origins: Vec<String>` list. Defaults
to empty; install flow writes the admin UX origin during step 6.
Wildcard origins refused at config-load time. Preflight responses
include `Idempotency-Key` in `Access-Control-Allow-Headers`.

### 9.5 REST surface (representative — full OpenAPI in §16 followup)

```
# Install / admin lifecycle
POST   /v1/install/claim
POST   /v1/admin/bootstrap
POST   /v1/admin/passkeys/register
DELETE /v1/admin/passkeys/{credential_id}
GET    /v1/admin/passkeys

# Admin runtime configuration
GET    /v1/admin/config
PATCH  /v1/admin/config
POST   /v1/admin/config/reload
POST   /v1/admin/config/restart

# Community
GET    /v1/community/profile
PUT    /v1/community/profile

# Members
GET    /v1/members
GET    /v1/members/{did}
GET    /v1/members/{did}/relationships
PATCH  /v1/members/{did}                 # role / extensions
DELETE /v1/members/{did}                 # admin removal
DELETE /v1/members/me                    # self removal
POST   /v1/members/me/renew
POST   /v1/members/me/rotate
POST   /v1/members/{did}/personhood/assert
DELETE /v1/members/{did}/personhood

# Join requests
POST   /v1/join-requests                 # submit (unauth, rate-limited)
GET    /v1/join-requests
GET    /v1/join-requests/{id}
POST   /v1/join-requests/{id}/approve
POST   /v1/join-requests/{id}/reject
POST   /v1/join-requests/{id}/defer

# Invitations (VIC)
POST   /v1/invitations
GET    /v1/invitations
DELETE /v1/invitations/{id}

# Policies
GET    /v1/policies
POST   /v1/policies
POST   /v1/policies/{id}/activate
POST   /v1/policies/{id}/test
GET    /v1/policies/active

# Relationships (VRC)
POST   /v1/relationships
GET    /v1/relationships
DELETE /v1/relationships/{id}

# Credentials (Issuer/Admin)
POST   /v1/credentials/endorsements      # mint VEC
POST   /v1/credentials/witnesses         # mint VWC
POST   /v1/credentials/rcards            # mint RCard

# Status lists
GET    /v1/status-lists/revocation       # public (the VC)
GET    /v1/status-lists/suspension       # public (the VC)

# Audit
GET    /v1/audit

# Backup
POST   /v1/backup/export                 # admin only
POST   /v1/backup/import                 # admin only
POST   /v1/config/export
POST   /v1/config/import

# Trust-registry
GET    /v1/registry/profile
POST   /v1/registry/refresh

# Health
GET    /health
GET    /v1/health/diagnostics            # admin only
```

### 9.6 DIDComm surface

Symmetric protocols under `community/1.0/`:

```
community/1.0/join-request
community/1.0/join-decision
community/1.0/renew-vmc
community/1.0/rotate-did
community/1.0/self-remove
community/1.0/role-update              # admin → member notification
community/1.0/status-changed           # admin → member notification
community/1.0/membership-revoked       # admin → member notification

invitations/1.0/issue                  # admin/issuer
invitations/1.0/redeem                 # applicant

relationships/1.0/publish
relationships/1.0/query

policies/1.0/upload
policies/1.0/activate
policies/1.0/test

credentials/1.0/issue-endorsement      # admin/issuer
credentials/1.0/issue-witness
credentials/1.0/issue-rcard
```

`community/1.0/install/*` does not exist — install is REST-only by
nature (no DIDComm session before admin bootstrap).

## 10. Audit log

### 10.1 Event vocabulary (versioned)

```rust
#[serde(tag = "type", content = "data")]
enum AuditEvent {
    // v1 events
    CommunityInstalled(CommunityInstalledData),
    EmergencyBootstrapInvoked(EmergencyBootstrapData),

    AdminPasskeyRegistered(AdminPasskeyRegisteredData),
    AdminPasskeyRevoked(AdminPasskeyRevokedData),

    JoinRequestSubmitted(JoinRequestSubmittedData),
    JoinRequestApproved(JoinDecisionData),
    JoinRequestRejected(JoinDecisionData),
    JoinRequestDeferred(JoinDecisionData),

    MemberAdded(MemberLifecycleData),
    MemberRemoved(MemberLifecycleData),
    MembershipRenewed(MembershipRenewedData),
    RoleChanged(RoleChangedData),
    PersonhoodAsserted(PersonhoodData),
    PersonhoodRevoked(PersonhoodData),
    MemberDidRotated(DidRotationData),

    RegistryRecordPublished(RegistryRecordData),
    RegistryRecordUpdated(RegistryRecordData),
    RegistryRecordRemoved(RegistryRecordData),
    RegistryRecordPolicyOverride(RegistryOverrideData),

    StatusListBitFlipped(StatusListBitFlippedData),
    StatusListOccupancyWarning(StatusListWarningData),

    PolicyUploaded(PolicyMetadata),
    PolicyActivated(PolicyMetadata),

    InvitationIssued(InvitationData),
    InvitationRedeemed(InvitationData),
    InvitationRevoked(InvitationData),

    RelationshipPublished(RelationshipData),
    RelationshipRemoved(RelationshipData),

    CredentialIssued(CredentialIssuedData),    // VEC / VWC / RCard

    ConfigChanged(ConfigChangedData),
    ConfigReloaded(ConfigReloadedData),
    RestartRequested(RestartRequestedData),
}

struct ConfigChangedData {
    changes: Vec<ConfigChange>,
    requires_restart: bool,
}

struct ConfigChange {
    key: String,
    old_value: Option<Value>,                  // null if previously unset
    new_value: Value,
    source_before: ConfigSource,               // "env" | "db" | "toml" | "default"
}

struct AuditEnvelope {
    event_id: Uuid,
    event_version: u32,                  // 1 for MVP; bumps on breaking shape change
    schema_version: u32,                 // overall vocabulary version
    timestamp: DateTime<Utc>,
    actor_did_hash: [u8; 32],            // hashed for purge resilience
    actor_did_plain: Option<String>,     // null after RTBF purge
    target_did_hash: Option<[u8; 32]>,
    target_did_plain: Option<String>,
    event: AuditEvent,
}
```

The hash-and-plaintext-pair pattern lets right-to-be-forgotten purges
null the plaintext while keeping the hash for correlation across the
audit log. Without hashes, every override leaks the DID it claimed to
remove.

### 10.2 Query surface

```
GET /v1/audit
  ?since=<ISO8601>
  &until=<ISO8601>
  &type=<EventType>
  &actor_did=<did>
  &target_did=<did>
  &cursor=<opaque>
  &limit=<1..200>
```

Indexed columns in the `audit` keyspace: `timestamp` (primary),
`type`, `actor_did_hash`, `target_did_hash`. Each yields a secondary
index keyspace (`audit_by_type`, etc.) maintained on write.

### 10.3 Retention

* Default: retain forever (audit is forensic infrastructure).
* Configurable per-event-type max retention via
  `audit.retention.<event_type>`. Pruner task wakes hourly.
* RTBF purges *null the plaintext fields*; the envelope (with hashes)
  is retained for chain integrity.

## 11. Member lifecycle

### 11.1 Join

```
applicant → VTC (REST POST /v1/join-requests or DIDComm join-request):
  {
    applicant_did,
    vp: <Verifiable Presentation>,
    registry_consent: { publish, departure_preference } | null,
    extensions: <opaque>
  }

VTC:
  1. Validate VP signature (typestate: VerifiedJoinRequest)
  2. Compile + run join.rego with input.vp_claims
  3. If allow:
     a. Allocate status-list index
     b. Compute VMC validUntil = now + community.membership.validity
     c. Mint VMC + role VEC via VTA signing oracle
     d. Write ACL entry + Member record
     e. Run registry.rego, enqueue MembershipSyncer job
     f. Sealed-transfer credentials to applicant_did
     g. Audit: JoinRequestApproved + MemberAdded
  4. If deny:
     a. Persist JoinRequest with status=Rejected + decision rationale
     b. Send DIDComm reject message to applicant
     c. Audit: JoinRequestRejected
```

### 11.2 Self-removal

```
member → VTC:
  DELETE /v1/members/me
  { disposition: "Purge" | "Tombstone" | "Historical" | "PolicyDefault" }

VTC:
  1. Auth check: caller's DID is in ACL
  2. Compute effective disposition (clamp to registry.rego allowed set;
     RTBF override path for Purge)
  3. Atomic local: delete ACL entry, delete/anonymize Member, flip
     status-list bit, emit MemberRemoved audit
  4. Enqueue MembershipSyncer job for registry-side change
  5. Return 200 with effective disposition + sync job id
```

### 11.3 Admin removal

```
admin → VTC:
  DELETE /v1/members/{did}
  { reason, disposition?: "..." }

VTC:
  1. Auth: admin role (or moderator if removal.rego allows)
  2. Run removal.rego with { actor, target, reason }
  3. If allow: same effects as self-removal, plus
     audit event tagged with actor_did
  4. Send community/1.0/membership-revoked DIDComm to target if
     reachable
```

### 11.4 Renewal

See §6.3. Unconditional on ACL membership.

### 11.5 Role change

```
admin → VTC:
  PATCH /v1/members/{did}
  { role: "moderator" }

VTC:
  1. Auth check; validate role exists (standard or defined in
     role_definitions.rego)
  2. Update ACL entry
  3. Mint new role VEC with endorsement.role=<new>
     Old VEC superseded by validFrom timestamp ordering
  4. Sealed-transfer new VEC to member
  5. Audit: RoleChanged + DIDComm role-update notification
```

### 11.6 DID rotation

See §6.5.

## 12. Optional surfaces

### 12.1 Public community website (`website` feature)

* Markdown blobs stored in the `website_content` keyspace, keyed by
  path (`/`, `/about`, `/join`).
* Server-rendered HTML (pulldown-cmark) at request time. No client-side
  scripting layer.
* Asset passthrough for static files (logo, images).
* Submit endpoint: `POST /v1/website/forms/join` (rate-limited, no
  auth) routes to `POST /v1/join-requests` internally. CSRF token
  required; double-submit cookie pattern.
* Disabled (feature off): all `/v1/website/*` routes 404. Operator
  points DNS at an external host.
* No CMS UI in MVP. Authoring is REST: `PUT /v1/website/pages/{path}`
  (admin/moderator).

### 12.2 VRC graph

* Self-issued only in MVP. Bilateral counter-signing v2.
* `POST /v1/relationships` (or `relationships/1.0/publish`) — caller
  submits a VRC they signed.
* VTC verifies VRC signature against caller's known DID.
* Run `relationships.rego` to decide whether to store.
* `GET /v1/members/{did}/relationships` returns published VRCs where
  the DID is issuer or subject. Pagination required.
* On member departure: VRCs they issued are handled per departure
  disposition (purged on `Purge`; retained on Tombstone/Historical
  with status annotation).

## 13. Storage (fjall keyspaces)

| Keyspace | Existing | Schema |
|---|---|---|
| `sessions` | ✓ | unchanged |
| `acl` | ✓ | extended: `VtcRole` enum + `extensions: Value` |
| `community` | new | singleton key `profile` → `CommunityProfile` |
| `policies` | new | `id → Policy`; `purpose_active/<purpose> → id` (secondary) |
| `members` | new | `did → Member` |
| `join_requests` | new | `id → JoinRequest`; `status/<status>/<id>` (secondary) |
| `invitations` | new | `id → Invitation` |
| `relationships` | new | `vrc_id → VrcRecord`; `by_member/<did>/<vrc_id>` (secondary) |
| `status_lists` | new | per-purpose state + index allocations |
| `registry_records` | new | `member_did → RegistryRecord` |
| `sync_queue` | new | pending `MembershipSyncer` jobs |
| `audit` | new | `timestamp → AuditEnvelope`; indices by type/actor/target |
| `idempotency` | new | `key → (request_hash, response, expires_at)` |
| `config` | new | `key → ConfigValue` — DB-layer overrides for runtime config |
| `website_content` | new (gated) | `path → WebsitePage` |

All keyspaces use the existing `KeyspaceHandle` enum (local fjall
today; vsock parity later if VTC ever runs in a TEE).

## 14. Operational

### 14.1 Backup / restore

Same pattern as VTA backup:

* Argon2id KDF (≥12-char password) + AES-256-GCM.
* `POST /v1/backup/export` returns the encrypted full state dump
  (all keyspaces).
* `POST /v1/backup/import` accepts a dump; refuses if `community_did`
  doesn't match the running VTC's DID (`check_vtc_did_compatibility`
  helper, mirror of VTA's check).
* Fresh-install VTC accepts any backup (no DID set yet); a configured
  VTC rejects mismatched backups.

### 14.2 Configuration export/import

Separate from data backup. Exports only configuration shape:

* Community profile.
* Policy bundle (all policies + the active set per purpose).
* CORS configured origins.
* `community.membership.validity`, status-list capacities, audit
  retention settings, registry endpoints.

Use case: promote-from-staging, migrate between hosts without copying
member data, share a community template.

`POST /v1/config/export` returns plain JSON.
`POST /v1/config/import` applies it transactionally; on conflict with
existing community profile, refuses (force flag = different endpoint).

### 14.3 Telemetry

Reuses `vti_common::telemetry::TelemetrySink` (existing ring-buffer
default). New event kinds:

* `JoinRequestSubmitted`, `JoinRequestDecided`
* `MemberAdded`, `MemberRemoved`, `MembershipRenewed`, `RoleChanged`
* `RegistrySyncPending`, `RegistrySyncFailed`, `StatusListUpdatePending`,
  `StatusListUpdateFailed`
* `StatusListOccupancyWarning`
* `PolicyActivated`
* `IdempotencyConflict`
* `CrossCommunityRoleEvaluated`

### 14.4 Health / diagnostics

* `GET /health` — unauth, returns 200 if the daemon is up and storage
  is reachable.
* `GET /v1/health/diagnostics` — admin only. Returns:
  * Status-list occupancy per purpose (count + percentage).
  * MembershipSyncer queue depth, last-success/failure timestamps.
  * Active policy ids per purpose with their SHA-256.
  * Trust-registry last-publish timestamp + status.
  * Telemetry ring-buffer snapshot summary.

### 14.5 Runtime guards (preserve)

* Rate limit on unauth routes via `tower-governor`: 5 rps + 10 burst
  per source IP. Applies to `/v1/join-requests` (submit), `/v1/install/*`,
  `/health`, and public website forms.
* Body cap: 1 MB globally.
* Audience isolation: VTC JWTs only — `aud: "VTC"`. Cross-audience
  tokens rejected.
* Install carve-out: single-use, like VTA's bootstrap carve-out.

### 14.6 Runtime configuration management

Every configurable VTC option is settable through the admin web UX
via REST. Settings that can take effect without interrupting service
(log level, CORS origins, rate limits, audit retention, membership
validity defaults) apply on explicit reload. Settings that require a
process restart to take effect (bind address, TLS certificates,
storage path) are flagged in the UX response and applied via an
explicit restart action.

#### Persistence model

Configuration is a three-layer overlay, evaluated right-to-left at
boot and on reload:

```
effective = env_vars > db_overrides > config.toml > defaults
```

* `config.toml` is the on-disk seed loaded at boot (compatibility with
  the existing config story).
* `db_overrides` is a new `config` keyspace; the admin UX writes here.
* Environment variables (`VTC_*`) win over everything for ops-style
  emergency overrides.

`GET /v1/admin/config` returns the effective config with per-field
annotations: `source: "env" | "db" | "toml" | "default"` and
`requires_restart: bool`.

#### REST surface

```
GET   /v1/admin/config
PATCH /v1/admin/config            # partial update
POST  /v1/admin/config/reload     # apply reloadable changes in-place
POST  /v1/admin/config/restart    # graceful shutdown for restart-required changes
```

`PATCH` accepts a JSON object with any subset of mutable config keys.
Writes to the `config` keyspace and returns:

```json
{
  "applied":          ["log.level", "cors.allowed_origins"],
  "pending_restart":  ["server.port"],
  "rejected":         []
}
```

`pending_restart` fields are persisted but not yet active. Calling
`POST /v1/admin/config/reload` re-applies the effective config to
running subsystems for hot-reloadable settings. Calling
`POST /v1/admin/config/restart` initiates graceful shutdown:

1. Stop accepting new HTTP / DIDComm requests.
2. Drain in-flight requests with a configurable
   `restart.drain_timeout` (default 30s).
3. Flush `MembershipSyncer` queue (bounded wait, also 30s).
4. Emit `RestartRequested` audit event.
5. Exit with status 0.

A process supervisor (systemd `Restart=always`, kubernetes,
supervisord) is required to actually restart the binary; the spec
documents this as an explicit operational dependency. CLI users get
`vtc daemon` (existing) supervised by their init system; container
users get a k8s `Deployment`.

#### Config taxonomy

| Key | Reload | Restart | UX-settable | Notes |
|---|---|---|---|---|
| `server.host` | | ✓ | ✓ | |
| `server.port` | | ✓ | ✓ | |
| `server.tls.cert_path` | | ✓ | ✓ | |
| `server.tls.key_path` | | ✓ | ✓ | |
| `log.level` | ✓ | | ✓ | |
| `cors.allowed_origins` | ✓ | | ✓ | |
| `audit.retention.*` | ✓ | | ✓ | |
| `membership.validity` | ✓ | | ✓ | New value applies to *subsequent* VMC issuance; existing VMCs retain their issued validUntil. |
| `status_list.capacity` | | ✓ | ✓ | Existing lists keep their capacity; new lists (on chaining) adopt the new value. |
| `registry.endpoint` | ✓ | | ✓ | Triggers reconnect. |
| `registry.publish_on_startup` | ✓ | | ✓ | |
| `rate_limit.unauth_rps` | ✓ | | ✓ | |
| `rate_limit.unauth_burst` | ✓ | | ✓ | |
| `body_cap_bytes` | ✓ | | ✓ | |
| `restart.drain_timeout` | ✓ | | ✓ | |
| `storage.path` | | ✓ | ✓ | |
| `community.profile.*` | ✓ | | ✓ | Goes through `/v1/community/profile`, not `/v1/admin/config`. |
| Secret backend (keyring / AWS / GCP / Azure) | | n/a | n/a | Selected by cargo feature at compile time; UX surfaces "active backend". |
| Cargo features (`website`, etc.) | n/a | n/a | n/a | Compile-time only. UX surfaces "feature available" / "not built in". |

#### Audit + telemetry

Every mutation emits a versioned audit event (see §10.1
additions). `ConfigChanged` carries the per-key change set;
`ConfigReloaded` and `RestartRequested` mark control-plane actions.

Telemetry counters: `config_patched`, `config_reloaded`,
`config_restart_requested`, `config_reload_failed`.

#### Relationship to `/v1/config/{export,import}`

`/v1/config/export` (§14.2) returns the union of community profile +
policy bundle + DB-layer config overrides — exactly what's needed to
recreate a community on a fresh VTC. It does **not** include
TOML-layer or env-layer values, since those are deployment-specific.
`/v1/config/import` writes to the DB layer; restart-required fields
take effect at next process start.

## 15. CLI surface

`cnm-cli` extension. The community-network-manager binary already
exists; new subcommands added under `cnm community`:

```
cnm community setup
cnm community status

cnm community profile        {show, set}
cnm community policies       {list, upload, activate, show, test}
cnm community members        {list, show, role, remove}
cnm community join           {list, approve, reject, defer, show}
cnm community invitations    {list, issue, revoke}
cnm community website        {publish, unpublish, list}     # feature-gated
cnm community registry       {publish, refresh, status}
cnm community status-lists   {show, occupancy}
cnm community audit          {list, since, type, actor, target}
cnm community backup         {export, import}
cnm community config         {show, set, reload, restart, export, import}
cnm community daemon         {reload, restart, status}
```

`cnm community config show` returns the effective config with source
annotations. `cnm community config set <key> <value>` PATCHes a single
key. `cnm community config reload` and `restart` map directly to the
REST control-plane endpoints. `cnm community daemon` is a thin alias
for the reload/restart actions, parallel to how operators think about
the running process.

CLI commands are thin wrappers over `vta-sdk` REST/DIDComm clients
(workspace doctrine: CLI logic in `vta-cli-common`).

## 16. Phasing / milestones

Phases are ordered by dependency. Each ships independently as an
operator-visible increment.

| Phase | Deliverable | Gates next phase by |
|---|---|---|
| **0 — Provisioning + install** | `vtc-host` DID template, `vtc setup` CLI wizard, install-token + WebAuthn install flow, multi-passkey admin DID, community profile keyspace. | DID + auth foundation. |
| **1 — IAM + member lifecycle** | Role enum + custom roles, ACL extension, member CRUD, join requests (manual approve/reject), self-removal + admin-removal (no policy yet), audit events v1, idempotency keys, cursor pagination, `/v1/` URL versioning. | The community can have members. |
| **2 — Policy engine + DTG issuance** | regorus engine, policy upload/activate, `join.rego` driving the join flow, `removal.rego`, VMC + VEC issuance via VTA oracle, status-list publication, renewal endpoint, DID rotation (both methods). | The community has live policies and proper credential issuance. |
| **3 — Trust-registry + extensibility** | Trust-registry publish on startup, three departure dispositions, `registry.rego`, `MembershipSyncer`, RTBF override path, hash-tagged audit envelopes, cross-community recognition policies. | The community is part of the wider DTG network. |
| **4 — VRC + Personhood** | Self-issued VRC publishing + storage, `relationships.rego`, `personhood.rego` (deny-all stub) + assert/revoke endpoints, custom endorsement issuance (issuer role). | The graph and personhood semantics are live. |
| **5 — Optional surfaces** | Public community website (feature-gated), admin web UX (separate repo, can land in parallel with any prior phase once REST surface is stable after phase 2). | MVP complete. |

Phase 5 sub-tasks parallelize with phases 3 and 4. Phases 0–4 are
strictly serial.

## 17. Open questions

These are *not* blockers — they have proposed answers documented in
prior turns of design. Listed here so the spec is honest about what
remains to validate during implementation.

1. **Personhood policy input schema beyond the minimal contract.**
   Each community extends; the workspace does not standardize. Risk:
   community implementations diverge wildly. Mitigation: publish at
   least one reference personhood policy in `docs/04-reference/`
   after Phase 4 lands.

2. **Status-list chaining strategy.** MVP alerts at 75% occupancy and
   declines beyond capacity. Production communities will exceed
   131,072 members eventually. Plan: introduce a successor-list
   pointer header in the BitstringStatusListCredential and a
   `chained_status_lists` keyspace. Spec'd as a v2 add-on.

3. **Member DID rotation atomicity under registry lag.** If a `did:key`
   rotation succeeds locally but the trust-registry sync to update the
   record's member DID lags, external verifiers briefly see the old
   DID as active and the new DID as unknown. Workspace doctrine
   accepts this: registry lag is a known property; verifiers should
   re-query on mismatch.

4. **Audit hash function and salt strategy.** Currently spec'd as
   plain SHA-256 over the DID string. Could be salted per-community
   to prevent cross-community correlation attacks. v2 question.

5. **DIDComm join-request DoS exposure.** Unlike REST (rate-limited by
   IP), DIDComm doesn't have an obvious rate-limiting axis. Per-DID
   rate-limit on `community/1.0/join-request` is the obvious answer
   but adds state. Defer to a phase 2.5 hardening step.

6. **CORS + WebAuthn `RP ID` coupling.** The admin UX origin must
   match the WebAuthn `RP ID` set at passkey registration. Operators
   who migrate the admin UX to a new domain re-register all passkeys.
   Document as expected; codify in operator runbook.

## 18. Explicitly NOT in MVP

To preserve clarity about scope, the following are out:

* **N-of-M admin approvals** for sensitive operations. Retrofit cost
  is bounded (insert a `proposal` phase ahead of ~8 endpoints); design
  doesn't need to anticipate it now.
* **Webhooks / external event subscribers.** Audit event vocabulary
  is stable from MVP (§10), so this is delivery-layer additive.
* **Bulk operations** (mass-invite, mass-remove, mass-export). Each
  is a new endpoint on top of the per-item ones; additive.
* **WASM / plugin extensions.** Communities extend via Rego + JSON
  blobs, not custom code. Hard "no" in MVP.
* **i18n at the resource layer** (translated profile fields, role
  names, policy messages). Migration plan: introduce
  `name_translations` field with fallback to `name`. Not
  architecturally load-bearing — defer with confidence.
* **VPC (Persona credentials)** beyond reserving the type. Land in
  v2 when display-identity needs concrete.
* **Bilateral VRC counter-signing.** Self-issued only in MVP.
* **TEE / Nitro Enclave deployment** of the VTC binary. The vsock
  store parity work in `vti-common` carries over when needed.
* **VTC-to-VTC community migration tooling.** Config export +
  community-data backup already give operators the primitives;
  packaged migration scripts are a follow-up.
* **Onboarding state machine** for new members ("welcome flow",
  required first actions). Encode in policy + admin UX initially.
* **Multi-tenant** (one VTC binary hosts multiple communities).
  Architectural rewrite, intentionally out.

## 19. Related work

* `docs/05-design-notes/runtime-service-management.md` — the service-
  advertisement primitives the VTC inherits via `vta-sdk`.
* `docs/03-integrating/provision-integration.md` — how the VTC's own
  DID is minted from its VTA.
* `docs/05-design-notes/pnm-setup-deferred-vta-did.md` — the deferred-
  DID pattern, useful reference for the VTC install flow.
* [`openvtc/dtg-credentials`](https://github.com/OpenVTC/dtg-credentials)
  — the credential catalog.
* [`affinidi/affinidi-trust-registry-rs`](https://github.com/affinidi/affinidi-trust-registry-rs)
  — TRQP v2.0 server + client.
* [`affinidi/affinidi-tdk-rs`](https://github.com/affinidi/affinidi-tdk-rs)
  — `affinidi-status-list`, `affinidi-vc`, `affinidi-data-integrity`.
