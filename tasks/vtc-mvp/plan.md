# Plan: VTC MVP — Phase 0

Companion to `docs/05-design-notes/vtc-mvp.md`. This document is the
implementation plan for Phase 0. `todo.md` is the actionable task
list with acceptance criteria.

## Objective

Stand up the **DID + auth foundation** for the VTC MVP:

- `vtc-host` DID template in `vta-sdk` so the VTC can mint its own
  `did:webvh` via the existing `provision-integration` flow.
- A minimal CLI wizard (`vtc setup`) that mints the seed, provisions
  the VTC DID, initialises all keyspaces, and hands off to the admin
  web UX via a one-time install URL.
- A WebAuthn-bound install flow that turns the install token into a
  bootstrapped admin DID with multi-passkey support from day one.
- Cross-cutting hygiene primitives (Trust-Task extractor, versioned
  audit envelope with HMAC actor hashing, scoped idempotency cache,
  cursor pagination) added to `vti-common` so every endpoint that
  ships in Phase 1+ inherits them.
- Community profile + runtime configuration plumbing (read/write
  config via REST, reload, restart-with-supervisor-handshake).
- Path-prefix routing default with cookie-scope isolation invariants
  enforced at config-load time.

Phase 0 is the gate that unblocks every subsequent phase. Nothing
here issues credentials, evaluates policy, or touches the trust-
registry — those are Phases 1-3.

## Scope

### In scope (per spec §16)

Spec §3, §4, §5.1, §5.3, §9.1, §9.2, §9.3, §9.4 (MVP soft gate),
§9.5 (Phase-0 subset), §10.4 (admin promotion plumbing — endpoint
stub only, since "members" don't fully exist yet), §11.1, §11.4
(envelope only; full vocabulary in Phase 1), §14.2, §14.4.

### Out of scope

- Member CRUD, join requests, policies, regorus — Phase 1+
- VMC / VEC / status-list issuance — Phase 2
- Trust-registry publishing — Phase 3
- VRC, personhood — Phase 4
- Public website, admin UX bundling, subdomain routing test
  surface — Phase 5
- DIDComm transport for Phase 0 operations (passkey ops are REST-
  only by spec; install is REST-only by nature; admin/config and
  community/profile DIDComm twins land in Phase 1)

## Dependency graph

```
                M0.1 hygiene primitives (vti-common)
                ╱      │           │           ╲
       ┌──────┘       │           │            └──────┐
       ▼              ▼           ▼                   ▼
  M0.3 /v1/   M0.7 community   M0.8 config     M0.4 install token
  migration   profile          plumbing        + carve-out
       │              │           │                   │
       │              │           │                   ▼
       │              │           │           M0.5 WebAuthn claim flow
       │              │           │                   │
       │              │           │                   ▼
       │              │           │           M0.6 admin bootstrap
       │              │           │           + multi-passkey schema
       │              │           │                   │
       │              │           │                   ▼
       │              │           │           M0.10 emergency bootstrap
       └──────────────┴───────────┴───────────────────┘
                          │
                          ▼
              M0.11 routing + CORS + cookie-scope
                          │
                          ▼
              M0.12 install-flow integration tests

  M0.2 vtc-host template (vta-sdk) — fully parallel with M0.1
  M0.9 CLI setup wizard — depends on M0.2 + M0.4
```

Critical path: M0.1 → M0.4 → M0.5 → M0.6 → M0.10 → M0.11 → M0.12.

Parallelisable side tracks:

- **M0.2** (DID template in `vta-sdk`) is in a different crate and
  has no internal dependencies — can start at day one.
- **M0.7** (community profile) and **M0.8** (config plumbing) only
  depend on M0.1; can be developed concurrently once M0.1.4 lands.
- **M0.9** (CLI wizard) needs M0.2 and the install-token primitive
  from M0.4 but not the WebAuthn server side.

## Milestones

| ID | Title | Critical path | Description |
|---|---|---|---|
| **M0.1** | Hygiene primitives | ✓ | Trust-Task extractor, audit envelope + HMAC, idempotency keyspace, cursor pagination. Lands in `vti-common`. Everything downstream depends on these. |
| **M0.2** | `vtc-host` DID template | parallel | New built-in template in `vta-sdk::did_templates`. Provisionable via the existing `provision-integration` flow against any running VTA. |
| **M0.3** | `/v1/` URL migration | ✓ | Move existing routes under `/v1/` prefix, wire the Trust-Task extractor, add Trust-Task-exempt path for `/health`. Migration is destructive to the public surface but pre-Phase-0 there are no external consumers. |
| **M0.4** | Install token + carve-out | ✓ | Single-use signed JWT install token (15-min TTL, embedded WebAuthn ceremony nonce + ephemeral keypair) and process-wide async mutex around the install carve-out. |
| **M0.5** | WebAuthn claim flow | ✓ | `POST /v1/install/claim` accepts the WebAuthn assertion bound to the token's nonce; Ed25519-only; cosigned DID-binding challenge proves same-key control. |
| **M0.6** | Admin bootstrap + multi-passkey schema | ✓ | `POST /v1/admin/bootstrap` writes first ACL admin entry; ACL schema extended for `passkeys: Vec<RegisteredPasskey>`; passkey register/revoke/list with step-up UV reauth and CAS-protected last-passkey check. |
| **M0.7** | Community profile | parallel | `CommunityProfile` schema; `community` keyspace; `GET / PUT /v1/community/profile` with `extensions: JsonValue` slot. |
| **M0.8** | Config plumbing | parallel | Three-layer config overlay (env > db > toml > defaults); `config` keyspace; `GET / PATCH /v1/admin/config`; reload/restart/export/import. Restart endpoint refuses without supervisor handshake. Sensitive-path PATCH gated by directory allowlist. |
| **M0.9** | CLI setup wizard | parallel | Rewrite `vtc setup` to the minimal 3-question wizard. Mints seed, calls VTA provision-integration with `vtc-host`, initialises keyspaces, mints install token, prints install URL. Replaces the existing 930-line setup.rs. |
| **M0.10** | Emergency bootstrap | ✓ | `vtc admin emergency-bootstrap` on a stopped daemon, gated by master seed mnemonic possession (not just stopped-daemon). Loud audit event on next boot. |
| **M0.11** | Routing + CORS + cookie-scope | ✓ | Path-prefix routing config; admin session cookie scoped to `/admin`; CORS allowlist with wildcard refusal; cookie-scope invariant verified at config-load time. |
| **M0.12** | Install-flow integration tests | ✓ | End-to-end test exercising the install + bootstrap + first-admin-passkey path through `Router::oneshot`, plus the emergency-bootstrap path. Phase 0 gate. |

## Pre-implementation design decisions

Each of these is a small but real decision that should land before
the corresponding milestone starts. Recorded here so they're visible
not buried inside individual tasks.

| ID | Decision | Required before | Default we'll adopt unless we agree otherwise |
|---|---|---|---|
| **D1** | Trust Task `schema.json` shape | M0.1.1 | JSON Schema draft 2020-12. Single schema file per task with `$id` matching the Trust Task URL. |
| **D2** | WebAuthn ceremony nonce ↔ install-token binding | M0.4 | Token carries a `cnonce` claim (32 bytes, base64url-encoded). Server stores the nonce alongside the install-token state; claim flow requires the WebAuthn `clientDataJSON.challenge` to match `cnonce`. **Token consumption follows webvh-common's `claimed_at` window pattern** (D12), not immediate single-use. |
| **D3** | `audit_key` storage + lifecycle | M0.1.2 | Per-community 32-byte HMAC-SHA256 key. Initial key derived via `HKDF-SHA256(master_seed, info: "vtc-audit-key/v1", salt: empty)`. Subsequent rotations generate fresh random keys (not deterministic). See **D10** for the full rotation/retention policy. |
| **D4** | `extensions` size limit | M0.7 | 16 KiB per `extensions` JSON blob. Larger blobs return 413. Configurable later if needed. |
| **D5** | Existing `vtc-service` code reuse strategy | M0.9 | **The existing `vtc-service` is throw-away** — it predates the spec rewrite and should not be salvaged. The **VTA service (`vta-service`) is the latest working reference implementation** for setup, did:webvh creation, secret-store wiring, and route patterns. M0.9.1 reviews `vta-service`, not the current `vtc-service`. Anything genuinely shared between VTA and VTC (config types, store abstractions, auth extractors, audit, WebAuthn) lives in `vti-common`. The new `vtc-service` shape emerges as a thin consumer of `vti-common` + `vta-sdk`. |
| **D6** | Idempotency "destructive op" identification | M0.1.3 | Explicit annotation on the route at attach time (`.with_idempotency(IdempotencyClass::Destructive)`). **Clarity-over-cleverness**: a future reader of the route file sees the class directly next to the handler, with no heuristic to reverse-engineer. Default class is `NonDestructive` (24 h TTL); destructive routes are explicit. |
| **D7** | WebAuthn `RP ID` derivation | M0.5 | **Single source: `public_url` config field, parsed as a URL; `rp_id = url.domain()`, `origin = url`.** Adopted directly from `webvh-common::server::passkey::build_webauthn`. Drop the earlier multi-source cascade — webvh-service proves the single-field pattern is robust enough and operator-friendly. Operator runbook (spec §17 Q6) covers domain-migration consequences. |
| **D8** | Trust-Task `Trust-Task` HTTP header name | M0.1.1 | Literal `Trust-Task`. Reserved against future workspace conflict. |
| **D9** | Route-attachment macro vs explicit registration | M0.1.1 | Explicit registration via a typed `TrustTaskRouter` builder. No macros for MVP — readable, debuggable. |
| **D10** | `audit_key` rotation cadence + retention | M0.1.2 | **Rotation triggers**: (a) RTBF event (immediate, key-id specific); (b) **routine annual rotation** (background task wakes hourly, rotates when `last_rotated_at` is > 365 days old; configurable as `audit.routine_rotation_days`); (c) explicit `vtc admin rotate-audit-key` CLI. **Retention**: **all prior keys retained indefinitely** in the `audit_key` keyspace — 32 bytes each, one rotation/year × 100 years = 3.2 KB. Lookups walk newest-first. Each entry: `{ key_id: Uuid, key: [u8;32] (encrypted via store::encryption), valid_from, valid_until: Option, rotation_reason: enum }`. Verification walks all keys until one verifies (typical case is the active key; pre-rotation hashes only need older keys during compliance investigations). |
| **D11** | WebAuthn / passkey infrastructure location | M0.1 + M0.5 | **Lives in `vti-common::auth::passkey`**, adopting the `webvh-common::server::passkey` pattern. Components: `PasskeyState` trait (services implement it), `build_webauthn(public_url) -> Webauthn` helper, `Enrollment` + `PasskeyUser` + `CredentialMapping` storage types, `enroll_start` / `enroll_finish` / `login_*` route handlers generic over `S: PasskeyState`. The `vtc-service` implements `PasskeyState` on its `AppState`; VTA can later implement it too if it needs admin-passkey auth. This is a new task **M0.1.6** added to Phase 0. |
| **D12** | Install-token consumption pattern | M0.4 | **Adopt webvh-common's `claimed_at` window**, not immediate single-use. State machine: `Issued { exp, cnonce, ephemeral_privkey }` → on `enroll_start` (= our `/v1/install/claim/start`) set `claimed_at` (locks concurrent claims for `ENROLLMENT_CLAIM_WINDOW_SECS = 300`) → on successful WebAuthn ceremony, **consume** → on failure or 5-minute timeout, allow retry. The carve-out only closes after `POST /v1/admin/bootstrap` succeeds. This protects legitimate operators from denial-of-service caused by a stolen URL being clicked-then-abandoned. |
| **D13** | `Debug` redaction of bearer secrets | M0.4, M0.5, M0.6 | **Adopt webvh-common's manual `Debug` impl pattern**: types holding bearer tokens (install token, session token, refresh token, idempotency key) implement `Debug` manually, printing only a short prefix or `<redacted>` for the secret. Prevents accidental log leakage via stray `tracing::debug!(?token, …)`. Codified as a workspace-wide pattern in CLAUDE.md after Phase 0 lands. |

## Parallelisation strategy

After M0.1 ships, three concurrent tracks open up:

1. **Install + auth track** (critical path): M0.4 → M0.5 → M0.6 → M0.10
2. **Surfaces track**: M0.7 (community profile) and M0.8 (config)
   land independently; can be a second engineer's queue.
3. **DID-template track**: M0.2 lands without any internal deps and
   can be picked up as the first "real" change (lowest-risk PR to
   sanity-check the workflow).

M0.11 (routing) is a single-engineer task that gates M0.12 and is
the last thing on the critical path; it touches all surfaces, so
it lands after the other tracks merge.

## Checkpoints

Five checkpoints between milestones. Each is a green-build gate
plus a working capability the team can demo.

- **CP-A — Hygiene foundation green.** After M0.1: Trust-Task
  extractor + audit envelope + idempotency keyspace + cursor
  pagination are unit-tested and exported from `vti-common`. No
  consumer yet, but the primitives compile and have golden tests.

- **CP-B — DID template provisionable.** After M0.2: a developer
  can stand up a fresh VTA, point the existing
  `vta bootstrap provision-integration` flow at the new `vtc-host`
  template, and receive a sealed bundle containing a valid
  `did:webvh` for a VTC. No VTC binary needed yet.

- **CP-C — Install-token primitive works.** After M0.4: install
  tokens can be minted and atomically consumed; concurrent claims
  on the same token race correctly through the mutex. No WebAuthn
  yet; tests exercise the JWT plumbing only.

- **CP-D — End-to-end first-admin install.** After M0.6: a fresh
  VTC binary can be set up, the install URL claimed via WebAuthn
  in a test harness, the admin DID bootstrapped, and a second
  passkey registered against the same admin. The community has its
  first admin and the install carve-out is permanently closed.

- **CP-E — Phase 0 gate met.** After M0.12: full install flow runs
  through Router::oneshot, including emergency-bootstrap
  recovery; community profile and config endpoints work; routing +
  cookie-scope + CORS invariants enforced; all Phase-0 endpoints
  have Draft Trust Task spec files on disk. Phase 1 can start.

## Reference implementations

We don't invent these patterns. They're already in production.

| Topic | Reference | What we adopt |
|---|---|---|
| WebAuthn / passkey enrolment + login | [`affinidi/affinidi-webvh-service` — `webvh-common/src/server/passkey/{mod,store,routes}.rs`](https://github.com/affinidi/affinidi-webvh-service/tree/main/webvh-common/src/server/passkey) | `PasskeyState` trait, `build_webauthn(public_url)` helper, `Enrollment` token shape with `claimed_at` window, `PasskeyUser` + `CredentialMapping` storage, route handlers generic over `S: PasskeyState`, redacted-token `Debug` impls. |
| `public_url` ↔ `RP ID` derivation | `webvh-common::server::passkey::build_webauthn` | Single-source `public_url` → `Webauthn` builder. |
| Setup wizard / did:webvh creation / secret-store wiring | The workspace's own `vta-service` — current latest impl. | The shape of an install/setup module that's actually production-ready. The current `vtc-service` is **not** a reference — it's throw-away. |
| Audit envelope shape, store abstractions, JWT auth | `vti-common` itself (existing) + `vta-service` consumers | Extend in place per the new spec; don't fork. |

## Risks

| Risk | Mitigation |
|---|---|
| **WebAuthn test harness complexity.** Browser WebAuthn ceremonies are not trivial to fake in Rust tests. | `webauthn-rs` ships a deterministic test mode; webvh-common already proves this pattern in production. M0.5 includes a separate task to validate the harness works end-to-end before any production code depends on it (task M0.5.0). |
| **Ed25519-only authenticator availability.** Apple Touch ID / Windows Hello typically default to ES256, not EdDSA. The spec mandates Ed25519 for the passkey ↔ DID binding. | Acknowledged in spec §4.2. Operators see an install error pointing at supported devices. Cover in operator-facing docs alongside M0.9. Long-term: revisit if Ed25519 adoption stalls. |
| **Replacing the existing 930-line setup.rs.** A lot of did:webvh creation logic lives there; some of it is reusable. | M0.9 has an explicit "salvage pass" sub-task to identify reusable helpers before the bulk rewrite. |
| **Config migration from existing `vtc-service` layout.** Current config has fields the new spec doesn't, and vice versa. | M0.8 includes a sub-task for config migration: existing TOML keys map to the new shape; unknown keys log a warning rather than fail. |
| **`/v1/` URL migration breaks existing integration tests.** | M0.3 migrates the tests in lockstep. The current public surface has no external consumers (pre-MVP), so the change is in-tree only. |
| **Trust Task source repo location decision (spec §17 Q3) not yet made.** | Treat `trust-tasks/` in this workspace as authoritative for MVP. Spec already notes this as an open question; revisit when VTA-side tasks appear. |

## Definition of done — Phase 0

All of the following must hold for Phase 0 to be considered complete
and Phase 1 to start:

1. `cargo build` and `cargo test` green workspace-wide.
2. `cargo clippy -- -D warnings` clean.
3. `cargo fmt --check` clean.
4. A developer can run `vtc setup` against a freshly-provisioned VTA
   and reach the install URL.
5. The install URL can be claimed end-to-end in an integration test
   (mocked WebAuthn ceremony) and produces a bootstrapped admin DID
   with a working session.
6. A second passkey can be registered against the same admin DID.
7. `vtc admin emergency-bootstrap` works when the master seed
   mnemonic is provided.
8. `GET /v1/community/profile` returns the configured profile;
   `PUT` updates it.
9. `GET / PATCH /v1/admin/config` round-trips a setting.
10. `POST /v1/admin/config/restart` refuses without
    `VTC_SUPERVISED=1`; accepts with it.
11. Routing config in path-prefix mode mounts `/v1`, `/admin`, `/`
    correctly; cookie-scope isolation invariants enforced.
12. Every Phase-0 REST endpoint has a Draft `trust-tasks/.../spec.md`
    + `schema.json` on disk; manifest `trust-tasks/index.json` is
    populated.
13. Each milestone landed via its own DCO-signed PR; commits formatted
    per workspace conventions.
14. Memory entry `project_vtc_mvp.md` updated to reflect any
    discovered design tweaks (mirror of the "Phase 1 outcome" notes
    in the prior DIDComm plan).
