# Auth-architecture consolidation (S1+S2+S3)

**Status**: landed in vti-common 0.7 + vta-sdk 0.7 + did-hosting-common
0.8 + `@openvtc/rp-sdk` 0.1.0. May 2026.

## Problem

Five separate codebases each carried their own implementation of the
`/auth/challenge` → `/auth/authenticate` → `/auth/refresh` flow:

| Service                | Transport(s)        | KeyspaceHandle  | Role enum     |
|------------------------|---------------------|-----------------|---------------|
| `vta-service`          | REST + DIDComm      | `vti-common`    | `vti-common`  |
| `vtc-service`          | REST + DIDComm      | `vti-common`    | `VtcRole`     |
| `did-hosting-control`  | REST (SIOPv2)       | `did-hosting`   | `did-hosting` |
| `did-hosting-server`   | DIDComm             | `did-hosting`   | `did-hosting` |
| `did-hosting-witness`        | DIDComm             | `did-hosting`   | `did-hosting` |

The flow logic was 90% identical across all five. The 10% that
differed (TEE attestation on VTA, SIOPv2 id_token verification on
did-hosting-control, per-DID rate-limit shape, JWT minter) had
drifted in subtle, security-relevant ways. The May 2026 cross-system
security review surfaced:

- VTA + VTC had no per-DID challenge rate limit; did-hosting-server +
  did-hosting-witness had one but used an O(N) prefix-scan; did-hosting-control
  had an O(1) tracker.
- `session_pubkey_b58btc` support existed only on did-hosting-control;
  server + witness silently ignored the field.
- AAL preservation across refresh was added in three places by hand
  instead of once at the trait layer.
- VTC's refresh response shape lagged behind the canonical
  `{ session, tokens }` from the SIOPv2 spec.

The structural fix is one canonical implementation that all five
services dispatch to. Per-service variation lives in a thin
`AuthBackend` impl, not in copy-pasted route handlers.

## Trait shape

```rust
#[async_trait]
pub trait AuthBackend: Send + Sync + 'static {
    type Store: SessionStore;
    type Error: From<AuthError> + Debug + Send + Sync + 'static;
    type Role: std::fmt::Display + Serialize + Clone + ...;

    fn sessions(&self) -> &Self::Store;

    async fn mint_access_token(
        &self, subject: &str, session_id: &str, role: &Self::Role,
        contexts: &[String], amr: &[String], acr: &str,
        tee_attested: bool, ttl_secs: u64,
    ) -> Result<String, Self::Error>;

    async fn check_acl(&self, did: &str)
        -> Result<RoleResolution<Self::Role>, Self::Error>;

    // Default-method policy hooks — backends override only when needed.
    async fn validate_did(&self, _did: &str) -> Result<(), Self::Error> { Ok(()) }
    async fn attest_challenge(&self, _: &[u8; 32]) -> Result<AttestationOutcome, Self::Error> { ... }
    fn max_pending_challenges_per_did(&self) -> usize { 10 }
    fn audit(&self, event: AuthAuditEvent<'_>) { /* tracing::info!(audit=true, ...) */ }

    fn challenge_ttl(&self) -> u64;
    fn access_token_ttl(&self) -> u64;
    fn access_token_ttl_for_aal2(&self) -> u64 { max(60, self.access_token_ttl() / 3) }
    fn refresh_token_ttl(&self) -> u64;
    fn didcomm_freshness_window(&self) -> u64 { 60 }
}
```

### Associated types over generic params

`type Store`, `type Error`, `type Role` rather than `<S, E, R>`
generic parameters on every handler call. Each backend has
*exactly one* concrete impl; nobody wants `handle_challenge::<KeyspaceSessionStore,
AppError, Role>(backend, input)` at every call site. The
trade-off is that you can't have two `AuthBackend` impls with
the same `Self::Store` but different `Self::Error` for one
service — which would be nonsensical anyway.

### Why `Error: From<AuthError>` instead of returning `AuthError` directly

The canonical handler raises typed `AuthError` variants
(`Forbidden`, `ChallengeMismatch`, `SignerMismatch`, etc.). Each
backend's local error type (`vti_common::error::AppError`,
`did_hosting_common::server::error::AppError`) converts via
`From<AuthError>` so the route layer's existing `IntoResponse`
plumbing renders the response — no backend-specific glue.

A backend that wants to log or instrument the typed variant
before conversion can implement a richer `From<AuthError>`. The
default conversion maps each variant to the standard HTTP
status (Forbidden → 403, ChallengeMismatch → 401, etc.) plus
the canonical body shape.

## `SessionStore` trait

```rust
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    type Error: Debug + Send + Sync + 'static;
    async fn store_session(&self, s: &Session) -> Result<(), Self::Error>;
    async fn get_session(&self, id: &str) -> Result<Option<Session>, Self::Error>;
    async fn delete_session(&self, id: &str) -> Result<(), Self::Error>;
    async fn store_refresh_index(&self, token: &str, sid: &str) -> Result<(), Self::Error>;
    async fn take_session_id_by_refresh(&self, token: &str) -> Result<Option<String>, Self::Error>;
    async fn count_pending_challenges(&self, did: &str) -> Result<usize, Self::Error>;
}
```

Two impls ship in the workspace:

- `vti_common::auth::handlers::KeyspaceSessionStore` — wraps
  `vti_common::store::KeyspaceHandle` (enum dispatch: local
  fjall, vsock-proxied). VTA + VTC use it directly.
- `did_hosting_common::server::auth::DidHostingSessionStore` —
  wraps did-hosting's `KeyspaceHandle` struct (separate trait
  with fjall / Redis / DynamoDB / Firestore / Cosmos DB
  backends). did-hosting-control + server + did-hosting-witness use it.

A future Redis-backed direct impl could ship here when the
canonical handler runs in a cloud deployment; the trait
boundary keeps the canonical flow agnostic.

### `take_session_id_by_refresh` — atomic GETDEL semantics

The classic Redis-`GETDEL` shape. Exactly one concurrent caller
observes `Some` for any given refresh token; the cross-replica
race is closed at the storage layer.

- `vti_common::store::KeyspaceHandle::take_raw` runs `get + remove`
  inside a single `blocking_with_timeout` closure on `LocalKeyspaceHandle`
  (single-process fjall serialises per-keyspace). On `Vsock` it falls
  back to two RPCs with a per-call `warn!()` and a doc note — single-
  replica TEE deployments are unaffected; cross-replica vsock would
  need a new opcode.
- did-hosting's `KeyspaceHandle::take_raw_atomic` delegates to the
  backend trait, which has primitives for each cloud store's atomic
  GETDEL equivalent.

## Canonical flows

### `/auth/challenge`

1. `validate_did` (backend hook; default no-op).
2. `check_acl` (raises `Forbidden` on miss / expired).
3. Per-DID rate limit (`count_pending_challenges` vs.
   `max_pending_challenges_per_did`).
4. Mint 32-byte hex challenge from OS RNG.
5. Optional `attest_challenge` (backend hook; default not-
   attested).
6. Persist `ChallengeSent` session with `tee_attested` from
   step 5 and empty `amr`/`acr`.
7. Emit `ChallengeIssued` audit event.
8. Return canonical `ChallengeResponse`.

### `/auth/`

Transport-specific layer (REST JSON parse / DIDComm
`unpack_signed` / SIOPv2 JWS verify) produces an
`AuthenticateInput { session_id, challenge, signer_did,
created_time?, session_pubkey_b58btc? }`. The canonical handler:

1. Load session by `session_id`; reject if missing or already
   `Authenticated`.
2. Constant-time challenge match.
3. `signer_did == session.did` (load-bearing — without this any
   leaked challenge could be redeemed by any signer).
4. Challenge TTL + DIDComm `created_time` freshness window.
5. Re-look-up ACL role (propagates revocation between issue and
   use).
6. `mint_access_token` (backend hook). TTL = `access_token_ttl_for_aal2`
   if `acr == "aal2"`, else `access_token_ttl`.
7. Transition session → `Authenticated`, persist
   `(amr, acr, refresh_token, refresh_expires_at,
   session_pubkey_b58btc?)`.
8. Emit `Authenticated` audit event.
9. Return canonical `AuthenticateResponse { session, tokens }`.

### `/auth/refresh`

1. **Atomic claim** of the `refresh_token → session_id` index via
   `take_session_id_by_refresh`. Exactly one caller proceeds per
   token, cross-replica safe.
2. Load session.
3. (DIDComm transports) `signer_did == session.did` binding.
4. State check (`Authenticated`).
5. Refresh-token expiry check.
6. **Preserve `(amr, acr)`** from the pre-rotation session. A
   step-upped `aal2` session stays at `aal2` across rotation
   instead of dropping to `aal1`.
7. Delete old session.
8. Re-look-up ACL role.
9. Mint new session (new `session_id`, access token, refresh
   token; AAL preserved; TTL acr-dependent).
10. Emit `Refreshed` audit event.
11. Return canonical `AuthenticateResponse`.

## What stays out of the trait

- **Transport** (REST vs. DIDComm) — the canonical handler takes
  the pre-extracted `*Input` struct; transport-specific
  unpacking stays in the route handler.
- **id_token-internal checks** (SIOPv2 `aud`, `iat`, `exp`) —
  these are properties of the SIOPv2 token, not the
  challenge-response session. did-hosting-control's route
  handler runs them before dispatching to the canonical
  handler.
- **Wire-shape serialisation** — canonical request / response
  types live in `vta_sdk::protocols::auth` and are shared with
  clients.
- **The `StepUpAuth` extractor** — separate from the canonical
  handler; runs on every gated route the handler doesn't own.

## Cross-repo dependency

did-hosting's repo doesn't currently consume vti-common from
crates.io. During the consolidation window, did-hosting-common
and its consumers pin `vti-common` and `vta-sdk` by git rev
(same rev for both, kept in lock-step). When this PR merges and
vti-common 0.7 + vta-sdk 0.7 publish, the git deps flip to
`version = "0.7"`.

A standalone follow-up PR makes that flip — it's a five-line
Cargo.toml change in each of `did-hosting-common`,
`did-hosting-control`, `did-hosting-server`, `did-hosting-witness`,
and the workspace root.

## Security review follow-ups closed by the consolidation

| ID  | Item                                                  | How                                                   |
|-----|-------------------------------------------------------|-------------------------------------------------------|
| H3  | server/witness O(N) rate-limit scan                   | canonical handler uses O(1) backend count             |
| H4  | VTA/VTC missing per-DID rate limit                    | canonical handler enforces it everywhere              |
| H5  | `allowed_did_methods` error leak                      | canonical `Forbidden` swallows the configured list    |
| L3  | `session_pubkey_b58btc` only on did-hosting-control   | now threaded through `AuthenticateInput` everywhere   |
| M3  | DIDComm freshness window not enforced on VTA/VTC      | `msg.created_time` now threaded into `AuthenticateInput` |

Each of H1/M1/M2/M4/M5/M6/L1/L2/L4 land as point-fixes in
focused commits. See the CHANGELOG `Unreleased` block for
per-item commit pointers.

## Open follow-ups

- **vti-common 0.7 + vta-sdk 0.7 publish to crates.io.** Once
  this PR merges, two `cargo publish` runs from main.
- **did-hosting flip to crates.io deps.** Five-line follow-up
  PR in the did-hosting repo.
- **H1 operator-visible flow** — settings toggle, first-enroll
  passkey ceremony, migration UX for existing plaintext
  wallets, lock/unlock surfaced from the popup. Infrastructure
  is in (`SecretWrap` trait + `WebAuthnPrfSecretWrap` impl);
  not yet auto-enabled in `holder.ts`.
- **L5 — workspace lint for trust-task `recipient` enforcement.**
  Tooling-heavy; needs its own design pass.
