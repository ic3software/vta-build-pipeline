# VTC MVP — Phase 5 plan

> **Status:** draft, awaiting review.
> **Deliverable:** "MVP complete." Per spec §16 Phase 5: public
> website (filesystem-backed, CSP, path safety), admin UX consumed
> via `build.rs` (release-key-signed tarball), path-prefix routing
> default + subdomain support.
> **Spec:** `docs/05-design-notes/vtc-mvp.md` §§9.2, 9.3, 9.5,
> 9.6, 12.1, 12.2, 14.4, 16, 18.

## Objective

After Phase 5, a single VTC binary serves three explicit surfaces
on one process — the JSON/DIDComm API, a baked-in admin SPA, and
an operator-managed static public website — with the cookie-scope
+ CSRF + CSP invariants the spec promises:

- The router separates **API** (`/v1/*`), **admin UX**
  (`/admin/*`), and **public website** (`/*` catch-all) onto
  distinct mounts. Route priority `/health` > `/v1/*` >
  `/v1/website/*` > `/admin/*` > `/*` is enforced at attach
  time. Subdomain mode dispatches by `Host` header; unmatched
  hosts return 404 (no silent fall-through to the website
  catch-all).
- A configured **CORS allowlist** is enforced (already in
  Phase 0); wildcards refused; the public-site origin is
  **not** auto-allowed for admin endpoints. Admin mutating
  endpoints require either `Sec-Fetch-Site: same-origin` or a
  CSRF double-submit cookie. Public-site form POSTs to
  `/v1/join-requests` work via simple-request semantics — no
  preflight, no CSRF token.
- The **public website** serves a filesystem tree at
  `website.root_dir` with full path safety (NFC, no symlinks
  out, no hidden files, no executable bits, MIME-from-extension)
  and a per-site-configurable CSP defaulting to `default-src
  'self'; script-src 'self'; object-src 'none'; base-uri 'self'`.
  ETag + Cache-Control + an FD cache support CDN fronting.
- A **website management API** under `/v1/website/*` (REST-only
  per §9.6) lets the admin upload single files, delete files,
  list / read, and deploy bundles. In `live` mode bundles
  extract to a staging directory + rename atomically; in
  `managed` mode they create new `gen-N/` directories under
  `root_dir` and flip the `current → gen-N` symlink, retaining
  the last 5 generations. Website routes carry a per-route
  body-cap override (`max_bundle_size_mb`, `max_file_size_mb`).
- The **admin UX** is a static SPA baked into the binary via
  `build.rs` from a SHA-256-pinned, OpenVTC-release-key-signed
  tarball published by the sibling
  [`OpenVTC/vtc-admin-ui`](https://github.com/OpenVTC/vtc-admin-ui)
  repo. `VTC_OFFLINE_BUILD=1` uses a vendored placeholder so CI
  + air-gapped builds work without a network fetch.
  `admin_ui.mode = "embedded"` (default) serves the baked SPA;
  `mode = "external"` skips embedding and writes the operator-
  supplied origin into `cors.allowed_origins`.
- WebAuthn **RP ID** rule: path mode → base host; subdomain mode
  → base domain (so passkeys stay valid across the API +
  admin-UX subdomains). Migrating the admin UX to a different
  base domain re-registers all passkeys (documented in the
  operator runbook).
- New **audit variants**: `WebsiteFileWritten`,
  `WebsiteFileDeleted`, `WebsiteBundleDeployed`,
  `WebsiteGenerationRolledBack`, `AdminUiServed` (one-shot per
  daemon boot, recording the embedded-tarball digest).
- New **Trust Tasks** (8 total) for the website management +
  rollback endpoints (admin UX surfaces no new tasks — it
  consumes the existing `/v1/*` API).
- Phase 5 **closes the MVP gate**.

Out of scope (per §18 and reaffirmed below; do not let them
drift in):

- TEE / Nitro enclave deployment — permanent non-goal (§3-K).
- Multi-tenant binary, multi-process daemons.
- N-of-M admin approvals.
- Webhooks / external event subscribers (the §11.4 audit
  vocabulary is the surface; delivery is a follow-up).
- Bulk operations (mass-invite / mass-remove / mass-export).
- WASM / plugin extensions on the website (no template engine,
  no opinions about structure — spec §12.1 is explicit).
- S3 / external filesystem backends beyond `website.root_dir`.
- i18n at the resource layer.
- Onboarding state machine.
- VTC-to-VTC community-migration tooling.
- Bilateral VRC counter-signing.
- VPC beyond type-reservation.

## Scope (per spec §16, Phase 5 row)

### In scope

- **Routing surface separation** (§9.2). `TrustTaskRouter`
  composes one combined `axum::Router` whose routes attach
  under the configured `routing.api.mount` / `admin_ui.mount`
  / `website.mount` prefixes. The Phase-0
  `validate_routing` invariants already cover collisions +
  cookie scope; Phase 5 adds subdomain-mode dispatch.
- **Subdomain-mode dispatch** — a tower middleware reads
  `Host` and routes to one of three sub-routers when any
  surface has `host` set; unknown hosts → 404.
- **CSRF middleware** on admin mutating endpoints
  (`POST/PUT/PATCH/DELETE` under `routing.api.mount` when
  the request carries the admin session cookie OR when the
  caller's session role is `Admin` / `SuperAdmin`). Allow
  pass-through when either:
  - `Sec-Fetch-Site: same-origin` is present, OR
  - The double-submit cookie + matching `X-CSRF-Token`
    header match.
  Public `/v1/join-requests` POST is **exempt** (simple-
  request semantics, see §9.3).
- **Admin session cookie** (new, see D5) — the bearer JWT
  stays for programmatic clients; the admin UX gets a
  parallel cookie session set with
  `Path=/admin; SameSite=Strict; Secure; HttpOnly`. The
  CSRF double-submit cookie pairs with this session.
- **Cookie-scope isolation invariant** — when admin UX +
  website share the same origin, the admin cookie's
  `Path=/admin` ensures public-site JS cannot read it.
  Explicit tests exercise this.
- **§14.4 runtime guards now land** (see D11) — Phase 0–4
  didn't actually wire `tower-governor` or the 1 MB global
  body cap; Phase 5 lands both, with the body-cap exception
  for website routes.
- **Public website (`website` feature)** at `website.root_dir`:
  - `live` mode (default): serve as-is; bundle extracts to
    `<root_dir>.staging.<timestamp>/` then `rename(staging,
    root_dir)`.
  - `managed` mode: `root_dir/gen-N/` directories; current
    pointer via `root_dir/current → gen-N` symlink.
    Retention default 5 generations (configurable). Rollback
    flips the symlink.
  - Path safety per spec §12.1 (NFC, canonicalised,
    no-escape, no-symlink-follow, no-hidden, no-exec-bit,
    extension blocklist `.cgi/.php/.exe`).
  - MIME via `mime_guess`; `X-Content-Type-Options: nosniff`
    always.
  - Default CSP `default-src 'self'; script-src 'self';
    object-src 'none'; base-uri 'self'`; per-site override
    via a `<root_dir>/.vtc-website.toml` config file
    (operator can opt into looser CSP for SPA-style sites).
  - ETag from SHA-256 of content; `Cache-Control`
    configurable (`website.cache_control` default
    `"public, max-age=300"`).
  - Live-mode FD cache TTL `website.live_cache_ttl_seconds`
    default 5.
  - Form POST target is `/v1/join-requests` directly. No
    proxy endpoint.
- **Website management API** (§9.5):
  - `GET /v1/website/files` — list (cursor paginated).
  - `GET /v1/website/files/{path}` — read.
  - `PUT /v1/website/files/{path}` — write one file.
  - `DELETE /v1/website/files/{path}` — delete one file.
  - `POST /v1/website/deploy` — upload tar.gz bundle.
  - `GET /v1/website/generations` — managed-mode only.
  - `POST /v1/website/rollback/{gen}` — managed-mode only.
  - All admin-gated; body-cap overrides per §14.4.
- **Admin UX (`admin-ui` feature)**:
  - `build.rs` fetches a SHA-256-pinned, signed tarball
    from `OpenVTC/vtc-admin-ui` GitHub releases.
  - Signature verification against the OpenVTC release
    public key (vendored under
    `vtc-service/release-keys/openvtc-admin-ui.pub`).
  - Tarball baked via `include_dir!`.
  - `VTC_OFFLINE_BUILD=1` → vendored fallback at
    `vtc-service/vendor/admin-ui-placeholder/` (minimal
    hello-admin SPA shipping in-tree; build-time stamp
    surfaced via `/admin/build-info.json`).
  - `admin_ui.mode = "embedded"` (default) serves baked
    SPA; `"external"` skips embedding + writes the
    external origin into `cors.allowed_origins`.
  - WebAuthn `RP ID` set per routing mode (path → base
    host; subdomain → base domain).
- **5 new audit variants**: `WebsiteFileWritten`,
  `WebsiteFileDeleted`, `WebsiteBundleDeployed`,
  `WebsiteGenerationRolledBack`, `AdminUiServed`.
- **8 new Trust Tasks** (per D9):
  - `website/files/list/1.0`
  - `website/files/show/1.0`
  - `website/files/write/1.0`
  - `website/files/delete/1.0`
  - `website/deploy/1.0`
  - `website/generations/list/1.0`
  - `website/rollback/1.0`
  - `admin-ui/build-info/1.0` (admin UX consumes one info
    endpoint that surfaces the baked-tarball digest +
    embed mode).
- **Operator documentation**:
  - `docs/04-reference/website-management.md`
  - `docs/04-reference/admin-ui-deployment.md`
  - `docs/04-reference/routing-modes.md`
- **§17.1 reference policy templates** doc — this is the
  Phase-4 follow-up the §17.1 open question parks. Includes
  it here so MVP completion ships the documentation
  surface alongside the code.
- **Spec amendments** captured at M5.10 (mirror the
  Phase 4 spec-amendment-surface pattern).

### Out of scope

- New `/v1/*` resource endpoints beyond the website
  management surface.
- DIDComm twins for website management — §9.6 names
  website as REST-only.
- Webhooks / subscription delivery on top of the audit
  vocabulary (§18).
- Admin UX feature-flag matrix for individual admin
  surfaces (the UX consumes whatever the daemon exposes;
  it is not a feature-gated UX).
- Operator-uploadable admin UX themes / branding (out of
  scope per §18 — communities extend via Rego + JSON
  blobs only; the admin UX is operator-owned, not
  community-owned).
- SPA template engine, server-side rendering, route-
  rewrites for the public website — §12.1 is explicit.
- Asset compression (gzip / brotli) at the daemon layer —
  CDN territory; we surface ETag + Cache-Control + that's
  it.
- Live-edit collaboration on the website (concurrent
  operator edits via the management API rely on
  ETag-based optimistic concurrency; lock files are not
  introduced — see R3 + D6).
- Trust-registry advertisement of the admin UX or public
  website URLs — these are operational endpoints, not
  community-identity advertisements.

## Pre-implementation design decisions

Load-bearing. Defaults below; flag dissent before any code
lands.

### D1 — `OpenVTC/vtc-admin-ui` sibling repo status — **BLOCKER**

The repo **does not yet exist** on the OpenVTC org (verified
2026-05-14 via `gh repo list OpenVTC`; only 6 repos live —
verifiable-trust-infrastructure, vti-setup, governance,
openvtc, wiki, dtg-credentials).

The `build.rs` fetch path (M5.6) is dead without it. Three
options:

(a) **Bootstrap the sibling repo first** (M5.6.0 — new
    pre-impl task before any code lands). Minimal "hello-
    admin" SPA: a Vite + TypeScript + React skeleton that
    can call `GET /v1/community/profile` and render the
    response. Tarball release flow: GitHub Actions builds
    `dist/`, packs `tar.gz`, signs with the OpenVTC release
    key, attaches to a GitHub Release. The vtc-service
    `build.rs` consumes the release tarball URL.

(b) **Stub `build.rs`** that always uses the vendored
    placeholder under `vtc-service/vendor/admin-ui-
    placeholder/`. The signed-tarball fetch is wired but
    unreachable (no upstream); the placeholder ships as
    the "real" admin UX. M5.6 still validates the fetch +
    verify code paths via a mock tarball.

(c) **Defer the `admin-ui` feature to a follow-up phase**.
    Phase 5 ships the website + routing-mode work; the
    admin UX track lands in Phase 5.5 or later. MVP gate
    redefined to "website + routing complete; admin UX
    arrives next."

**Recommended default: (a)**. Reasons:

- The MVP gate explicitly names admin UX as Phase 5
  deliverable. Deferring (c) is renegotiating scope.
- (b) lets the admin track land in this repo but ships
  literally nothing useful — a stub that 200s with
  "hello admin" is worse than a real basic SPA that an
  operator can actually use to inspect community state.
- Bootstrapping the sibling repo is one PR's worth of
  scaffold (Vite + auth flow + a handful of read-only
  pages). The release-signing CI is a second PR. Both
  can land in parallel with M5.1–M5.5 in this repo.

**Decision needed before M5.6.0 PR lands**: confirm the
operator persona's MVP expectation — is "operator can
manage the community without dropping to curl" a hard
gate, or is "operator can run an external SPA against the
JSON API + CORS-allowlist" sufficient?

If (b) is picked instead, the placeholder ships a
read-only "Community status" page so the operator can at
least verify the daemon is alive without `curl`. M5.7's
`admin_ui.mode = "external"` becomes the recommended
operator path.

### D2 — Release-key generation + storage

The signed-tarball flow needs a release-signing keypair.

**Default**:

- A **detached Ed25519 signing key** held by the OpenVTC
  GitHub Actions release pipeline (encrypted secret).
- **Public key vendored in-tree** at
  `vtc-service/release-keys/openvtc-admin-ui.pub` (raw
  32-byte Ed25519 public key, hex-encoded, in a small
  text file with a header line documenting issuance
  date + fingerprint).
- The release pipeline:
  1. Builds `dist/` from the SPA repo.
  2. Computes `tar.gz` with deterministic ordering +
     timestamps (`tar --sort=name --mtime=<release-tag-
     date>`).
  3. Computes SHA-256.
  4. Signs the SHA-256 with the release key via
     `minisign` or in-tree `ed25519-dalek` runner.
  5. Publishes `vtc-admin-ui-vX.Y.Z.tar.gz` +
     `vtc-admin-ui-vX.Y.Z.tar.gz.sig` to the GitHub
     Release.
- `build.rs` downloads both, verifies the signature
  using the vendored public key, verifies the digest
  against the pin recorded in `vtc-service/admin-ui-pin.
  toml`, then extracts.
- **Key rotation procedure**: a new keypair lands as a
  new vendored public-key file with a `released_from`
  date; old releases stay signed against the old key
  until they're rebuilt. Phase 5 ships only the initial
  key; rotation runbook is in the operator docs.

**Alternative considered (rejected)**: sigstore /
cosign. Sigstore needs an OIDC provider + Fulcio root
trust — too much trust-anchor surface to commit to in
MVP. Plain Ed25519 + vendored public key is the same
trust shape `vta-sdk::provision_integration` uses for
its sealed-bootstrap payloads.

### D3 — `VTC_OFFLINE_BUILD=1` vendored fallback location

**Default location**: `vtc-service/vendor/admin-ui-placeholder/`.

- Tracked in git (the CI builds + air-gapped builds both
  exercise this path).
- Contents: a single-page Vite-built `dist/` produced from
  a checked-in source tree under
  `vtc-service/vendor/admin-ui-placeholder-src/` (or
  fetched-and-built from the sibling repo on a known
  release tag during local dev).
- `build.rs` detects the env var **before** any network
  call. If set, copies the placeholder directly into the
  build output. CI sets it; release builds unset it.
- Failure mode: `cargo build` with neither
  `VTC_OFFLINE_BUILD=1` nor network connectivity fails
  loudly with `error: failed to fetch admin-ui release
  tarball — set VTC_OFFLINE_BUILD=1 or restore network`.
  No silent fall-through to a stub that 500s at runtime.

Picking (a) in D1 means the placeholder is identical to
or strictly older than the latest release; picking (b)
means the placeholder *is* the admin UX.

### D4 — Routing-mode dispatch implementation

Three options:

(i) **Single `Router` with per-route prefix attach + a
    tower middleware that inspects `Host`**. Subdomain
    mode middleware short-circuits 404 when `Host`
    doesn't match the surface owning the matched route.

(ii) **One `axum::Router` per surface, merged into a
     parent via `Router::nest`**. Per-surface body cap
     + CSRF + CSP layers attach at the nest boundary.
     Subdomain mode wraps the merged router in a
     `Host`-routing middleware.

(iii) **Router-per-port** — each surface on its own
      `TcpListener`. Operationally clean (firewalling,
      per-surface TLS); operationally heavier (3
      listeners, 3 metrics streams).

**Default: (ii)**. Reasons:

- Per-surface middleware is the most legible — readers
  see the website mount and its body-cap override + CSP
  + path-safety layer in one place.
- `TrustTaskRouter` already produces a `Router<S>`
  via `into_router()`; nesting is a one-call change.
- Subdomain dispatch becomes a `from_fn` middleware on
  the parent router that 404s when `Host` doesn't match
  the surface map.
- (iii) is operationally cleaner but breaks the §3-K
  "single daemon, single fjall" invariant — three
  listeners share one daemon but the operator can no
  longer firewall + scale them independently anyway
  (same process). Not worth the LoC.

**Configuration surface** (already in Phase 0):
- `routing.api.mount` / `.host`
- `routing.admin_ui.mount` / `.host`
- `routing.website.mount` / `.host`

Phase 5 adds:
- `routing.subdomain_mode_strict: bool` (default `true`)
  — when any surface has `host` set, 404 unknown hosts
  rather than falling back to path-mode matching.

### D5 — CSRF token storage

Spec §9.3 says "CSRF double-submit cookie". Two
implementation flavours:

(a) **Server-side session-bound token**. Stored in the
    `sessions` keyspace keyed by session id. Refreshed
    on each request. Higher fjall write rate.

(b) **Stateless double-submit cookie**. Random 32-byte
    token in a `csrf` cookie (Path=/, SameSite=Strict,
    Secure, HttpOnly=false so JS can read it); the
    admin UX sets `X-CSRF-Token` to the cookie value on
    mutating requests; the server compares header == cookie.

**Default: (b)**. Stateless, no fjall writes per
request, the spec says "double-submit". The cookie is
**HttpOnly=false** intentionally — JS must read it to
mirror into the header. The protection comes from
SameSite + the requirement that the attacker can't see
the value (the cookie is scoped to the daemon's origin;
cross-origin JS can't read it).

The admin session cookie (D7) is HttpOnly=true. CSRF
cookie is HttpOnly=false. Two separate cookies.

### D6 — `website.root_dir` concurrency model

fjall does not manage `root_dir` — it's just a path on
the filesystem. Operators can edit files directly
(scp / rsync / git pull) **and** through the
management API.

**Default: best-effort with ETag-based optimistic
concurrency, no locking.**

- `PUT /v1/website/files/{path}` accepts an optional
  `If-Match: <etag>` header. When present, the server
  computes the current file's SHA-256 + 412
  `WebsiteEtagMismatch` if it doesn't match.
- Without `If-Match`, last-writer-wins (`scp` clobber +
  API clobber both unconditional).
- `POST /v1/website/deploy` is **always atomic** at the
  filesystem level — `live` uses staging-then-rename,
  `managed` uses symlink swap. An in-flight operator
  `scp` will land in the *post-rename* directory
  silently (the rename moved the directory out from
  under them). The audit envelope records the deploy
  + the operator can detect drift via the next
  `GET /v1/website/files`.
- The admin UX docs (`website-management.md`) call out
  the operator-edit + API-edit race explicitly:
  "either edit files directly OR via the API; mixing
  the two without ETag guards is undefined".

**Alternative considered (rejected)**: lock file at
`root_dir/.vtc-website.lock`. Adds operational
complexity (stale-lock recovery, PID inspection,
restart-during-edit). For a small public website
edited by a handful of admins, ETag-based optimistic
concurrency is sufficient.

### D7 — `managed`-mode generation retention

**Default: count-based, keep the last 5 generations.**

- Config: `website.managed_generations_keep: u32`
  default `5`.
- After a successful deploy in `managed` mode,
  generations older than the Nth-most-recent get
  pruned (`fs::remove_dir_all`).
- The currently-symlinked generation is **never**
  pruned, even if it's stale. (Rollback flow leaves
  `current` pointing at an old gen; that gen stays
  until the next deploy + retention sweep.)
- Time-based retention is not added in MVP. Operators
  wanting "keep 30 days" can crank the count knob.

**Failure mode**: pruning fails mid-loop (FS errors,
permissions). The deploy itself has already succeeded
(symlink flipped); pruning logs a warning + emits a
telemetry event but doesn't fail the deploy. The
audit envelope's `pruned_generation_count` field
records the actual number pruned.

### D8 — Audit envelope shape for website ops

Five new variants:

| Variant | Fields |
|---|---|
| `WebsiteFileWritten` | `path` (UTF-8 string), `bytes_written: u64`, `etag: String` (hex SHA-256 of the new contents) |
| `WebsiteFileDeleted` | `path: String` |
| `WebsiteBundleDeployed` | `bundle_sha256: String`, `bytes: u64`, `mode: "live" \| "managed"`, `target_generation: Option<u32>` (managed only), `pruned_generation_count: u32` (managed only) |
| `WebsiteGenerationRolledBack` | `from_generation: u32`, `to_generation: u32` |
| `AdminUiServed` | `tarball_sha256: String`, `tarball_version: String`, `mode: "embedded" \| "external"`. Emitted once at boot. |

`AdminUiServed` is one-shot per daemon start so SIEM can
correlate sessions back to the running build's tarball
digest.

All five follow the discipline of Phases 1–4: round-trip
test + `variant_discriminator_strings` entry + `camelCase`
wire + `Option`s with `skip_serializing_if`.

### D9 — Trust Task allocation

8 new Trust Tasks for Phase 5:

| Endpoint | Trust Task ID |
|---|---|
| `GET /v1/website/files` | `…/website/files/list/1.0` |
| `GET /v1/website/files/{path}` | `…/website/files/show/1.0` |
| `PUT /v1/website/files/{path}` | `…/website/files/write/1.0` |
| `DELETE /v1/website/files/{path}` | `…/website/files/delete/1.0` |
| `POST /v1/website/deploy` | `…/website/deploy/1.0` |
| `GET /v1/website/generations` | `…/website/generations/list/1.0` |
| `POST /v1/website/rollback/{gen}` | `…/website/rollback/1.0` |
| `GET /admin/build-info.json` | `…/admin-ui/build-info/1.0` |

The shared-mount per-method workaround (Phase 1 + 3 + 4
collapse-pattern) applies to `/v1/website/files/{path}` —
one mount, three methods (GET + PUT + DELETE), one
Trust Task at the router layer, three on-disk tasks for
soft-gate completeness.

The admin UX itself surfaces no new Trust Tasks: it
consumes the existing `/v1/*` API. `/admin/build-info.json`
is the single admin-track Trust Task because it carries
state (the embedded tarball digest) that needs to be
auditable.

Final count: 55 (Phase 0–4) + 8 = **63 Trust Tasks** at
MVP gate.

### D10 — Routes-at-root audit + path-mode catch-all collision

The public website mounts at `/` as a catch-all. Current
Phase 0–4 routes at "root" that risk colliding:

- `/health` — Trust-Task exempt, **must** stay at root.
  Solution: route priority `/health` > `/*` (axum's
  path-trie automatically prefers the literal match).
- `/v1/{scid}/did.jsonl` — Trust-Task exempt did:webvh
  log. Lives under `/v1/`, no collision.
- `/v1/status-lists/{purpose}` — Trust-Task exempt
  status-list publication. Lives under `/v1/`, no
  collision.

**Audit result**: no current routes collide with the `/*`
website catch-all. The path-trie precedence guarantees
`/health` wins; everything else lives under `/v1/` or
`/admin/`. Phase 5 doesn't need to rename any existing
routes.

When `routing.api.mount` is changed away from `/v1`
(operator override), the same precedence rule holds —
the catch-all sits below all literal-prefix routes in
priority.

### D11 — §14.4 runtime guards — body cap + tower-governor

**Fact check (planning review):** the prompt asserts a
"1 MB global body cap" + "tower-governor 5 rps / 10
burst" already exist. They don't (`grep -n
"DefaultBodyLimit\|tower_governor"
vtc-service/src/server.rs` returns nothing). §14.4
names them as workspace doctrine inherited from the
VTA but Phase 0–4 didn't actually wire them in
`vtc-service`. Phase 5 has to land them as a
prerequisite to the body-cap exception making any
sense.

**Default: bundled into M5.1** (the routing-surface
separation PR), because the body-cap layers attach at
the per-surface nest boundary in scheme D4(ii). Three
sub-tasks:

- M5.1.4 — `DefaultBodyLimit::max(1 MiB)` attaches on
  the `routing.api` sub-router for all routes **except**
  the website management routes (which override).
- M5.1.5 — `tower_governor` attaches on the
  `routing.api` sub-router for the unauth routes
  (`/v1/install/*`, `/v1/join-requests` POST,
  `/v1/auth/challenge`, `/v1/auth/`, `/v1/auth/refresh`).
- Authenticated routes inherit the default body cap
  but no governor (their JWT auth is the limiter).

§14.4 update applied in M5.10 spec amendments — confirm
the guards landed as part of Phase 5, not Phase 0.

### D12 — Admin UX session model

**Current state**: programmatic JWT in `Authorization:
Bearer`. The admin UX SPA needs cross-page-load auth.

Three options:

(i) **Bearer JWT in `localStorage`**. Simple. Vulnerable
    to XSS — a single malicious npm dep in the SPA bundle
    can exfiltrate the token. Sub-optimal for an admin
    UX.

(ii) **HttpOnly cookie session** (new). Pair with CSRF
     double-submit (D5). Resistant to XSS exfil. Adds
     a `sessions` keyspace path that mints a cookie
     beside the existing JWT.

(iii) **Bearer JWT in `sessionStorage`** + per-tab login.
      Slightly safer than (i); breaks "open admin UX in
      two tabs" UX. Still XSS-vulnerable to anything
      that can run JS.

**Default: (ii)**. The admin UX is a privilege boundary;
XSS protection matters. The session-mint flow:

1. Admin completes WebAuthn UV ceremony on
   `/admin/login`.
2. Server validates the assertion, mints a session in
   the existing `sessions` keyspace, returns a `Set-Cookie:
   vtc_admin_session=<jwt>; Path=/admin; SameSite=Strict;
   Secure; HttpOnly` header **plus** a `csrf` cookie
   (HttpOnly=false, see D5).
3. SPA fetches `/v1/*` with `credentials: 'include'` +
   `X-CSRF-Token: <csrf-cookie-value>`.
4. Bearer JWT still works for programmatic clients
   (`cnm-cli`); the two paths coexist.

`Path=/admin` ensures public-site JS on the same origin
can't read the cookie (the browser only sends it on
`/admin/*` requests; the SPA's same-origin `fetch` to
`/v1/*` includes it because cookies attach by origin not
by path on outbound — but the public-site JS on `/` can't
*read* the cookie because of Path scoping when reading
`document.cookie`). Confirmed at impl time with explicit
tests (M5.4.3).

Cookie auth lands in M5.4. Phase 0–4's existing JWT path
stays for programmatic + DIDComm + cnm-cli.

### D13 — Tarball digest pin file format

**Default**: `vtc-service/admin-ui-pin.toml`:

```toml
# OpenVTC admin UX release pin. Updated by
# `cargo xtask bump-admin-ui` (or hand-edited).
version = "0.1.0"
tarball_sha256 = "abcdef..."
release_url = "https://github.com/OpenVTC/vtc-admin-ui/releases/download/v0.1.0/vtc-admin-ui-v0.1.0.tar.gz"
signature_url = "https://github.com/OpenVTC/vtc-admin-ui/releases/download/v0.1.0/vtc-admin-ui-v0.1.0.tar.gz.sig"
```

`build.rs` reads this, fetches both URLs, verifies, pins
the digest, extracts. No moving targets — version bumps
are explicit PRs.

## Dependency graph

```
M5.1 Routing surface separation + §14.4 guards
  │
  ├─────────────► M5.2 CORS + admin cookie + CSRF middleware
  │                 │
  │                 ▼
  │              M5.3 Cookie-scope isolation tests + CSP defaults
  │
  ▼
M5.4 Website feature scaffold + path safety
  │
  ▼
M5.5 Website management API (list / read / write / delete / deploy / rollback)
  │
  ▼
M5.6 Admin UX feature: sibling-repo bootstrap (D1 decision) + build.rs + offline fallback
  │
  ▼
M5.7 Admin UX mount + RP ID rules + AdminUiServed audit
  │
  ▼
M5.8 Audit variants snapshot tests
M5.9 Trust Task on-disk + index.json batch
M5.10 Phase 5 outcomes + spec amendments + reference policy templates
M5.11 Phase 5 / MVP gate
```

Critical paths:

- **Routing track** (M5.1 → M5.2 → M5.3). Sequential. The
  router-shape changes underpin everything else.
- **Website track** (M5.1 → M5.4 → M5.5). M5.4 + M5.5 are
  parallelisable with M5.2 + M5.3 once M5.1 lands.
- **Admin UX track** (M5.1 → M5.6 → M5.7). M5.6 has a hard
  blocker on D1 (sibling repo bootstrap or stub
  decision). Parallel with website track after M5.1.
- **Closeout** (M5.8–M5.11) depends on all three tracks.

Parallelisable after M5.1:

- M5.2 + M5.3 (CORS / CSRF / cookies track).
- M5.4 + M5.5 (website track).
- M5.6 + M5.7 (admin UX track, gated on D1).

## PR slicing — proposed

Phase 5 lands in **5 PRs** (mirrors Phase 3 + 4 cadence).
The admin-UX work is the heaviest because it spans the
sibling-repo bootstrap + the build.rs + the runtime
embedding.

1. **PR-1**: M5.1 + M5.2 + M5.3.
   Routing-surface separation, §14.4 guards, CORS
   tightening, CSRF middleware, admin session cookie,
   cookie-scope isolation tests. **Foundational** — every
   subsequent PR depends on the surface shape.
2. **PR-2**: M5.4.
   `website` feature scaffold: `website` module,
   filesystem path safety helpers, content-type / CSP /
   ETag plumbing, FD cache, public-static handler. No
   management API yet — the public website serves
   filesystem content. Includes the `live` + `managed`
   deploy-mode storage primitives (without REST surfaces).
3. **PR-3**: M5.5.
   Website management API — all 7 endpoints + Trust
   Tasks + body-cap overrides + ETag-based concurrency
   + `WebsiteFile*` / `WebsiteBundle*` /
   `WebsiteGenerationRolledBack` audit emission. The
   heaviest single PR (~ 800-1000 LoC).
4. **PR-4**: M5.6 + M5.7.
   Admin UX. M5.6 lands the sibling-repo bootstrap
   (out-of-tree work, but the PR adds the build.rs +
   pin file + vendored public key + placeholder in
   this repo). M5.7 wires the runtime mount + RP-ID
   rules + `AdminUiServed` audit. Per D1, the sibling
   repo PR can land in parallel; this PR consumes the
   first sibling release.
5. **PR-5**: M5.8 + M5.9 + M5.10 + M5.11.
   Audit snapshots, Trust Task on-disk batch + index
   verification, Phase 5 outcomes header, spec
   amendments, reference policy templates doc
   (closes §17.1 OQ#1), workspace gate. **MVP gate met
   here.**

5 PRs across 11 milestones — matches Phase 3 (5 PRs / 14
milestones) and Phase 4 (5 PRs / 12 milestones). PR-3 +
PR-4 are the heaviest; PR-1 is intentionally a
foundation PR that derisks every subsequent surface.

## Checkpoints

- **After PR-1**: routing surfaces split + cookie-scope
  isolation invariant tested + CSRF middleware live +
  §14.4 guards landed. Public-site origin requests to
  admin endpoints rejected. **Routing-mode gate met.**
- **After PR-2**: public website serves filesystem
  content under `/` with path safety + CSP + ETag +
  FD cache. **Public website read-path gate met.**
- **After PR-3**: admins manage the website via
  `/v1/website/*` API with body-cap overrides + atomic
  deploy + managed-mode rollback + audit emission.
  **Website management gate met.**
- **After PR-4**: admin UX baked into the binary +
  served at `/admin/*` + RP-ID rules wired + offline
  build path works. **Admin UX gate met.**
- **After PR-5**: workspace gate green; Trust Task
  count 55 → 63; all Phase 5 milestones marked `[x]`;
  spec amendments applied. **MVP gate met.**

## Risks

- **R1: Sibling repo (`OpenVTC/vtc-admin-ui`) doesn't
  land in time.** The build.rs fetch is dead without
  an upstream tarball. **Mitigation**: D1's bootstrap
  decision. Worst case (b) — `VTC_OFFLINE_BUILD=1` is
  the only supported build path until upstream catches
  up; M5.6 ships a placeholder that 200s on every
  admin route. Document this in the operator runbook.
- **R2: Path-safety bypass via Unicode normalisation
  edge cases.** NFC alone doesn't defeat all
  reflexive-path-traversal attempts; non-ASCII
  encodings of `..` exist. **Mitigation**: canonicalise
  to the real path **after** NFC normalisation, then
  verify the canonical path is a prefix of the
  canonical `root_dir`. Add fuzz tests with known
  Unicode confusables (e.g. fullwidth `.` U+FF0E).
- **R3: Concurrent operator edits race the API.**
  See D6. **Mitigation**: ETag optimistic concurrency
  for single-file writes; atomic-rename for bundle
  deploys. Document the "don't mix" rule loudly.
- **R4: tarball signature key compromise.** A leaked
  release-signing key lets an attacker publish a
  malicious admin UX. **Mitigation**: D2's key-
  rotation runbook + the vendored public-key file is
  the trust anchor; rotating means a new vendored key
  file in a new vtc-service release. Operators
  re-build to pick it up.
- **R5: CSP misconfiguration breaks operator-uploaded
  SPAs.** A community wanting a Vue/Svelte public site
  with inline scripts hits the default `script-src
  'self'` and breaks. **Mitigation**: per-site CSP
  override in `<root_dir>/.vtc-website.toml`. Document
  the override in `website-management.md` with concrete
  examples.
- **R6: `managed` mode generation pruning racing the
  symlink swap.** Operator inspects an older generation
  via the filesystem during a deploy + retention sweep;
  the gen-N directory disappears mid-read. **Mitigation**:
  pruning runs **after** the symlink swap commits, in a
  background task; the swap-then-prune ordering means
  the rolled-back generation is always present.
  Pruning failures don't fail the deploy (D7).
- **R7: Admin UX bundle digest drifts between Cargo.lock
  + admin-ui-pin.toml.** A developer bumps the pin
  without bumping the Cargo.lock-tracked dep. **Mitigation**:
  the pin is its own TOML; a CI check verifies
  `build.rs` computes the digest matches at build time
  and fails the build otherwise.
- **R8: Subdomain mode in production without TLS for
  every subdomain.** Operator sets
  `routing.admin_ui.host = "admin.example.com"` but
  doesn't have a cert for it. **Mitigation**: the
  daemon doesn't terminate TLS in subdomain mode (the
  reverse proxy does). Document the requirement in
  `routing-modes.md`. The daemon does NOT auto-detect
  missing TLS — that's the operator's responsibility.
- **R9: Body-cap override on website routes
  accidentally allows DoS.** 50 MB bundle uploads from
  an admin route are large but bounded. **Mitigation**:
  the body cap is per-request; tower-governor on
  unauth doesn't apply (admin-gated routes are
  authenticated). Operator policy + RBAC are the
  controls. Document the trade-off.

## Definition of done — Phase 5 / MVP

After M5.11:

- `cargo build/clippy/fmt/test --workspace` clean (with
  and without `--no-default-features`).
- `cargo build --workspace --features website,admin-ui`
  clean — both feature flags exercised in CI.
- `cargo build --workspace --no-default-features` clean
  (no `website` / no `admin-ui` — the routing surfaces
  inactive-features return 404).
- `VTC_OFFLINE_BUILD=1 cargo build -p vtc-service` clean
  — air-gapped build path verified.
- 8 new Trust Tasks in `Draft` status with matching
  `spec.md` + `schema.json` files.
- `trust-tasks/index.json` carries all 63 entries (55 +
  8); CI verifies count match against on-disk task
  count.
- Every Phase 5 milestone marked `[x]` in
  `phase-5-todo.md`.
- Memory entry `project_vtc_mvp.md` updated with the
  as-shipped outcomes for D1–D13.
- Spec amendments applied per the surface in this plan.
- Integration tests cover:
  - End-to-end routing: path mode → API / admin / website
    all reachable on one host. Subdomain mode → each
    surface only on its host; wrong-host requests 404.
  - End-to-end CSRF: admin POST without
    `Sec-Fetch-Site: same-origin` and without
    `X-CSRF-Token` → 403; with `X-CSRF-Token` matching
    cookie → 200.
  - End-to-end cookie isolation: public-site GET
    response carries no admin session cookie; admin-
    session cookie's `Path=/admin` rejects public-site
    JS reads.
  - End-to-end website: PUT a file via API → ETag
    returned → GET returns the same content + ETag.
    PUT with stale `If-Match` → 412. Deploy a tar.gz
    bundle in `live` mode → contents served. Deploy
    in `managed` mode → new gen-N + symlink swap.
    Rollback → previous gen-N served. Retention prunes
    old gens beyond the keep count.
  - End-to-end path safety: GET
    `/website/../../etc/passwd` → 400. GET a path
    containing non-NFC chars → 400. GET a hidden file
    → 404.
  - End-to-end admin UX: with `VTC_OFFLINE_BUILD=1` the
    placeholder serves; without it (mocked release
    fetch in tests) the baked SPA serves; embedded vs
    external modes both respect the config.
  - End-to-end CSP: response headers include the
    configured CSP + `X-Content-Type-Options: nosniff`.
- Operator documentation present:
  - `docs/04-reference/website-management.md`
  - `docs/04-reference/admin-ui-deployment.md`
  - `docs/04-reference/routing-modes.md`
  - `docs/04-reference/personhood-templates.md` (closes
    §17.1 OQ#1).
- §14.4 guards verified: body-cap rejection test +
  governor rate-limit test in CI.

**MVP gate met.** Phase 6+ is post-MVP (witness /
RCard credentials, bilateral VRC counter-signing, etc.;
none in scope for this plan).

## Spec amendment surface

Recording up front so they're not surprises mid-impl:

- **§9.2**: confirm subdomain-mode dispatch via tower
  middleware (D4); `routing.subdomain_mode_strict` new
  config key.
- **§9.3**: pin admin session cookie shape
  (`Path=/admin; SameSite=Strict; Secure; HttpOnly`) +
  CSRF double-submit cookie (D5) + cookie auth as the
  admin-UX session model (D12). The §9.3 statement
  "CSRF double-submit cookie" becomes prescriptive.
- **§9.4**: 8 new Trust Tasks land in MVP; total moves
  to 63.
- **§9.5**: confirm the website management surface ID
  shape (the `[/{path}]` shortcut is split into 4
  explicit ID lines + 3 deploy/generations lines).
- **§11.4**: extend audit catalogue with 5 new variants
  (D8).
- **§12.1**: per-site CSP override via
  `<root_dir>/.vtc-website.toml` (R5 mitigation); pin
  `live_cache_ttl_seconds` default; pin
  `managed_generations_keep` default; pin
  `executable_blocklist` exact set.
- **§12.2**: pin admin UX release pipeline (D2 +
  D13) + offline-build fallback location (D3) +
  embedded vs external mode behaviour.
- **§14.4**: confirm guards landed (D11) — the section
  was aspirational pre-Phase-5; it becomes load-bearing
  after M5.1.
- **§17.1**: closes — the personhood-templates doc
  ships as part of Phase 5 closeout.

Any decision that drifts from the default during
implementation should be recorded in `phase-5-plan.md`
under a "Phase 5 outcomes" header (mirror of Phase 1–4
pattern).

## Phase 5 outcomes

> *To be filled in at M5.10 close-out, mirroring the
> Phase 1–4 pattern. Each row links a pre-impl decision
> (D1–D13) or risk (R1–R9) to the as-shipped reality.
> Spec amendments listed at the bottom.*
```

