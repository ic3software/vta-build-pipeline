# Todo: VTC MVP — Phase 5

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

Spec: `docs/05-design-notes/vtc-mvp.md` §§9.2, 9.3, 9.5,
9.6, 12.1, 12.2, 14.4, 16, 18.
Plan: `tasks/vtc-mvp/phase-5-plan.md`

Every code task also drafts the matching Trust Task spec
(`trust-tasks/.../spec.md` + `schema.json`) in the same PR —
soft gate per spec §9.4. Trust Task IDs per plan §D9.

Every PR must be DCO-signed (`git commit -s`) and pass
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`.

---

## M5.1 — Routing surface separation + §14.4 guards

### `[ ]` M5.1.1 — Nest routes under per-surface sub-routers

- **Acceptance**
  - `routes::router()` returns a parent `axum::Router` that
    nests three sub-routers — API (under `routing.api.mount`),
    admin UX (under `routing.admin_ui.mount`), website (under
    `routing.website.mount`).
  - The API sub-router is the existing `TrustTaskRouter`-built
    router (no changes to handler attach order).
  - Admin UX sub-router is a placeholder returning 503 (real
    SPA lands in M5.7).
  - Website sub-router is a placeholder returning 503 (real
    handler lands in M5.4).
  - `/health` stays attached at the parent router root,
    Trust-Task exempt, **above** all sub-router prefixes.
  - Per-surface body-cap + middleware layers attach at the
    nest boundary (Phase 5 plan D4(ii)).
- **Verify** 4 unit tests:
  - GET `/health` → 200 (path-mode and subdomain-mode).
  - POST `/v1/auth/challenge` → existing 400/401 (no shape
    drift).
  - GET `/admin/anything` → 503 placeholder.
  - GET `/anything-else` → 503 placeholder.
- **Files**
  - `vtc-service/src/routes/mod.rs`
  - `vtc-service/src/server.rs` (consumer)
- **Deps**: none
- **Pre-impl decision**: **D4** (nest, not merge).

### `[ ]` M5.1.2 — Subdomain-mode dispatch middleware

- **Acceptance**
  - New `vtc_service::routing::host_dispatch` module — tower
    middleware that inspects `Host`. When **any** surface has
    `host` set in config, every request is matched against
    the surface map; non-matching `Host` → 404
    `HostNotRecognised`.
  - When **all** surfaces have `host = None`, the middleware
    is a no-op and path-mode prefix matching applies.
  - New config knob `routing.subdomain_mode_strict: bool`
    default `true`. When `false`, unknown hosts fall back to
    path-mode matching against the parent router. (Recommended
    `true` for production; `false` is a debug aid.)
- **Verify** 4 integration tests:
  - Path mode (all hosts unset) → no host enforcement.
  - Subdomain mode (api/admin/website all set with distinct
    hosts) → each host reaches its surface only.
  - Subdomain mode + wrong host + `strict = true` → 404.
  - Subdomain mode + wrong host + `strict = false` →
    path-mode fallback.
- **Files**
  - `vtc-service/src/routing/mod.rs` (new module)
  - `vtc-service/src/routing/host_dispatch.rs` (new)
  - `vtc-service/src/config.rs` (`subdomain_mode_strict` knob)
  - `vtc-service/src/server.rs`
- **Deps**: M5.1.1
- **Pre-impl decision**: **D4**.

### `[ ]` M5.1.3 — Routing-mode integration test fixtures

- **Acceptance**
  - New `vtc-service/tests/routing/` directory with two
    integration tests: `path_mode.rs` + `subdomain_mode.rs`.
  - Test harness builds the full `Router` with a fake
    `AppState` + asserts the route priority `/health` >
    `/v1/*` > `/v1/website/*` > `/admin/*` > `/*`.
  - Subdomain test exercises the `Host` header on each
    surface.
- **Verify** harness compiles + tests green.
- **Files**
  - `vtc-service/tests/routing/path_mode.rs` (new)
  - `vtc-service/tests/routing/subdomain_mode.rs` (new)
  - `vtc-service/tests/common/mod.rs` (extend)
- **Deps**: M5.1.1, M5.1.2

### `[ ]` M5.1.4 — Global 1 MiB body cap on API surface

- **Acceptance**
  - `DefaultBodyLimit::max(1 * 1024 * 1024)` attaches at the
    `routing.api.mount` nest boundary.
  - Website management routes carry a per-route override (lands
    in M5.5) — these routes attach **after** the global layer
    with explicit per-handler caps using
    `DefaultBodyLimit::disable()` + a route-scoped
    `RequestBodyLimitLayer::new(<cfg>)`.
  - Existing tests pass; new test confirms a 1.1 MiB POST to
    `/v1/community/profile` → 413 `PayloadTooLarge`.
- **Verify** 1 integration test (body-cap rejection).
- **Files**
  - `vtc-service/src/routes/mod.rs`
  - `vtc-service/src/server.rs`
- **Deps**: M5.1.1
- **Pre-impl decision**: **D11**.

### `[ ]` M5.1.5 — tower-governor on unauth routes

- **Acceptance**
  - New workspace dep `tower-governor = "0.4"` (or current
    workspace pin; align with VTA's pin if present).
  - Governor configuration: 5 rps + 10 burst per IP, applied
    to:
    - `POST /v1/auth/challenge`
    - `POST /v1/auth/`
    - `POST /v1/auth/refresh`
    - `POST /v1/join-requests` (submit)
    - `POST /v1/install/claim/start`
    - `POST /v1/install/claim/finish`
  - All other routes inherit no governor (their JWT auth
    is the bound).
  - Per-IP key extractor; in subdomain mode the governor
    keys by `(host, remote_ip)` so per-host limits don't
    cross-pollinate.
- **Verify** 2 integration tests:
  - 15 rapid POSTs to `/v1/auth/challenge` from one IP →
    last 5 return 429.
  - Authenticated routes unaffected by the governor.
- **Files**
  - `Cargo.toml` (workspace dep)
  - `vtc-service/Cargo.toml`
  - `vtc-service/src/routing/governor.rs` (new)
  - `vtc-service/src/routes/mod.rs`
- **Deps**: M5.1.1, M5.1.4
- **Pre-impl decision**: **D11**.

---

## M5.2 — CORS tightening + CSRF middleware + admin cookie

### `[ ]` M5.2.1 — CORS allowlist enforcement audit

- **Acceptance**
  - Existing `build_cors_layer` (Phase 0) already enforces
    the allowlist; Phase 5 confirms the public-website
    origin is **NOT** auto-added.
  - New negative test: `cors.allowed_origins = []` + a
    cross-origin `Origin: https://example.com` request to a
    mutating endpoint → no `Access-Control-Allow-Origin`
    response header (CORS blocks).
  - Documentation update — `routing-modes.md` calls out
    that the public-site origin doesn't auto-allowlist.
- **Verify** 2 integration tests (empty allowlist + one
  configured origin both behaving correctly).
- **Files**
  - `vtc-service/src/server.rs` (no code change — just
    test coverage)
  - `vtc-service/tests/cors_enforcement.rs` (new)
- **Deps**: M5.1.1

### `[ ]` M5.2.2 — CSRF middleware for admin mutating endpoints

- **Acceptance**
  - New `vtc_service::auth::csrf` module — tower middleware
    that:
    - Allows pass-through on GET / HEAD / OPTIONS.
    - Allows pass-through when `Sec-Fetch-Site: same-origin`
      is present (modern browsers set this; non-browser
      clients can spoof, but they're not the attack surface
      — XSS-driven cross-origin POST from another tab is).
    - Allows pass-through when the `csrf` cookie value
      matches the `X-CSRF-Token` header value.
    - Rejects otherwise with 403 `CsrfFailed`.
  - Applies to: all `POST`/`PUT`/`PATCH`/`DELETE` under
    `routing.api.mount` **except** `/v1/join-requests`
    (public form-encoded POST, see §9.3).
  - Public form posts: form-encoded POST with `Origin`
    matching a configured `cors.allowed_origins` entry
    passes (simple-request semantics).
- **Verify** 6 integration tests:
  - Authenticated mutating POST without CSRF, without
    `Sec-Fetch-Site` → 403.
  - Same POST with `Sec-Fetch-Site: same-origin` → 200.
  - Same POST with CSRF cookie + header matching → 200.
  - CSRF cookie + non-matching header → 403.
  - GET on the same path bypasses → 200.
  - Public `/v1/join-requests` POST without CSRF → 200.
- **Files**
  - `vtc-service/src/auth/csrf.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `vti-common/src/error.rs` (new `CsrfFailed` variant)
- **Deps**: M5.1.1, M5.2.1
- **Pre-impl decision**: **D5** (stateless double-submit).

### `[ ]` M5.2.3 — Admin session cookie mint flow

- **Acceptance**
  - New `POST /v1/auth/admin-login` endpoint — accepts a
    completed WebAuthn UV assertion; mints a session in the
    existing `sessions` keyspace + returns:
    - `Set-Cookie: vtc_admin_session=<jwt>; Path=/admin;
      SameSite=Strict; Secure; HttpOnly; Max-Age=<ttl>`.
    - `Set-Cookie: csrf=<random-32-byte-hex>; Path=/;
      SameSite=Strict; Secure` (HttpOnly **false** so JS
      can mirror to header — per D5).
  - The bearer-JWT path (`POST /v1/auth/` per Phase 0) is
    unchanged.
  - `AdminAuth` extractor (in `vti-common`) extended to
    accept either:
    - `Authorization: Bearer <jwt>` (existing), OR
    - `Cookie: vtc_admin_session=<jwt>` (new).
  - Trust Task `auth/admin-login/1.0` ships (this is the
    9th Trust Task — added because the cookie flow needs
    its own surface).
- **Verify** 5 integration tests:
  - Admin login mints both cookies on success.
  - Cookie-authenticated `GET /v1/members` returns 200.
  - Cookie + bearer both present → cookie wins (documented).
  - Cookie scope: cookie is **not** sent on `GET /` (public
    website origin) because of `Path=/admin`.
  - Logout (`DELETE /v1/auth/sessions/{id}`) clears the
    cookie via `Set-Cookie: vtc_admin_session=; Max-Age=0`.
- **Files**
  - `vtc-service/src/routes/auth.rs` (extend)
  - `vti-common/src/auth/extractor.rs` (cookie path)
  - `trust-tasks/auth/admin-login/1.0/{spec.md,schema.json}` (new)
- **Deps**: M5.2.2
- **Pre-impl decision**: **D12** (HttpOnly cookie session).

---

## M5.3 — Cookie-scope isolation tests + CSP defaults

### `[ ]` M5.3.1 — Cookie-scope isolation invariant tests

- **Acceptance**
  - New integration test file
    `vtc-service/tests/cookie_isolation.rs`:
    - Boot daemon with path-mode routing (admin + website
      both on the same host).
    - Admin login → admin session cookie set with
      `Path=/admin`.
    - GET `/` (website) → response carries no
      `Set-Cookie` for the admin session.
    - Document attribute assertion: the cookie's `Path`
      attribute is exactly `/admin` (not `/`).
  - Negative test: configuring `routing.admin_ui.mount =
    "/"` is rejected at config load (Phase 0's
    `validate_routing` already enforces; Phase 5 confirms
    + adds the test).
- **Verify** 3 integration tests (cookie path + public-
  site no-leak + config-load rejection).
- **Files**
  - `vtc-service/tests/cookie_isolation.rs` (new)
- **Deps**: M5.2.3

### `[ ]` M5.3.2 — Default CSP + `X-Content-Type-Options`
attached to website + admin sub-routers

- **Acceptance**
  - Tower middleware `vtc_service::routing::security_headers`:
    - Always: `X-Content-Type-Options: nosniff`.
    - Default CSP: `default-src 'self'; script-src 'self';
      object-src 'none'; base-uri 'self'`.
    - Attached to admin UX sub-router (real placeholder for
      M5.7).
    - Attached to website sub-router (real handler in M5.4).
  - API sub-router does NOT get CSP (it's a JSON API; CSP
    is browser-only).
- **Verify** 2 integration tests (admin + website both
  carry the headers).
- **Files**
  - `vtc-service/src/routing/security_headers.rs` (new)
  - `vtc-service/src/routes/mod.rs`
- **Deps**: M5.1.1

### Checkpoint — Routing-mode gate met

After M5.3.2: surfaces split, CORS tight, CSRF live, cookie
isolation tested, security headers default-on for public
surfaces. Sub-routers still return 503 for content;
foundation is correct.

---

## M5.4 — `website` feature scaffold + path safety

### `[ ]` M5.4.1 — `website` feature flag + module scaffold

- **Acceptance**
  - New cargo feature `website` in `vtc-service/Cargo.toml`.
    Default-on for the `vtc` binary so MVP `cargo run` works
    out of the box.
  - New module tree `vtc_service::website`:
    - `mod.rs` — public façade + config.
    - `paths.rs` — path-safety helpers (NFC normalisation,
      canonicalisation, no-escape check, hidden-file check,
      exec-bit check, MIME guess).
    - `storage.rs` — `WebsiteRoot` enum
      (`Live { root: PathBuf }` /
      `Managed { root: PathBuf, current_gen: u32 }`) +
      deploy primitives.
    - `cache.rs` — file-descriptor cache (TTL based).
  - New config block `[website]` in `AppConfig`:
    - `root_dir: PathBuf` (no default — feature works only
      when set).
    - `deploy_mode: "live" | "managed"` default `"live"`.
    - `live_cache_ttl_seconds: u64` default `5`.
    - `managed_generations_keep: u32` default `5`.
    - `cache_control: String` default
      `"public, max-age=300"`.
    - `executable_blocklist: Vec<String>` default
      `[".cgi", ".php", ".exe"]`.
    - `max_bundle_size_mb: u64` default `50`.
    - `max_file_size_mb: u64` default `10`.
    - `csp_override_file: PathBuf` default
      `".vtc-website.toml"` (relative to `root_dir`).
- **Verify** 4 unit tests:
  - Config round-trip.
  - `paths::canonical_within_root` rejects `..` escape.
  - `paths::canonical_within_root` rejects non-NFC.
  - `paths::canonical_within_root` rejects hidden-file
    requests.
- **Files**
  - `vtc-service/Cargo.toml` (`website` feature)
  - `vtc-service/src/website/mod.rs` (new)
  - `vtc-service/src/website/paths.rs` (new)
  - `vtc-service/src/website/storage.rs` (new)
  - `vtc-service/src/website/cache.rs` (new)
  - `vtc-service/src/config.rs` (`WebsiteConfig` block)
- **Deps**: M5.1.1
- **Pre-impl decision**: **D6** (no locks), **D7**
  (count-based retention).

### `[ ]` M5.4.2 — Public static handler at the website mount

- **Acceptance**
  - `vtc_service::website::serve` — async handler bound to
    `GET /{*path}` at the website sub-router.
  - Flow:
    1. Decode the path; NFC-normalise; reject non-NFC.
    2. Canonicalise against `root_dir` (or `root_dir/current`
       in managed mode).
    3. Reject `..` escape, symlink-out, hidden files,
       exec-bit, blocklisted extensions.
    4. Open via FD cache; compute SHA-256 → ETag.
    5. Honour `If-None-Match` for 304.
    6. MIME via `mime_guess::from_path`; fall back to
       `application/octet-stream`.
    7. Response headers: `Content-Type`, `ETag`,
       `Cache-Control` (from config), `X-Content-Type-Options:
        nosniff`, CSP (default or per-site override from
       `.vtc-website.toml`).
- **Verify** 8 integration tests:
  - GET `/index.html` → 200 + correct headers.
  - GET `/index.html` with `If-None-Match` → 304.
  - GET `/../../etc/passwd` → 400.
  - GET `/.hidden` → 404.
  - GET `/script.cgi` → 403 `WebsiteBlockedExtension`.
  - GET non-NFC path → 400.
  - GET symlink pointing outside root → 400.
  - Per-site CSP override from `.vtc-website.toml`
    surfaces in response.
- **Files**
  - `vtc-service/src/website/serve.rs` (new)
  - `vtc-service/src/routes/mod.rs` (attach)
  - `vti-common/src/error.rs` (new website error variants)
- **Deps**: M5.4.1
- **Pre-impl decision**: **D6**, **R2** (Unicode
  confusables in tests).

### Checkpoint — Public website read-path gate met

After M5.4.2: filesystem-backed static serving works with
full path-safety + CSP + ETag + FD cache. Management API
not yet present.

---

## M5.5 — Website management API

### `[ ]` M5.5.1 — `GET /v1/website/files` + `GET /v1/website/files/{path}`

- **Acceptance**
  - List handler: admin-gated. Cursor pagination per §9.1
    (`?cursor=&limit=` clamped 1..=200). Returns
    `{ path, size_bytes, etag, modified_at }` per entry.
    Honours the same path-safety rules (hidden files
    excluded from listings).
  - Show handler: admin-gated. Returns the file content
    inline with the same response headers as the public
    handler **plus** an `X-Website-Etag` echo.
  - Both behind the global 1 MiB body cap (responses
    bounded by `max_file_size_mb` on the way out).
  - Trust Tasks ship: `website/files/list/1.0`,
    `website/files/show/1.0`.
- **Verify** 4 integration tests:
  - List 10 files → paginated.
  - Show by path.
  - Show 404 on unknown path.
  - Path-safety rules apply (hidden files 404, etc.).
- **Files**
  - `vtc-service/src/routes/website/mod.rs` (new)
  - `vtc-service/src/routes/website/files.rs` (new)
  - `vtc-service/src/routes/mod.rs`
  - `trust-tasks/website/files/list/1.0/{spec.md,schema.json}`
  - `trust-tasks/website/files/show/1.0/{spec.md,schema.json}`
- **Deps**: M5.4.2
- **Pre-impl decision**: **D9** (Trust Task split).

### `[ ]` M5.5.2 — `PUT /v1/website/files/{path}` + `DELETE`

- **Acceptance**
  - PUT handler: admin-gated. Body-cap overrides global to
    `max_file_size_mb` (default 10). Path safety applies.
  - Optional `If-Match: <etag>` header for optimistic
    concurrency; mismatch → 412
    `WebsiteEtagMismatch`.
  - Writes to a temp file in the same directory then
    `rename` for atomic single-file write.
  - DELETE handler: admin-gated. 200 with empty body on
    success; 404 if absent.
  - Both emit audit envelopes (`WebsiteFileWritten` /
    `WebsiteFileDeleted`).
  - Trust Tasks ship: `website/files/write/1.0`,
    `website/files/delete/1.0`.
- **Verify** 6 integration tests:
  - PUT new file → 200 + ETag in response.
  - PUT with stale `If-Match` → 412.
  - PUT exceeding `max_file_size_mb` → 413.
  - PUT path escape → 400.
  - DELETE existing → 200 + audit.
  - DELETE missing → 404.
- **Files**
  - `vtc-service/src/routes/website/files.rs`
  - `vti-common/src/audit/event.rs` (variant stubs)
  - `trust-tasks/website/files/{write,delete}/1.0/...`
- **Deps**: M5.5.1
- **Pre-impl decision**: **D6** (ETag optimistic
  concurrency), **D8** (audit variants).

### `[ ]` M5.5.3 — `POST /v1/website/deploy`

- **Acceptance**
  - Admin-gated. Body-cap override `max_bundle_size_mb`
    (default 50). Accepts `application/gzip` tar.gz.
  - Flow:
    1. Stream body into a temp file.
    2. Verify it's a valid tar.gz (header check).
    3. **Pre-extract path safety**: iterate every entry,
       reject any with `..`, absolute paths, symlinks,
       hidden top-level, exec-bit, or blocklisted
       extension. (Mirror the public-handler safety
       rules at write time.)
    4. **Live mode**: extract to
       `<root_dir>.staging.<timestamp>/`, then `rename` to
       `root_dir`. Old `root_dir` moves to
       `<root_dir>.previous.<timestamp>/`, retained for
       one cycle for diagnostic recovery, pruned on the
       next deploy.
    5. **Managed mode**: extract to `root_dir/gen-N/`
       (N = highest_existing + 1). Update the `current`
       symlink atomically (`symlink + rename` via
       temp-name pattern). Prune generations beyond
       `managed_generations_keep`.
    6. Emit `WebsiteBundleDeployed` audit with the
       bundle digest + bytes + mode + target_generation
       (managed) + pruned count.
  - Trust Task `website/deploy/1.0` ships.
- **Verify** 6 integration tests:
  - Happy live-mode deploy → contents served + audit
    emitted.
  - Happy managed-mode deploy → new gen-N + symlink
    swap + retention prune.
  - Bundle with `..` entry rejected pre-extract.
  - Bundle exceeding 50 MB → 413.
  - Bundle with symlink entry rejected.
  - Mid-extract crash recovery (kill the process; on
    restart the staging dir is detected + cleaned).
- **Files**
  - `vtc-service/src/routes/website/deploy.rs` (new)
  - `vtc-service/src/website/storage.rs` (extend)
  - `trust-tasks/website/deploy/1.0/{spec.md,schema.json}`
- **Deps**: M5.5.2
- **Pre-impl decision**: **D6**, **D7**, **D8**.

### `[ ]` M5.5.4 — `GET /v1/website/generations` + `POST /v1/website/rollback/{gen}`

- **Acceptance**
  - List handler: managed-mode only (live mode → 400
    `WebsiteNotManagedMode`). Returns
    `{ generation: u32, deployed_at, is_current: bool,
       size_bytes: u64 }` per row. Admin-gated.
  - Rollback handler: managed-mode only. Validates the
    target generation exists; swaps the `current`
    symlink atomically; emits
    `WebsiteGenerationRolledBack { from_generation,
    to_generation }`. Returns 200.
  - Rollback to the **current** generation → 200 no-op
    (idempotent).
  - Trust Tasks ship: `website/generations/list/1.0`,
    `website/rollback/1.0`.
- **Verify** 5 integration tests:
  - List in managed mode → all gens enumerated.
  - List in live mode → 400.
  - Rollback to existing past gen → contents served from
    that gen.
  - Rollback to current → 200 no-op.
  - Rollback to nonexistent → 404.
- **Files**
  - `vtc-service/src/routes/website/generations.rs` (new)
  - `vtc-service/src/website/storage.rs`
  - `trust-tasks/website/generations/list/1.0/...`
  - `trust-tasks/website/rollback/1.0/...`
- **Deps**: M5.5.3
- **Pre-impl decision**: **D7**, **D8**.

### Checkpoint — Website management gate met

After M5.5.4: full website management API live; ETag
concurrency + atomic deploy + managed-mode rollback + 5
audit envelopes ship; body-cap overrides verified.

---

## M5.6 — Admin UX: sibling-repo bootstrap + `build.rs` + offline fallback

### `[ ]` M5.6.0 — Sibling repo bootstrap (out-of-tree, D1 decision)

> **BLOCKED on D1 decision** — confirm with user before
> opening this PR. Three options per plan §D1; default (a).

- **Acceptance** (assuming D1 default):
  - New GitHub repo `OpenVTC/vtc-admin-ui` created.
  - Skeleton: Vite + TypeScript + React. Pages:
    - `/login` (WebAuthn UV ceremony → admin cookie).
    - `/` (Community profile read).
    - `/members` (member list — read-only first cut).
  - Release CI: tag-driven, builds `dist/`, packs tar.gz
    with deterministic ordering, signs with the OpenVTC
    release key, attaches to a GitHub Release.
  - **No changes to this repo** for this milestone — it's
    purely upstream scaffolding work.
- **Verify**
  - First tagged release `v0.0.1` produces tarball +
    signature.
  - Public key fingerprint recorded in this plan's
    outcomes section.
- **Files** — out-of-tree.
- **Deps**: D1 decision.
- **Pre-impl decision**: **D1**, **D2**.

### `[ ]` M5.6.1 — Vendored release public key + offline placeholder

- **Acceptance**
  - New file `vtc-service/release-keys/openvtc-admin-ui.pub`:
    32-byte Ed25519 public key, hex-encoded, with a
    header comment (issuance date + fingerprint).
  - New directory `vtc-service/vendor/admin-ui-placeholder/`:
    a minimal, pre-built admin SPA (single index.html +
    one CSS + one JS) showing "VTC admin UX — offline
    build" + the daemon's `/health` status (via a fetch
    on page load). Tracked in git.
  - New file `vtc-service/admin-ui-pin.toml`:
    - `version` (initial: `0.0.1` or "offline" if M5.6.0
      not yet landed).
    - `tarball_sha256` (placeholder hash if offline).
    - `release_url` (empty if offline).
    - `signature_url` (empty if offline).
- **Verify** 2 unit tests (parsing the pin TOML +
  parsing the public key).
- **Files**
  - `vtc-service/release-keys/openvtc-admin-ui.pub` (new)
  - `vtc-service/admin-ui-pin.toml` (new)
  - `vtc-service/vendor/admin-ui-placeholder/` (new dir)
- **Deps**: M5.6.0 (or D1 fallback)
- **Pre-impl decision**: **D2**, **D3**, **D13**.

### `[ ]` M5.6.2 — `build.rs` fetch + verify + extract

- **Acceptance**
  - New `vtc-service/build.rs`:
    1. Read `admin-ui-pin.toml`.
    2. If `VTC_OFFLINE_BUILD=1` → copy `vendor/admin-ui-
       placeholder/` to `OUT_DIR/admin-ui/`.
    3. Otherwise: fetch `release_url` + `signature_url`
       (using `reqwest` blocking client, gated behind a
       new `[build-dependencies]`).
    4. Verify Ed25519 signature against vendored public
       key.
    5. Verify SHA-256 digest matches the pin.
    6. Extract tar.gz to `OUT_DIR/admin-ui/`.
    7. Set `cargo:rerun-if-changed=admin-ui-pin.toml`.
  - On verification failure → `panic!` with a clear
    error pointing the operator at the offline build
    flag.
  - `include_dir!` macro consumes `OUT_DIR/admin-ui/` at
    compile time.
- **Verify**
  - `cargo build` with offline env var → placeholder
    used.
  - `cargo build` with mocked fetch (test fixture
    serving the placeholder tarball over a local
    `tiny_http` listener) → release-flow code path
    exercised.
  - `cargo build` with no env var + no network → fails
    with a clear error message.
- **Files**
  - `vtc-service/build.rs` (new)
  - `vtc-service/Cargo.toml` (`[build-dependencies]`:
    `reqwest = "0.12"` blocking feature, `ed25519-dalek`,
    `sha2`, `toml`, `tar`, `flate2`)
  - `vtc-service/src/admin_ui/mod.rs` (new — exposes
    `EMBEDDED_DIR` via `include_dir!`)
- **Deps**: M5.6.1
- **Pre-impl decision**: **D2**, **D3**, **D13**.

---

## M5.7 — Admin UX mount + RP-ID rules + `AdminUiServed` audit

### `[ ]` M5.7.1 — `admin-ui` feature flag + embedded mount

- **Acceptance**
  - New cargo feature `admin-ui` in
    `vtc-service/Cargo.toml`. Default-on for the `vtc`
    binary.
  - Feature gates:
    - The `build.rs` fetch path (no admin-ui feature → no
      tarball fetch, no include_dir).
    - The `routes::admin_ui` module.
    - The `routing.admin_ui` mount attach.
  - `admin_ui.mode = "embedded"` (default): serve the
    baked SPA at `routing.admin_ui.mount` via
    `tower-http`'s `ServeDir`-equivalent backed by
    `include_dir`.
  - `admin_ui.mode = "external"`: skip embedding;
    `routing.admin_ui.mount` returns 404; the operator-
    supplied origin is added to `cors.allowed_origins`
    at config-load time.
  - SPA history-mode fallback: unmatched routes under
    `/admin/*` serve `index.html` so client-side
    routing works.
- **Verify** 4 integration tests:
  - GET `/admin/` → 200 + serves index.html.
  - GET `/admin/static/app.js` → 200 + correct
    content-type.
  - External mode → `/admin/*` returns 404.
  - External mode → configured origin lands in CORS
    allowlist.
- **Files**
  - `vtc-service/Cargo.toml` (`admin-ui` feature)
  - `vtc-service/src/admin_ui/mod.rs`
  - `vtc-service/src/routes/admin_ui.rs` (new)
  - `vtc-service/src/config.rs` (`AdminUiConfig` block:
    `mode`, `external_origin`, `rp_id`)
- **Deps**: M5.6.2, M5.3.2

### `[ ]` M5.7.2 — `GET /admin/build-info.json` + `AdminUiServed` audit

- **Acceptance**
  - New endpoint `GET /admin/build-info.json` (no auth —
    surfaces the public release metadata).
  - Returns `{ tarball_sha256, version, mode, built_at,
    offline_build: bool }`.
  - `AdminUiServed` audit envelope emitted once at boot:
    `{ tarball_sha256, tarball_version, mode }`.
  - Trust Task `admin-ui/build-info/1.0` ships.
- **Verify** 3 integration tests:
  - GET build-info → 200 with expected fields.
  - Boot emits `AdminUiServed` exactly once.
  - External mode → `mode: "external"`.
- **Files**
  - `vtc-service/src/routes/admin_ui.rs`
  - `vti-common/src/audit/event.rs` (variant stub)
  - `trust-tasks/admin-ui/build-info/1.0/{spec.md,schema.json}`
- **Deps**: M5.7.1
- **Pre-impl decision**: **D8**.

### `[ ]` M5.7.3 — WebAuthn RP-ID rules

- **Acceptance**
  - The `webauthn` config block extended with:
    - `rp_id: Option<String>` (operator override).
    - When `None`: derive from routing mode:
      - Path mode → base host (e.g. `vtc.example.com`).
      - Subdomain mode → base domain (e.g.
        `example.com`) so passkeys validate across the
        api / admin / website subdomains.
  - Config-load validation: if `routing.admin_ui.host`
    and `routing.api.host` resolve to different base
    domains, refuse load with a clear error.
  - `RP ID` change between boots → existing passkeys
    rejected (documented in operator runbook;
    re-register flow lands in M5.10's docs).
- **Verify** 4 unit tests:
  - Path mode → RP ID = configured base host.
  - Subdomain mode (admin.x.com + api.x.com) → RP ID =
    `x.com`.
  - Mismatched base domains → config error.
  - Operator override → RP ID = the override value.
- **Files**
  - `vtc-service/src/config.rs`
  - `vtc-service/src/webauthn.rs` (extend)
- **Deps**: M5.7.1

### Checkpoint — Admin UX gate met

After M5.7.3: baked SPA served at `/admin/*` (or external
mode skips); build-info surfaces the release digest +
emits `AdminUiServed`; RP-ID rules track routing mode.

---

## M5.8 — Audit variants snapshot tests

### `[ ]` M5.8.1 — Round-trip + discriminator coverage

- **Acceptance**
  - The **five** Phase 5 audit variants (D8:
    `WebsiteFileWritten`, `WebsiteFileDeleted`,
    `WebsiteBundleDeployed`, `WebsiteGenerationRolledBack`,
    `AdminUiServed`) each gain a round-trip snapshot test
    in `vti-common/src/audit/event.rs`.
  - All five added to `variant_discriminator_strings`
    coverage table.
- **Verify** `cargo test -p vti-common audit::` passes.
- **Files**
  - `vti-common/src/audit/event.rs`
- **Deps**: M5.5.4, M5.7.2 (last endpoints to land their
  variants)
- **Pre-impl decision**: **D8**.

---

## M5.9 — Trust Task drafts + index

### `[ ]` M5.9.1 — On-disk + index entries

- **Acceptance**
  - **Eight** new Trust Task directories per plan §D9
    plus the one from M5.2.3 → **9 total**:
    - `website/files/list/1.0`
    - `website/files/show/1.0`
    - `website/files/write/1.0`
    - `website/files/delete/1.0`
    - `website/deploy/1.0`
    - `website/generations/list/1.0`
    - `website/rollback/1.0`
    - `admin-ui/build-info/1.0`
    - `auth/admin-login/1.0` (added at M5.2.3)
  - `trust-tasks/index.json` carries all nine new
    entries (total 55 + 9 = 64; note: plan §D9 said 8;
    the cookie-login flow added one).
  - Each Trust Task ID is `exact_matched` at route
    attach in `routes/mod.rs`.
  - CI script verifies on-disk count matches
    `index.json` count.
- **Files**
  - All `trust-tasks/{...}/1.0/*` directories above.
  - `trust-tasks/index.json`
- **Deps**: M5.5.4, M5.7.2, M5.2.3
- **Pre-impl decision**: **D9**.

---

## M5.10 — Phase 5 outcomes + spec amendments + reference templates

### `[ ]` M5.10.1 — Document the as-shipped reality

- **Acceptance**
  - `tasks/vtc-mvp/phase-5-plan.md` gains a "Phase 5
    outcomes" section recording the as-shipped reality
    for D1–D13 + R1–R9 realisation status.
  - `docs/05-design-notes/vtc-mvp.md` §§9.2 / 9.3 / 9.4 /
    9.5 / 11.4 / 12.1 / 12.2 / 14.4 / 17.1 amended per
    the spec-amendment surface in the plan.
  - Memory entry `project_vtc_mvp.md` updated.
- **Files**
  - `tasks/vtc-mvp/phase-5-plan.md`
  - `docs/05-design-notes/vtc-mvp.md`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M5.8.1, M5.9.1

### `[ ]` M5.10.2 — Operator reference documentation

- **Acceptance**
  - New doc `docs/04-reference/website-management.md`:
    - Live vs managed mode comparison.
    - Bundle format + path-safety rules.
    - CSP override file format + examples (Vue / React
      SPA).
    - ETag optimistic concurrency + concurrent-edit
      caveat (D6).
    - Retention behaviour (D7).
  - New doc `docs/04-reference/admin-ui-deployment.md`:
    - Embedded vs external mode comparison.
    - `VTC_OFFLINE_BUILD=1` flow.
    - Release pipeline trust model (D2 + D13).
    - RP-ID migration runbook (subdomain ↔ path mode
      passkey re-registration).
  - New doc `docs/04-reference/routing-modes.md`:
    - Path vs subdomain mode comparison.
    - CORS + cookie-scope specifics.
    - CSRF middleware behaviour + bypass cases.
    - Reverse-proxy / CDN integration tips.
  - New doc `docs/04-reference/personhood-templates.md`
    (closes §17.1 OQ#1):
    - At least 3 reference policies (single-witness,
      multi-witness, witness-age-bounded).
    - Migration notes from the default policy.
- **Files**
  - `docs/04-reference/website-management.md` (new)
  - `docs/04-reference/admin-ui-deployment.md` (new)
  - `docs/04-reference/routing-modes.md` (new)
  - `docs/04-reference/personhood-templates.md` (new)
- **Deps**: M5.10.1

---

## M5.11 — Phase 5 / MVP gate

### `[ ]` M5.11.1 — Workspace gate green

- **Acceptance** (mirrors M3.14.1 / M4.12.1)
  - `cargo build --workspace` green.
  - `cargo build --workspace --all-features` green.
  - `cargo build --workspace --no-default-features`
    green (website + admin-ui both off).
  - `VTC_OFFLINE_BUILD=1 cargo build -p vtc-service`
    green.
  - `cargo test --workspace` green.
  - `cargo clippy --workspace --all-targets -- -D
    warnings` clean.
  - `cargo fmt --check` clean.
  - `trust-tasks/index.json` lists every Phase 5 Trust
    Task with matching on-disk files; count = 64.
  - Memory entry `project_vtc_mvp.md` updated with the
    as-shipped outcomes for D1–D13.
  - Phase-5-todo milestones all flipped to `[x]`.
  - Spec amendments applied (§§9.2 / 9.3 / 9.4 / 9.5 /
    11.4 / 12.1 / 12.2 / 14.4 / 17.1).
- **Verify** CI green on the merge commit.
- **Files**
  - `trust-tasks/index.json`
  - `~/.claude/projects/.../memory/project_vtc_mvp.md`
- **Deps**: M5.8.1, M5.9.1, M5.10.1, M5.10.2

### Checkpoint — MVP gate met

After M5.11.1: VTC ships a complete MVP — install +
admin + member CRUD + policy + credentials + status
list + renewal + DID rotation + trust-registry sync +
cross-community recognition + relationships graph +
personhood + custom endorsements + public website +
admin UX + routing-mode-flexible deployment. The
binary covers the spec's §16 deliverables in full.

---

## Decision register — needs sign-off before code lands

| ID | Decision | Default | Status |
|---|---|---|---|
| D1 | `OpenVTC/vtc-admin-ui` strategy | (a) Bootstrap sibling repo | **NEEDS USER SIGN-OFF** |
| D2 | Release-key generation + storage | Ed25519 + vendored pub key | Default |
| D3 | Offline build fallback location | `vtc-service/vendor/admin-ui-placeholder/` | Default |
| D4 | Routing dispatch implementation | (ii) Nest with per-surface layers | Default |
| D5 | CSRF token storage | (b) Stateless double-submit | Default |
| D6 | Website concurrency model | ETag optimistic concurrency, no locks | Default |
| D7 | Managed-mode retention | Count-based, keep 5 | Default |
| D8 | Audit variants for website ops | 5 variants (see plan) | Default |
| D9 | Trust Task allocation | 8 (+1 from M5.2.3 = 9 total) | Default |
| D10 | Catch-all collision audit | No current collisions; `/health` priority preserved | Confirmed |
| D11 | §14.4 guards (body cap + governor) | Bundle into M5.1 | **NEEDS USER SIGN-OFF** — Phase 0–4 didn't land these |
| D12 | Admin UX session model | (ii) HttpOnly cookie + double-submit CSRF | **NEEDS USER SIGN-OFF** — adds new auth path beyond bearer JWT |
| D13 | Tarball digest pin file | `vtc-service/admin-ui-pin.toml` | Default |
```

