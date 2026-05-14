# Website + admin UX

Phase 5 ships three operator-facing surfaces on the same VTC
process: the **JSON API** at `/v1/*`, the **admin SPA** at
`/admin/*`, and the **public community website** at `/`. Each has
its own cookie scope, body cap, and CSP. This page covers the
public-website and admin-UX surfaces; the routing infrastructure
that makes them coexist safely is shared.

## Surface map

```mermaid
graph TB
    subgraph DAEMON["vtc daemon — single process, single port"]
        HEALTH[/health<br/>Trust-Task exempt]
        API[/v1/*<br/>JSON API]
        ADMIN[/admin/*<br/>SPA + build-info]
        WEB[/<br/>filesystem or default]
    end

    OPSCLI[cnm-cli<br/>bearer JWT]
    SPA[Admin SPA<br/>session cookie + CSRF]
    PUB[Public site visitors<br/>browser]
    APP[Application<br/>bearer JWT]

    OPSCLI --> API
    SPA --> ADMIN
    SPA --> API
    PUB --> WEB
    APP --> API
    PUB -. POST form .-> API

    classDef pub fill:#fff3e0,stroke:#c77a00,color:#5a3b00
    classDef priv fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    class WEB,PUB pub
    class API,ADMIN,SPA,OPSCLI,APP,HEALTH priv
```

The default routing assignment:

| Mount | Purpose | Body cap | CSP |
|---|---|---|---|
| `/health` | Health probe (Trust-Task exempt) | 1 MiB | — |
| `/v1/*` | JSON API | 1 MiB global, per-route override on website mgmt | — (JSON wire) |
| `/admin/*` | Admin SPA + `/admin/build-info.json` | 1 MiB | default-src 'self' |
| `/` (catch-all) | Public website | 1 MiB | default-src 'self' (overridable per site) |

Operators can rewrite these mounts via `routing.api.mount`,
`routing.admin_ui.mount`, `routing.website.mount`, or switch to
subdomain mode by setting per-surface `host = "..."`. Phase 5 path-
prefix mode is the default.

## Public website

### Deploy modes

```mermaid
graph TB
    subgraph Live["Live mode (default)"]
        root1[website.root_dir/]
        files1[index.html · assets · ...]
        root1 --> files1
        files1 -->|GET /| serve1[serve handler]
        deploy_l[POST /v1/website/deploy]
        deploy_l -.->|atomic rename| root1
    end

    subgraph Managed["Managed mode"]
        root2[website.root_dir/]
        gen1[gen-1/]
        gen2[gen-2/]
        gen3[gen-3/]
        current[current → gen-3<br/>(symlink)]
        root2 --> gen1
        root2 --> gen2
        root2 --> gen3
        root2 --> current
        current -.points to.-> gen3
        gen3 -->|GET /| serve2[serve handler]

        deploy_m[POST /v1/website/deploy]
        deploy_m -.->|extract| gen4[gen-4 new]
        deploy_m -.->|symlink swap| current
        rollback[POST /v1/website/rollback/2]
        rollback -.->|symlink swap| current
    end
```

| Mode | Where served from | Bundle deploy | Operator workflow |
|---|---|---|---|
| **`live`** (default) | `website.root_dir/` directly | Extract to `<root>.staging.<ts>/` + atomic rename | `scp` / `rsync` / `git pull` directly into `root_dir`, OR `POST /v1/website/deploy` |
| **`managed`** | `website.root_dir/current/` via symlink to `gen-N/` | Extract to `gen-N+1/` + symlink swap + prune | `POST /v1/website/deploy` for new gen; `POST /v1/website/rollback/{gen}` for rollback |

In managed mode the `current` symlink swap is atomic via the
`symlink + rename` idiom — concurrent readers never see a broken
link. `managed_generations_keep` (default 5) prunes oldest gens.

### Path safety

Every request walks through the same safety chain before hitting
the filesystem:

```mermaid
flowchart TD
    req([GET /some/path])
    ctrl{NUL or<br/>control chars?}
    nfc{NFC-normalised?}
    hidden{Any segment<br/>starts with .?}
    block{Extension in<br/>blocklist?<br/>(.cgi/.php/.exe)}
    canon{Canonicalises<br/>within root_dir?}
    exec{Exec bit set?<br/>(Unix only)}
    serve[Serve file]
    rej_400[400 / 403 / 404]

    req --> ctrl
    ctrl -- yes --> rej_400
    ctrl -- no --> nfc
    nfc -- no --> rej_400
    nfc -- yes --> hidden
    hidden -- yes --> rej_400
    hidden -- no --> block
    block -- yes --> rej_400
    block -- no --> canon
    canon -- no --> rej_400
    canon -- yes --> exec
    exec -- yes --> rej_400
    exec -- no --> serve

    classDef bad fill:#ffebee,stroke:#c62828,color:#5a0303
    classDef good fill:#e8f5e9,stroke:#3e8e41,color:#1b3a1f
    class rej_400 bad
    class serve good
```

Bundle uploads run the same chain on every entry **before**
extraction. A bundle containing a single forbidden entry is rejected
in toto.

### CSP override

Default CSP: `default-src 'self'; script-src 'self'; object-src
'none'; base-uri 'self'`.

Operators relax it by dropping a `.vtc-website.toml` at the root:

```toml
# vtc-service/website.example.com/.vtc-website.toml
csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
```

The file is read on every request (no daemon restart needed). Empty
or missing file → default CSP applies.

### Default landing page

When `website.root_dir` is **unset**, the daemon serves a small
in-tree landing page (HTML/CSS/JS at `vtc-service/website-default/`)
that fetches `/v1/community/profile` + `/health` and renders them.
The moment an operator sets `root_dir`, the filesystem handler
takes over and the default is unreachable.

## Admin UX

```mermaid
graph LR
    src[vtc-service/admin-ui/<br/>index.html · app.css · app.js]
    binary[vtc binary]
    routes[/admin/* handler]
    info[/admin/build-info.json]

    src -- "include_dir!<br/>at compile time" --> binary
    binary --> routes
    binary --> info
```

The admin SPA source is **in-tree**. Per Phase 5 D1 the user chose
this over a sibling `OpenVTC/vtc-admin-ui` repo + signed-tarball
fetch:

- **Pros**: `cargo build` is self-contained — no npm, no node, no
  network, no release-signing infrastructure.
- **Cons**: Rich SPA tooling (TypeScript, React, Vite) can't live
  here without dragging node into the build path. The MVP shell is
  plain HTML/CSS/JS.

Operators wanting a richer UX replace the files in
`vtc-service/admin-ui/` and rebuild. The `admin_ui.mode = "external"`
config knob skips the embedded SPA and adds the operator-supplied
origin to `cors.allowed_origins` so an externally-hosted SPA can
drive the API.

### `/admin/build-info.json`

Unauthenticated. Returns:

```json
{
  "version": "0.6.0",
  "indexSha256": "<sha256 of index.html>",
  "fileCount": 4,
  "mode": "embedded"
}
```

The `indexSha256` matches the `AdminUiServed` audit envelope emitted
exactly once at boot — operators who suspect compromise can pin the
running build against the audit record.

### Cookie session vs bearer

```mermaid
graph LR
    cli[cnm-cli] -->|Authorization: Bearer| api[/v1/*]
    dc[DIDComm bridge] -->|authcrypt| api
    spa[Admin SPA<br/>browser] -->|Cookie: vtc_admin_session<br/>+ X-CSRF-Token| api
```

Three concurrent auth paths:

- **Bearer JWT** — `Authorization: Bearer <jwt>`. Used by
  `cnm-cli`, DIDComm bridges, programmatic clients.
- **Cookie session** — `Cookie: vtc_admin_session=<jwt>`. Used by
  the admin SPA. Path-scoped to `/admin` so the public website
  origin can't read it. HttpOnly + Secure + SameSite=Strict.
- **CSRF double-submit** — `csrf=<random>` cookie (JS-readable) +
  `X-CSRF-Token` header. Required on every mutating call from the
  cookie session. Bearer-only callers don't carry CSRF.

Both flow through the same `AuthClaims` extractor in `vti-common`,
which tries bearer first then falls back to cookie. Bearer wins
when both are present.

### Admin login

`POST /v1/auth/admin-login` accepts the same DIDComm-packed
challenge response as `POST /v1/auth/` and **additionally** returns
`Set-Cookie` headers carrying the session JWT + CSRF token. The
bearer endpoint and admin-login endpoint share their internal
mint logic; only the response shape differs.

## Routing modes

```mermaid
graph TB
    subgraph PathMode["Path mode (default)"]
        host_p[example.com]
        v1[/v1/*]
        admin_p[/admin/*]
        web_p[/<br/>catch-all]
        host_p --> v1
        host_p --> admin_p
        host_p --> web_p
    end

    subgraph SubdomainMode["Subdomain mode"]
        api_h[api.example.com]
        admin_h[admin.example.com]
        web_h[example.com]
        api_h --> v1b[/v1/*]
        admin_h --> admin_b[/admin/*]
        web_h --> web_b[/]
    end
```

Subdomain mode is enabled by setting per-surface `host = "..."` in
the routing config. A tower middleware (`routing::host_dispatch`)
short-circuits 404 when an unrecognised `Host` header arrives in
strict mode (default). Set `routing.subdomain_mode_strict = false`
to allow path-mode fallback for unknown hosts — debug aid only.

**WebAuthn `RP ID`** must be set correctly per mode:

| Mode | `admin_ui.rp_id` |
|---|---|
| Path mode | Base host (e.g. `example.com`) |
| Subdomain mode | Base **domain** so passkeys remain valid across `api.` + `admin.` (e.g. `example.com`, not `admin.example.com`) |

Migrating the admin UX to a different base domain forces every
passkey to re-register. Operator runbook.

## CLI quick reference

```sh
# Website management
cnm website files list
cnm website files show <path>
cnm website files write <path> --content @file.html
cnm website files delete <path>
cnm website deploy --bundle ./site.tar.gz

# Managed mode
cnm website generations list
cnm website rollback --to-gen 2

# Admin UX
cnm admin build-info     # → /admin/build-info.json output
```

## Configuration

```toml
[website]
root_dir = "/var/lib/community/site"      # unset → default landing page
deploy_mode = "live"                       # or "managed"
live_cache_ttl_seconds = 5
managed_generations_keep = 5
cache_control = "public, max-age=300"
executable_blocklist = [".cgi", ".php", ".exe"]
max_bundle_size_mb = 50
max_file_size_mb = 10
csp_override_file = ".vtc-website.toml"

[admin_ui]
mode = "embedded"                          # or "external"
external_origin = "https://admin.example.com"   # only when mode=external
rp_id = "example.com"                      # WebAuthn RP ID

[routing]
subdomain_mode_strict = true

[routing.api]
mount = "/v1"
# host = "api.example.com"                 # uncomment for subdomain mode

[routing.admin_ui]
mount = "/admin"

[routing.website]
mount = "/"

[cors]
allowed_origins = []                       # add SPA origin for external mode
```

## See also

- [VTC MVP spec §9, §12](../05-design-notes/vtc-mvp.md) — routing
  + website + admin UX surface.
- [Community lifecycle](community-lifecycle.md) — the public form
  POST to `/v1/join-requests` originates from the public website.
- [Architecture](architecture.md) — how the routing middleware
  composes.
