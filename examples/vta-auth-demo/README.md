# VTA Auth Demo

A static-file harness for exercising the VTA's authentication surface
from a browser. Zero build step — open `index.html` via a local HTTP
server and click around.

## What it exercises

| Flow                                | Surface                                                | Status      |
|-------------------------------------|--------------------------------------------------------|-------------|
| Passkey login (DID-VM-resolved WebAuthn) | `POST /auth/passkey-login/start` + browser WebAuthn API + `POST /auth/passkey-login/finish` | implemented |
| Session inspection                  | `GET /auth/sessions`                                   | implemented |
| Revoke session                      | `DELETE /auth/sessions/{session_id}`                   | implemented |
| Trust-task dispatch                 | `POST /api/trust-tasks` with bearer auth               | implemented |
| Legacy challenge / authenticate     | `POST /auth/challenge` + `POST /auth/`                 | **not in demo** |
| Refresh                             | `POST /auth/refresh`                                   | **not in demo** |

The legacy challenge/authenticate and refresh flows take DIDComm-packed
messages as their request body, not browser-friendly JSON. Use
`pnm auth` (or any programmatic SDK client) for those paths — they need
a DIDComm pack stack the browser doesn't have built in.

## Prerequisites

- A running VTA reachable from your machine (typically
  `http://localhost:8100` — `cargo run -p vta-service` from a
  workspace checkout).
- A user with a passkey verificationMethod published on their DID
  document. Set one up via `pnm passkey-vms enroll-challenge` →
  follow the browser ceremony → `pnm passkey-vms enroll-submit`. The
  enrolment ceremony itself requires an authenticated session, so
  you'll need a pre-existing admin DID configured on the VTA before
  the demo can drive the passkey-login flow.
- A static-file server. Anything will do. Two easy options:

  ```sh
  # Python
  cd examples/vta-auth-demo
  python3 -m http.server 8000

  # or any other static server you have lying around
  npx http-server -p 8000 examples/vta-auth-demo
  ```

  WebAuthn requires a "secure context"; `localhost` is one of those
  even over HTTP, so no TLS dance is needed for the demo.

## Configuring the VTA for cross-origin access

The demo runs at `http://localhost:8000` and fetches the VTA at
`http://localhost:8100`. Different origins → browser CORS preflight
→ VTA needs to advertise that the demo's origin is allowed.

Add this to your VTA's config TOML:

```toml
[server]
host = "127.0.0.1"
port = 8100
cors_origins = ["http://localhost:8000"]
```

Reload the VTA after changing the config (`pnm vta restart` or kill
+ restart the binary). The CORS layer only activates when
`cors_origins` is non-empty — production VTAs leave it empty by
default.

Important: the CORS layer doesn't accept wildcards. Add only the
specific origins you want allowed. The bearer token is the only
cross-origin credential, so a loose CORS policy means a loose
authorisation policy.

## Running through the flows

1. Open `http://localhost:8000` in your browser.
2. **Step 1 — Connect**: confirm "Check /health" returns OK. If you
   get a CORS error in the browser console, the VTA's
   `cors_origins` doesn't include this page's origin.
3. **Step 2 — Passkey login**:
   - Enter the DID whose passkey you want to authenticate as.
   - Click "Start" — the VTA returns a challenge and the credential
     IDs the DID document advertises.
   - Click "Finish" — the browser invokes
     `navigator.credentials.get(...)`. Touch ID / Face ID / a security
     key prompt appears. Once the assertion comes back, the demo
     POSTs it to `/auth/passkey-login/finish` and stores the JWT.
4. **Step 3 — Session inspection** (appears after login):
   - "List active sessions" shows every session on this VTA the
     caller can see (any-authed for own; admin sees all).
   - "Revoke current session" deletes the JWT's session row. After
     revocation, sending another trust-task should 401.
5. **Step 4 — Trust-task dispatch** (appears after login):
   - Pick a URI from the dropdown (e.g.
     `discovery/capabilities/1.0`). The payload field auto-fills
     with a minimal body.
   - Click "Send" — the demo wraps the payload in a trust-task
     envelope and POSTs it to `/api/trust-tasks`. The full request
     and response are printed.
   - Edit the payload textarea for other URIs that need parameters
     (e.g. `keys/get/1.0` needs `{"key_id": "..."}`).

## Source layout

```
examples/vta-auth-demo/
├── index.html      UI structure
├── app.js          Flow logic (vanilla ES modules, no build)
├── styles.css      Minimal dark-theme styling
└── README.md       This file
```

## Related crates

- **vti-webauthn** — the server-side verifier the passkey-login
  finish endpoint calls into. Server-side counterpart to the
  WebAuthn assertion the demo's "Finish" step sends.
- **vta-sdk** — the Rust client library. `VtaClient::backup_export_via_descriptor` etc. are the programmatic
  equivalents of the trust-task dispatch flow exercised in step 4.
- **vta-service::routes::auth** — the route handlers behind every
  `/auth/*` endpoint.
- **vta-service::routes::trust_tasks** — the dispatcher behind
  `POST /api/trust-tasks` that fans out to per-slice handlers.

## Known limitations

- **Legacy challenge/auth & refresh** are DIDComm-message-based and
  not callable from a browser without a DIDComm pack/unpack stack.
  They're deliberately out of scope for this demo. Use `pnm auth` or
  the SDK for those paths.
- **Session-bound passkey assertions**: v0.1 of the passkey-login
  flow stores the verifying-method id implicitly (the server matches
  on credential_id). Future versions may require the client to
  declare `verificationMethod` explicitly; the demo passes an empty
  string today.
- **No persistence**: the demo holds the JWT in memory. Reloading
  the page loses the session.
