# VTA Auth Demo

A static-file harness for exercising the VTA's authentication surface
from a browser. Zero build step — open `index.html` via a local HTTP
server and click around.

## What it exercises

| Step | Flow                                  | Surface                                                | Status |
|---|------------------------------------------|--------------------------------------------------------|---|
| 1 | Health check                              | `GET /health`                                         | implemented |
| 2 | Bootstrap auth (paste JWT)                | (purely client-side; needed when there's no passkey VM yet) | implemented |
| 3 | Enrol a passkey VM                        | `POST /did/verification-methods/passkey/challenge` + browser WebAuthn API + `POST /did/verification-methods/passkey` | implemented |
| 4 | Passkey login (DID-VM-resolved WebAuthn)  | `POST /auth/passkey-login/start` + browser WebAuthn API + `POST /auth/passkey-login/finish` | implemented |
| 5 | Session inspection + revoke               | `GET /auth/sessions`, `DELETE /auth/sessions/{id}`    | implemented |
| 6 | Trust-task dispatch                       | `POST /api/trust-tasks` with bearer auth              | implemented |
| 7 | DIDComm primitives smoke-test             | (purely client-side; resolve + pack against any DID)  | implemented |
| — | Legacy challenge / authenticate           | `POST /auth/challenge` + `POST /auth/`                | **not in demo** |
| — | Refresh                                   | `POST /auth/refresh`                                  | **not in demo** |

The legacy challenge/authenticate and refresh flows take DIDComm-packed
messages as their request body. Step 7 ships the JS DIDComm pack stack
(`vti-didcomm-js`) — it doesn't drive the legacy flow itself yet, but
it shows the primitives work in a real browser. A future step can wire
them up to actually call `/auth/`.

## Prerequisites

- A running VTA reachable from your machine (typically
  `http://localhost:8100`).
- An existing admin DID set up via `pnm` (your cold-start operator
  identity). PNM authenticates via the legacy DIDComm-based flow, so
  this works against an unmodified VTA.
- The VTA's `[server] cors_origins` must include this page's origin
  (default `http://localhost:8000`). See "Configuring the VTA" below.
- A WebVH-managed DID where you want to enrol a passkey VM. Easiest
  option: mint one with `pnm webvh create-did --context <ctx>` and
  grant it admin role with `pnm acl create --did <new-did> --role admin
  --contexts <ctx>`. You can also use an existing one.
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

Wildcards are not accepted. Add only the specific origins you want
allowed. The bearer token is the only cross-origin credential, so a
loose CORS policy means a loose authorisation policy.

## Where the JWT for Step 2 comes from

The demo's Step 2 (Bootstrap) needs an existing JWT, because Step 3
(enrolment) is admin-gated and there's no passkey-derived JWT yet.

Get one from the CLI:

```sh
pnm auth show-token
```

This prints the current admin JWT to stdout (re-authenticating first
if the cached one expired). Copy the output and paste it into the
"Access token (JWT)" box in Step 2.

Once a passkey VM is enrolled (Step 3), you can use Step 4 (passkey
login) instead — it produces a JWT directly, no `pnm auth show-token`
needed.

## Running through the flows

1. **Step 1 — Connect**: confirm "Check /health" returns OK. CORS
   errors in the browser console mean the VTA's `cors_origins`
   doesn't include this page's origin.

2. **Step 2 — Bootstrap**:
   - Run `pnm auth show-token` in your terminal; copy the output.
   - Paste into the textarea, click "Use this token".
   - Status line shows the JWT's role and expiry.
   - Sessions + trust-task panels (Steps 5/6) are now unlocked.

3. **Step 3 — Enrol a passkey VM**:
   - Enter a WebVH-managed DID your operator has admin role on.
   - Optional label (e.g. `"MacBook Touch ID"`).
   - Click "Enrol passkey".
   - Browser invokes WebAuthn registration; touch your authenticator.
   - On success the demo shows the new VM's `id`, the computed
     multikey, and the WebVH version that recorded the change.
   - The enrolled DID is pre-filled into Step 4's input.

4. **Step 4 — Passkey login** (you can do this fresh after enrolment
   or after signing out):
   - Click "Start" to fetch the challenge.
   - Click "Finish" to invoke `navigator.credentials.get(...)` and
     submit the assertion.
   - On success the session panel (Step 5) appears with the new JWT.

5. **Step 5 — Session inspection**:
   - "List active sessions" shows every session this caller can see.
   - "Revoke current session" deletes the JWT's session row;
     subsequent calls return 401.
   - "Sign out" clears local demo state without touching the VTA.

6. **Step 6 — Trust-task dispatch**:
   - Pick a URI from the dropdown (e.g. `discovery/capabilities/1.0`).
   - Edit the payload textarea for URIs that take parameters
     (e.g. `keys/get/1.0` needs `{"key_id": "..."}`).
   - Click "Send"; the response payload is printed.

7. **Step 7 — DIDComm primitives smoke-test**:
   - Paste any DID into "Recipient DID". `did:key:z…` resolves
     offline; `did:webvh:…` fetches its `did.jsonl` over HTTPS.
   - "Resolve DID" runs the resolver and shows the resolved DID
     document + metadata.
   - "Resolve + pack" additionally:
     - finds the recipient's first `keyAgreement` X25519 key,
     - generates an ephemeral X25519 sender keypair,
     - packs the textarea body as a DIDComm v2 authcrypt JWE
       (ECDH-1PU + A256CBC-HS512),
     - prints the JWE — but does NOT deliver it. This is a
       library smoke-test, not a transport.
   - The bundled crypto stack is at `./vendor/vti-didcomm-js.js`
     (100 KB minified, loaded lazily on first click).

## What the multikey computation does

WebAuthn enrolment is a multi-step ceremony, and the VTA's submit
endpoint requires `publicKeyMultibase` to match what the server
re-derives from the attestation. The demo computes it from the
attestation's SPKI bytes (via `getPublicKey()`):

1. Take the SPKI-encoded public key (DER).
2. Extract the trailing 65-byte uncompressed P-256 point
   (`04 || X[32] || Y[32]`).
3. Compress to 33 bytes (`02|03 || X`) based on Y's parity.
4. Prefix with multicodec varint `0x80 0x24` (p256-pub = 0x1200).
5. Base58btc-encode with a `z` multibase prefix.

This only works for ES256 (P-256, COSE algorithm -7). Modern platform
authenticators (Touch ID, Face ID, Windows Hello) all default to
ES256; if you have an authenticator that returns Ed25519 or RSA, the
enrol path errors out and you'll need to extend `p256AttestationToMultikey`.

## Source layout

```
examples/vta-auth-demo/
├── index.html                       UI structure (seven numbered sections)
├── app.js                           Flow logic + multikey computation (vanilla ES modules)
├── styles.css                       Minimal dark-theme styling
├── vendor/vti-didcomm-js.js         Bundled DIDComm v2 stack used by Step 7
└── README.md                        This file
```

To regenerate `vendor/vti-didcomm-js.js` after editing the JS library:

```sh
cd vti-didcomm-js
npm run build:demo
```

This runs `esbuild` to produce a minified ESM bundle (currently ~100 KB)
including `didwebvh-ts` and `@noble/curves`. The bundle is checked in so
the demo stays zero-build at runtime.

## Related crates

- **vti-webauthn** — the server-side verifier the passkey-login
  finish endpoint calls into. Server-side counterpart to the
  WebAuthn assertion the demo's Finish step sends.
- **vta-sdk** — the Rust client library. Programmatic equivalents of
  the trust-task dispatch flow (`VtaClient::post_trust_task`).
- **vta-service::routes::auth** — the route handlers behind every
  `/auth/*` endpoint.
- **vta-service::routes::passkey_vms** — the routes Step 3 hits.
- **vta-service::routes::trust_tasks** — the dispatcher behind
  `POST /api/trust-tasks` that fans out to per-slice handlers.

## Known limitations

- **ES256 only** for enrolment. Other COSE algorithms surface as a
  clear error in Step 3.
- **Legacy challenge/auth & refresh** are DIDComm-message-based and
  not callable from a browser without a DIDComm pack/unpack stack.
  Out of scope for this demo. Use `pnm auth` or the SDK.
- **No persistence**: the demo holds the JWT in memory. Reloading
  the page loses the session — you'll need to re-bootstrap or
  re-login.
- **The login Finish step passes `verificationMethod: ""`** — the
  server matches on `credential_id` to find the right VM. If a
  future passkey-login wire format requires the client to declare
  the VM explicitly, the demo will need updating.
- **Step 7 is a primitive showcase, not a transport.** It packs
  but doesn't deliver. Wiring the JWE to `POST /auth/` (or to a
  mediator's `/inbound`) is follow-on work — see B4 in the
  `vti-didcomm-js` roadmap.
