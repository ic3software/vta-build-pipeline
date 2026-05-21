# DIDComm v2 JS implementation — design note

**Status**: **implemented and proven live (2026-05-21).** B1–B5 plus
the mediator transport (M1–M4) have shipped as `vti-didcomm-js`, and
both the REST auth path and the full browser → mediator → VTA →
mediator → browser round-trip are validated against live infra
(`glenn.storm.ws`, `webvh.storm.ws`, `mediator.vtc.storm.ws`). The
sections below from "Why hand-rolled" onward are the original **B0
design plan**, kept for context; where the as-built result deviates
from the plan, the **As-built** section immediately below is
authoritative.

## As-built (authoritative — supersedes the B0 plan where they differ)

The plan was sound; a handful of details changed once we hit the real
Rust crate and the real mediator. The deviations that matter:

1. **Content encryption is A256CBC-HS512, not A256GCM.** The pinned
   `affinidi-messaging-didcomm` 0.13 decrypts **A256CBC-HS512 only**
   (it hardcodes a 16-byte IV + 32-byte tag and doesn't read `enc`).
   A256GCM JWEs simply don't round-trip with it. So `pack`/`unpack`
   use **ECDH-1PU+A256KW + A256CBC-HS512** (authcrypt), and
   ECDH-1PU's key-wrap mode folds the content-encryption tag into the
   Concat KDF as SuppPrivInfo (draft-madden §2.3) — meaning pack must
   encrypt *before* deriving the KEK. Every "A256GCM" / "12-byte IV"
   reference in the B0 sections below should read A256CBC-HS512 /
   16-byte IV / 64-byte CEK.

2. **DID resolution**: `did:key` is in-tree (Ed25519/X25519/P-256,
   incl. the Edwards→Montgomery derivation for the Ed25519
   keyAgreement key); `did:webvh` is delegated to DIF's
   **`didwebvh-ts`** (full hash-chain + Data-Integrity verification)
   rather than a hand-rolled `did.jsonl` parser. **`did:peer` was not
   implemented** — our mediator is a `did:webvh`, so numalgo-2 wasn't
   needed.

3. **Two transports, not one.** B4 became the **VTA REST** path
   (challenge → DIDComm-packed `/auth/` → JWT, + refresh with RFC 6749
   §10.4 rotation). The **mediator** path (forward routing + WS live
   delivery) landed separately as M1–M4. Pick REST when the VTA is on
   HTTPS; pick mediator when it isn't.

4. **Round-trip harness is a standalone Rust crate, not a vta-service
   test endpoint.** `vti-didcomm-roundtrip-helper` (`publish = false`)
   is a tiny bin that reads a JWE from stdin and shells it through
   `affinidi-messaging-didcomm`'s `unpack`. JS tests spawn it. This
   avoided adding a security-sensitive test route to vta-service
   (open question #6 is moot).

5. **`return_route: all` IS used** (B0 deferred it). It's how the
   mediator knows to push live-delivery responses back over the same
   WebSocket (message-pickup 3.0).

6. **Mediator WS auth: subprotocol bearer + a mandatory second
   subprotocol.** Browsers can't set an `Authorization` header on a
   WebSocket, so the mediator accepts the JWT as a
   `Sec-WebSocket-Protocol: bearer.<jwt>` entry. **Gotcha:** if only
   that entry is offered, the mediator selects no subprotocol and a
   spec-strict client (every browser + Node undici) rejects the 101
   with code 1006. The client therefore offers a second, separator-
   free entry (`didcomm`) for the mediator to echo back. `didcomm/v2`
   can't be used — `/` is not a valid RFC 6455 subprotocol token char.

7. **As-built module layout** (under `vti-didcomm-js/src/`):
   `base64url.js`, `multibase.js`, `jwk.js`, `concat-kdf.js`,
   `x25519.js`, `ecdh-1pu.js`, `aes.js`, `a256cbc-hs512.js`,
   `pack.js`, `unpack.js`, `did-key.js`, `did-webvh.js`,
   `resolver.js`, `vta-rest-auth.js`, `forward.js`, `mediator-auth.js`,
   `mediator-transport.js`, `vta-didcomm.js`, `index.js`.

**Tests**: 135 passing (`npm test`), incl. RFC 7518 §B.3 (A256CBC-HS512)
and RFC 7518 §C (Concat KDF) known-answer vectors, did:webvh against
real `didwebvh-rs` fixtures, and cross-implementation round-trips
through the Rust unpack helper.

**Consumers**: `examples/vta-auth-demo` (9 sections; 7=primitives,
8=REST auth+refresh, 9=mediator). Integration into the
`pnm-browser-plugin` (`@pnm/core`) is in progress — it replaces the
earlier `@pnm/didcomm-wasm` approach.

---

## Why hand-rolled, not the Rust crate compiled to WASM (B0 plan)

`affinidi-messaging-didcomm` v0.13.2 has dependency-tree blockers:

- `aws-lc-rs` — no WASM target. Maintained for native FIPS use; the
  upstream issue tracker has no WASM-port roadmap.
- `affinidi_secrets_resolver` — OS keychain / AWS Secrets Manager /
  file backends. WASM-incompatible by design (browser has no OS
  keychain to wrap).
- `tokio` runtime baked into the pack/unpack codepaths. Browsers
  use `wasm-bindgen-futures`, not tokio.
- Several transitive `getrandom` versions in disagreement about the
  `js` feature.

Getting it to WASM cleanly is a multi-week fork-and-maintain
exercise that leaves us downstream of upstream. A focused JS
implementation that covers our subset is smaller, auditable, and
doesn't fork.

## Subset we implement (and what we don't)

| Feature | Status | Rationale |
|---|---|---|
| Authcrypt pack (ECDH-1PU + A256GCM) | ✅ ship | Required to send authenticated messages to the VTA |
| Authcrypt unpack | ✅ ship | Required to receive authenticated responses |
| Anoncrypt pack/unpack | ❌ skip | We always have a sender identity; anoncrypt is for anonymous senders, which doesn't apply to our flows |
| Plaintext mode | ❌ skip | Trivial to add later; not needed for auth flows |
| Signed mode (JWS-only, no encryption) | ❌ skip | Not used in our auth flows |
| X25519-HKDF-SHA256 key agreement | ✅ ship | The only KEM we use |
| P-256 key agreement | ❌ skip | All our DIDs use Ed25519/X25519. Future addition if needed for other parties' DIDs. |
| A256GCM content encryption | ✅ ship | Web Crypto native |
| XC20P (XChaCha20-Poly1305) | ❌ skip | Not in Web Crypto; would need JS impl. AES-GCM is everywhere. |
| Ed25519 signatures | ✅ ship | Required for `from` field verification |
| Multi-recipient JWE | ❌ skip | One sender, one recipient in our flows |
| Forward routing (mediator wrap) | ✅ ship | Required since the VTA receives via mediator |
| Message pickup | ✅ ship | Required to receive responses from the plugin's own mediator |
| Return-route protocol | ❌ skip v1 | Optimization, not required |
| Attachments | ❌ skip | Not used in auth flows |
| BBS+ signatures, threading, ack | ❌ skip | Out of scope |
| `did:key` resolution | ✅ ship | Easy literal decode from multibase |
| `did:webvh` resolution | ✅ ship | HTTP fetch + parse `did.jsonl`, take latest LogEntry |
| `did:peer` resolution | ✅ ship (numalgo 2) | Mediator DIDs use this |
| `did:web` resolution | ❌ skip v1 | Add if needed |

## The crypto stack

Where the primitive exists in Web Crypto, use it (audited, in-tree).
Where it doesn't, use `@noble/curves` (tiny, audited, no native code).

| Primitive | Source |
|---|---|
| AES-256-GCM | Web Crypto (`AES-GCM`) |
| HKDF-SHA256 | Web Crypto (`HKDF`) |
| SHA-256 | Web Crypto (`digest`) |
| X25519 ECDH | Web Crypto (Chrome 132+, Firefox 130+, Safari 17.4+) with `@noble/curves/ed25519`'s `x25519` namespace as fallback |
| Ed25519 sign/verify | Web Crypto (Chrome 113+, Safari 17+, Firefox 119+) with `@noble/curves/ed25519` as fallback |
| Concat KDF (NIST SP 800-56A §5.8.1) | Hand-rolled on top of Web Crypto SHA-256 (~30 LOC; well-defined and easy to test against the DIDComm v2 spec test vectors) |
| Base64URL encode/decode | Hand-rolled (no external dep needed) |
| Base58btc | Hand-rolled (already in `examples/vta-auth-demo/app.js` — extract to shared) |

**No hand-rolled symmetric crypto. No hand-rolled curve math.** Only
the protocol-level orchestration (Concat KDF inputs, JWE assembly,
header canonicalization).

## File layout

New workspace member: `vti-didcomm-js/` at the workspace root.

```
vti-didcomm-js/
├── package.json          # ESM-only, type: module
├── README.md             # Subset declaration + usage examples
├── src/
│   ├── index.js          # Public API: pack, unpack, MediatorClient
│   ├── pack.js           # Authcrypt JWE assembly
│   ├── unpack.js         # Authcrypt JWE disassembly
│   ├── concat-kdf.js     # NIST SP 800-56A Concat KDF
│   ├── ecdh-1pu.js       # One-Pass Unified ECDH
│   ├── jwe.js            # JWE structure + canonical-header
│   ├── jwk.js            # JWK ↔ raw bytes
│   ├── did-resolver.js   # did:key / did:webvh / did:peer-numalgo-2
│   ├── mediator.js       # WebSocket client + pickup
│   ├── multibase.js      # Base58btc + multicodec varints
│   └── base64url.js      # Encode/decode
├── test/
│   ├── round-trip.test.js          # Encrypt with this, decrypt with Rust crate (via vta-service test endpoint)
│   ├── spec-vectors.test.js        # DIDComm v2 spec test vectors
│   ├── concat-kdf.test.js          # NIST Concat KDF vectors
│   └── jwe-shape.test.js           # JWE protected-header round-trip
└── examples/
    └── auth-roundtrip.js           # Programmatic example called from CI
```

ESM, no transpiler, no bundler in the source tree. Browser-ready as
relative-import modules. Consumers (demo, plugin) import via
`../../vti-didcomm-js/src/index.js` or as an npm workspace.

## Round-trip-against-Rust test harness

The hard part of a DIDComm v2 implementation is that any detail of
the spec is a silent failure surface. The Rust crate already
unpacks-correctly-or-not against the Sicpa Rust reference vectors;
if our JS pack is accepted by the Rust unpack, we're spec-correct.

Plan:

1. Add a test-only route to `vta-service` (`#[cfg(test)]` or a
   `test-support` feature) at `POST /test/didcomm/unpack` that takes
   a packed JWE and the recipient's private JWK, calls
   `affinidi-messaging-didcomm::Message::unpack`, and returns the
   plaintext + the sender's verified DID.

2. The JS test harness:
   - Generates an ephemeral X25519 keypair (sender)
   - Generates a recipient X25519 keypair
   - Packs a message via `pack()`
   - POSTs to the test endpoint with the packed JWE + recipient JWK
   - Asserts the round-tripped plaintext matches what we packed
   - Asserts the recovered sender DID matches what we declared

3. CI runs the harness against a freshly-built vta-service binary
   (we already do this for other Rust-side tests).

This pins every detail — Concat KDF inputs, APU/APV hashes, JWE
header canonicalization, base64url variants — by reference to a
known-correct implementation.

## Wire shape we produce (authcrypt JWE)

```json
{
  "protected": "<base64url(JSON({\n  \"typ\": \"application/didcomm-encrypted+json\",\n  \"alg\": \"ECDH-1PU+A256KW\",\n  \"enc\": \"A256GCM\",\n  \"apu\": \"<base64url(sender_did:key_id)>\",\n  \"apv\": \"<base64url(sha256(recipient_kids))>\",\n  \"skid\": \"<sender did:key_id>\",\n  \"epk\": { \"kty\": \"OKP\", \"crv\": \"X25519\", \"x\": \"<base64url>\" }\n}))>",
  "recipients": [
    {
      "header": { "kid": "<recipient_did:key_id>" },
      "encrypted_key": "<base64url(A256KW(CEK, KEK))>"
    }
  ],
  "iv": "<base64url(12 random bytes)>",
  "ciphertext": "<base64url(AES-256-GCM(plaintext, key=CEK, iv=iv, aad=protected))>",
  "tag": "<base64url(GCM tag)>"
}
```

Where:

- **CEK** is a randomly-generated 256-bit content encryption key
- **KEK** is derived via:
  1. `ze = ECDH(epk_priv, recipient_pub)`  ephemeral-to-recipient
  2. `zs = ECDH(sender_priv, recipient_pub)`  static-to-recipient
  3. `z = ze || zs`
  4. `KEK = ConcatKDF(z, alg="ECDH-1PU+A256KW", apu, apv, keyDataLen=256)`
- **encrypted_key** is `AES-256-KW(KEK, CEK)` (AES Key Wrap, RFC 3394)
- **AAD** is the canonical ASCII-encoded `protected` header string
  (the base64url, NOT the JSON)

Spec reference: DIDComm v2 §5.1 + §5.2; JWE per RFC 7516; ECDH-1PU
per draft-madden-jose-ecdh-1pu.

## API surface

Public functions exported from `index.js`:

```js
/**
 * Pack a plaintext DIDComm message as an authcrypt JWE.
 *
 * @param {Object} args
 * @param {Object} args.message - Plaintext DIDComm v2 message
 *   ({ id, type, from, to, body, ... }).
 * @param {Object} args.sender - Sender identity:
 *   { did, keyId, privateJwk }.
 * @param {Object} args.recipient - Recipient identity:
 *   { did, keyId, publicJwk }.
 * @param {boolean} [args.forwardWrap=false] - If true and the
 *   recipient DID resolves to a mediator service, wrap in a
 *   `https://didcomm.org/routing/2.0/forward` message addressed
 *   to the mediator.
 * @returns {Promise<string>} The packed JWE as a JSON string.
 */
export async function pack(args);

/**
 * Unpack an authcrypt JWE.
 *
 * @param {string} packed - JWE JSON string.
 * @param {Object} recipient - { did, keyId, privateJwk }.
 * @returns {Promise<{ message: Object, senderDid: string }>}
 */
export async function unpack(packed, recipient);

/**
 * Connect to a mediator via WebSocket. Handles pickup, ack, and
 * inbound message delivery.
 */
export class MediatorClient {
  constructor({ mediatorDid, ourDid, ourKey, didResolver });
  async connect();
  async send(packedJwe);
  onMessage(callback);  // callback(plaintext, senderDid)
  async disconnect();
}

/**
 * Resolve a DID to its document (subset: just enough to extract
 * keyAgreement keys + service endpoints).
 */
export async function resolveDid(did);
```

## Implementation phases (each a separate commit/session)

### B1 — Crypto primitives + spec vectors

- `concat-kdf.js`, `jwe.js`, `jwk.js`, `base64url.js`, `multibase.js`
- Spec test vectors from DIDComm v2 (Sicpa repo's test corpus)
- Concat KDF test vectors from NIST SP 800-56A
- No protocol code yet; just the math.

**Acceptance**: Concat KDF against NIST vectors. JWK ↔ raw round-trip.
Multibase encode/decode against known values.

### B2 — Pack/unpack + round-trip harness

- `ecdh-1pu.js`, `pack.js`, `unpack.js`
- `vta-service` test endpoint `POST /test/didcomm/unpack`
  (`test-support` feature only).
- Round-trip test: JS pack → Rust unpack → assertion.

**Acceptance**: Round-trip of a `{ type: "test", body: { hello: "world" } }`
message succeeds. Sender DID recovers correctly.

### B3 — DID resolution

- `did-resolver.js` covering `did:key`, `did:webvh`, `did:peer`
  (numalgo 2 only).
- Tests against known VTA + mediator DIDs.

**Acceptance**: Resolves a fresh `did:webvh:…` from a live VTA and
extracts its keyAgreement key + service endpoint.

### B4 — Mediator transport

- `mediator.js` WebSocket client.
- Pickup protocol (DIDComm v2 messagepickup 3.0).
- Forward routing wrap on pack.

**Acceptance**: JS plugin connects to ATM mediator, registers,
receives + sends test messages.

### B5 — Demo integration

- Update `examples/vta-auth-demo/` with a "DIDComm" tab that
  exercises the auth-via-DIDComm path alongside REST.
- Side-by-side comparison in the demo so operators can see both
  surfaces work against the same VTA.

**Acceptance**: Demo's DIDComm tab successfully authenticates
against `https://glenn.storm.ws` running with WebAuthn enabled.

### B6 — Plugin scaffold (separate workstream)

Out of scope for this design note. Once B1-B5 are done, the plugin
imports `vti-didcomm-js` and adds Chrome extension boilerplate.

## Estimated effort

| Phase | LOC | Time |
|---|---|---|
| B1 | ~400 | One session |
| B2 | ~600 | One session (the round-trip harness is the bulk) |
| B3 | ~250 | Half a session |
| B4 | ~400 | One session |
| B5 | ~200 | Half a session |
| **Total to operator-visible demo** | **~1850** | **~3-4 focused sessions** |

This is significantly less than forking `affinidi-messaging-didcomm`
to WASM (estimated 6-8 sessions including upstream tracking) and
the result is something we own entirely.

## Open questions for sign-off

Before B1 starts, get explicit ack on:

1. **Algorithms locked** — ECDH-1PU + X25519 + A256GCM + Ed25519 only.
   Future additions land as additive variants, not as silent
   negotiation.

2. **No anoncrypt in v1** — every message has a sender identity.
   Confirms we don't need ECDH-ES for any of our flows.

3. **Web Crypto baseline browsers** — Chrome 132 / Safari 17.4 /
   Firefox 130 for native X25519 support. Older browsers fall back
   to `@noble/curves`. Confirm this is acceptable, or pin to all
   browsers via `@noble/curves` exclusively (slightly larger
   bundle, no Web Crypto fast path).

4. **Mediator wire format** — Affinidi ATM uses DIDComm v2
   routing/2.0 + messagepickup/3.0. Confirm we're targeting ATM
   compatibility specifically, not e.g. Hyperledger mediator.

5. **Workspace location** — `vti-didcomm-js/` at workspace root
   (peer of `vti-webauthn/`, `vta-sdk/`, etc.). The "vti-" prefix
   matches our common-crate naming convention even though this is
   a JS package, not Rust. Alternative: `examples/didcomm-js/` if
   we want to emphasize it's a demo aid rather than production
   tooling.

6. **Test endpoint feature gate** — `POST /test/didcomm/unpack` is
   a security-sensitive surface (lets anyone unpack a JWE they
   couldn't decrypt themselves... wait, no — they have to supply
   the private JWK, so it's just a server-side validation oracle).
   Behind a `test-support` feature flag in vta-service, never
   compiled into release binaries. Confirm.

Once 1-6 are signed off, B1 can start immediately.

## What this design deliberately defers

- **Plugin manifest / Chrome extension boilerplate**: separate
  workstream, not part of B1-B5.
- **Native messaging fallback** for browsers without Web Crypto
  Ed25519/X25519: defer until a real user hits it.
- **DIDComm protocol-level features beyond pack/unpack/forward**:
  return-route, ack, threading, attachments. Add as needed.
- **Anoncrypt and signed-mode pack**: not required for our flows.
- **Multi-recipient JWEs**: not required for our flows.
- **Other DID methods (did:web, did:ion, did:ethr…)**: not required.

If a deferred item turns out to be needed later, it's purely
additive — none of the v1 wire shape changes.
