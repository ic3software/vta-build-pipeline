# vti-didcomm-js

Browser-side DIDComm v2 for the Verifiable Trust Infrastructure — a
focused, dependency-light JavaScript implementation of the subset our
auth flows need. ESM-only, runs in browsers and Node 20+.

Byte-compatible on the wire with [`affinidi-messaging-didcomm`] 0.13
(the same crate the VTA and the ATM mediator use) — every layer is
verified by round-tripping through the Rust crate's `unpack` in CI.

[`affinidi-messaging-didcomm`]: https://crates.io/crates/affinidi-messaging-didcomm

## What it does

- **Authcrypt** pack/unpack — ECDH-1PU + A256KW + **A256CBC-HS512**
  (DIDComm v2's required-to-implement content encryption). Sender-bound.
- **Anoncrypt** pack/unpack — ECDH-ES + A256KW + A256CBC-HS512. No
  sender identity; used for the `routing/2.0/forward` envelope to a
  mediator.
- **DID resolution** — `did:key` (Ed25519/X25519/P-256, in-tree) and
  `did:webvh` (via [`didwebvh-ts`], full hash-chain + Data-Integrity
  verification). Pluggable dispatcher for adding methods.
- **Forward routing** — `https://didcomm.org/routing/2.0/forward`
  wrapping.
- **VTA REST auth** — DIDComm-packed `/auth/` challenge-response + JWT
  refresh (RFC 6749 §10.4 rotation).
- **Mediator transport** — ATM challenge-response auth, browser
  WebSocket with subprotocol-bearer auth, message-pickup 3.0 live
  delivery, and `sendAndWait` request/response correlation.

Crypto comes from Web Crypto where possible (AES-CBC, HMAC, AES-KW,
SHA-256) and [`@noble/curves`] for X25519/Ed25519. No hand-rolled
symmetric crypto or curve math — only protocol-level orchestration.

[`didwebvh-ts`]: https://www.npmjs.com/package/didwebvh-ts
[`@noble/curves`]: https://www.npmjs.com/package/@noble/curves

### Not implemented (additive if a flow needs them)

Multi-recipient JWEs, P-256/secp256k1 ECDH (only X25519 key
agreement), XChaCha20-Poly1305, `did:peer`, signed-only (JWS) mode,
BBS+, attachments beyond the forward envelope.

## Install

```sh
npm install @openvtc/vti-didcomm-js
```

## Usage

```js
import { pack, unpack, packAnoncrypt, resolve } from "@openvtc/vti-didcomm-js";
import * as jwk from "@openvtc/vti-didcomm-js/jwk";

// Resolve a recipient and pack an authcrypt message to its keyAgreement.
const { didDocument } = await resolve("did:webvh:…:vta");
// … extract the keyAgreement X25519 key (see resolveX25519KeyAgreement) …

const jwe = await pack({
  message: { id, type, from: senderDid, to: [recipientDid], body },
  sender:    { kid: senderKid,    privateJwk },
  recipient: { kid: recipientKid, publicJwk  },
});

const { message, senderKid, authenticated } = await unpack(jwe, {
  kid: recipientKid,
  privateJwk: recipientPrivateJwk,
}, { publicJwk: senderPublicJwk });
```

Higher-level helpers:

- `@openvtc/vti-didcomm-js/vta-rest-auth` — `authenticate` / `refresh` against a
  VTA's REST `/auth/` surface.
- `@openvtc/vti-didcomm-js/vta-didcomm` — `connectVtaViaMediator` →
  `client.sendAndWait(type, body)` over a mediator WebSocket.

Each module is also a subpath export (e.g. `@openvtc/vti-didcomm-js/pack`,
`@openvtc/vti-didcomm-js/resolver`, `@openvtc/vti-didcomm-js/mediator-transport`).

## Module map

```
src/
  base64url.js          RFC 4648 §5 (no padding)
  multibase.js          base58btc + multicodec varints
  jwk.js                OKP JWK ↔ raw bytes (X25519, Ed25519)
  concat-kdf.js         NIST SP 800-56A Concat KDF (JOSE OtherInfo)
  x25519.js             X25519 key agreement (@noble/curves)
  ecdh-1pu.js           ECDH-1PU KEK (authcrypt; tag-bound key-wrap)
  ecdh-es.js            ECDH-ES KEK (anoncrypt)
  aes.js                AES-256-KW (RFC 3394)
  a256cbc-hs512.js      AES-256-CBC + HMAC-SHA-512 AEAD (RFC 7518 §5.2)
  pack.js               authcrypt JWE
  anoncrypt.js          anoncrypt JWE
  unpack.js             dual-mode unpack (authcrypt + anoncrypt)
  did-key.js            did:key resolver
  did-webvh.js          did:webvh resolver (via didwebvh-ts)
  resolver.js           method dispatcher
  forward.js            routing/2.0/forward wrapping
  vta-rest-auth.js      VTA /auth/ + refresh
  forward.js, mediator-auth.js, mediator-transport.js, vta-didcomm.js
                        mediator transport (auth, WS live delivery, sendAndWait)
  index.js              public re-exports
```

## Tests

```sh
npm test          # node --test; 140+ tests
```

Includes RFC 7518 §B.3 (A256CBC-HS512) and §C (Concat KDF) known-answer
vectors, did:webvh against real `didwebvh-rs` fixtures, and
cross-implementation round-trips through the Rust `affinidi-messaging-didcomm`
unpack (`vti-didcomm-roundtrip-helper`). Some tests reach live infra /
the Rust helper and skip cleanly when unavailable.

Design + as-built notes:
[`docs/05-design-notes/didcomm-js-implementation.md`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/docs/05-design-notes/didcomm-js-implementation.md).

## License

Apache-2.0
