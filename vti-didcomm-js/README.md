# vti-didcomm-js

Browser-side DIDComm v2 implementation for the Verifiable Trust
Infrastructure workspace.

**Status**: Phase B1. Crypto primitives only — base64url, multibase,
JWK shapes, Concat KDF. Pack / unpack / DID resolver / mediator
transport land in B2–B5. See
[`docs/05-design-notes/didcomm-js-implementation.md`](../docs/05-design-notes/didcomm-js-implementation.md)
for the full design.

## Subset

This implementation deliberately covers only what the workspace's
auth flows need:

- **Authcrypt** (ECDH-1PU + X25519 + A256GCM + Ed25519). No
  anoncrypt, no signed-only mode.
- **Single recipient** per JWE.
- **Forward routing** for mediator-wrapped sends.
- **DID resolution** for `did:key`, `did:webvh`, `did:peer` (numalgo 2).

Things NOT supported (and unlikely to be added unless a real flow
needs them): anoncrypt, ChaCha20-Poly1305, P-256 ECDH, multi-recipient,
attachments, BBS+, return-route, threading.

## Running tests

```sh
cd vti-didcomm-js
node --test test/
```

Node 20+ required (uses the built-in test runner). No dependencies in B1.

## File layout

```
src/
  base64url.js   RFC 4648 §5 encode/decode (no padding)
  multibase.js   Base58btc + multicodec varints (Ed25519, X25519, P-256)
  jwk.js         OKP JWK ↔ raw byte conversions (X25519, Ed25519)
  concat-kdf.js  NIST SP 800-56A Concat KDF (JOSE OtherInfo flavor)
  index.js       Re-exports for the public API
test/
  base64url.test.js   RFC 4648 test vectors + round-trip
  multibase.test.js   Multibase spec vectors + known did:key
  jwk.test.js         Shape + round-trip
  concat-kdf.test.js  RFC 7518 Appendix C ECDH-ES vector + invariants
```

## What lands next

- **B2** — `ecdh-1pu.js`, `pack.js`, `unpack.js`. Round-trip harness
  against `affinidi-messaging-didcomm` via a `test-support`-gated
  endpoint in vta-service.
- **B3** — DID resolution.
- **B4** — Mediator WebSocket transport.
- **B5** — Wire into `examples/vta-auth-demo/`.
