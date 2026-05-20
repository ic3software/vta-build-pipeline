import { test } from "node:test";
import assert from "node:assert/strict";

import * as b64u from "../src/base64url.js";
import * as jwk from "../src/jwk.js";

const x = new Uint8Array(32);
for (let i = 0; i < 32; i++) x[i] = i;
const d = new Uint8Array(32);
for (let i = 0; i < 32; i++) d[i] = 31 - i;

test("publicJwk shape is OKP/{crv} with base64url x", () => {
  const out = jwk.publicJwk("X25519", x, "did:key:zA#x");
  assert.equal(out.kty, "OKP");
  assert.equal(out.crv, "X25519");
  assert.equal(out.kid, "did:key:zA#x");
  assert.equal(out.x, b64u.encode(x));
  assert.ok(!("d" in out));
});

test("privateJwk includes 'd'", () => {
  const out = jwk.privateJwk("Ed25519", d, x);
  assert.equal(out.kty, "OKP");
  assert.equal(out.crv, "Ed25519");
  assert.equal(out.d, b64u.encode(d));
});

test("rawPublic round-trip", () => {
  const j = jwk.publicJwk("X25519", x);
  assert.deepEqual(jwk.rawPublic(j), x);
});

test("rawPrivate round-trip", () => {
  const j = jwk.privateJwk("X25519", d, x);
  assert.deepEqual(jwk.rawPrivate(j), d);
});

test("rawPrivate rejects public-only JWK", () => {
  const j = jwk.publicJwk("X25519", x);
  assert.throws(() => jwk.rawPrivate(j), /no 'd'/);
});

test("toPublic strips 'd'", () => {
  const priv = jwk.privateJwk("X25519", d, x, "did:webvh:foo#k");
  const pub = jwk.toPublic(priv);
  assert.equal(pub.kty, "OKP");
  assert.equal(pub.kid, "did:webvh:foo#k");
  assert.ok(!("d" in pub));
});

test("publicJwk rejects unsupported curve", () => {
  assert.throws(() => jwk.publicJwk("Ed448", x), /unsupported OKP curve/);
});

test("publicJwk rejects wrong-length input", () => {
  assert.throws(() => jwk.publicJwk("X25519", new Uint8Array(31), undefined), /must be 32 bytes/);
});

test("rawPublic rejects non-OKP kty", () => {
  assert.throws(
    () => jwk.rawPublic({ kty: "EC", crv: "P-256", x: "AAAA" }),
    /kty must be 'OKP'/,
  );
});
