import { test } from "node:test";
import assert from "node:assert/strict";

import * as x25519 from "../src/x25519.js";

test("generateKeyPair returns 32-byte private + public", () => {
  const { privateKey, publicKey } = x25519.generateKeyPair();
  assert.equal(privateKey.length, 32);
  assert.equal(publicKey.length, 32);
});

test("publicKeyFrom is deterministic", () => {
  const { privateKey, publicKey } = x25519.generateKeyPair();
  assert.deepEqual(x25519.publicKeyFrom(privateKey), publicKey);
});

test("sharedSecret is symmetric", () => {
  const alice = x25519.generateKeyPair();
  const bob = x25519.generateKeyPair();
  const ab = x25519.sharedSecret(alice.privateKey, bob.publicKey);
  const ba = x25519.sharedSecret(bob.privateKey, alice.publicKey);
  assert.deepEqual(
    ab,
    ba,
    "ECDH must produce identical secrets on both sides",
  );
  assert.equal(ab.length, 32);
});

test("rejects wrong-length inputs", () => {
  assert.throws(
    () => x25519.publicKeyFrom(new Uint8Array(31)),
    /must be 32 bytes/,
  );
  assert.throws(
    () => x25519.sharedSecret(new Uint8Array(32), new Uint8Array(31)),
    /must be 32 bytes/,
  );
});
