import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKekAnoncrypt, recipientKekAnoncrypt } from "../src/ecdh-es.js";
import * as x25519 from "../src/x25519.js";

const ALG = "ECDH-ES+A256KW";
const EMPTY = new Uint8Array();

test("ECDH-ES: sender and recipient derive the same KEK", async () => {
  const ephem = x25519.generateKeyPair();
  const recip = x25519.generateKeyPair();
  const apv = new Uint8Array([1, 2, 3, 4]);

  const senderKek = await deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recip.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });
  const recipientKek = await recipientKekAnoncrypt({
    recipientPrivate: recip.privateKey,
    ephemeralPublic: ephem.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });

  assert.equal(senderKek.length, 32);
  assert.deepEqual(senderKek, recipientKek, "ECDH-ES KEK must agree on both sides");
});

test("ECDH-ES: KEK is deterministic for fixed inputs", async () => {
  const ephem = x25519.generateKeyPair();
  const recip = x25519.generateKeyPair();
  const apv = new Uint8Array([9, 9]);
  const a = await deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recip.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });
  const b = await deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recip.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });
  assert.deepEqual(a, b);
});

test("ECDH-ES: apv changes the KEK", async () => {
  const ephem = x25519.generateKeyPair();
  const recip = x25519.generateKeyPair();
  const k1 = await deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recip.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv: new Uint8Array([1]),
  });
  const k2 = await deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recip.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv: new Uint8Array([2]),
  });
  assert.notDeepEqual(k1, k2);
});

test("ECDH-ES: a third party cannot derive the KEK", async () => {
  const ephem = x25519.generateKeyPair();
  const recip = x25519.generateKeyPair();
  const other = x25519.generateKeyPair();
  const apv = new Uint8Array([7]);
  const real = await recipientKekAnoncrypt({
    recipientPrivate: recip.privateKey,
    ephemeralPublic: ephem.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });
  const impostor = await recipientKekAnoncrypt({
    recipientPrivate: other.privateKey,
    ephemeralPublic: ephem.publicKey,
    alg: ALG,
    apu: EMPTY,
    apv,
  });
  assert.notDeepEqual(real, impostor);
});
