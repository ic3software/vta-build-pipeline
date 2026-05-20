import { test } from "node:test";
import assert from "node:assert/strict";

import * as ecdh1pu from "../src/ecdh-1pu.js";
import * as x25519 from "../src/x25519.js";

const ALG = "ECDH-1PU+A256KW";

/**
 * Sender derives KEK from (ephemeralPrivate, senderPrivate, recipientPublic).
 * Recipient derives the same KEK from (recipientPrivate, ephemeralPublic, senderPublic).
 *
 * If these don't match for the same JWE, decryption fails server-side.
 * This is the load-bearing invariant the whole authcrypt scheme rests on.
 */
test("sender-derived KEK equals recipient-derived KEK (the core invariant)", async () => {
  const ephem = x25519.generateKeyPair();
  const sender = x25519.generateKeyPair();
  const recipient = x25519.generateKeyPair();

  const apu = new TextEncoder().encode("did:key:zSender#x");
  const apv = new TextEncoder().encode("did:key:zRecipient#x");

  const senderKek = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: sender.privateKey,
    recipientPublic: recipient.publicKey,
    alg: ALG,
    apu,
    apv,
  });
  const recipientKek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: recipient.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: ALG,
    apu,
    apv,
  });

  assert.deepEqual(senderKek, recipientKek);
  assert.equal(senderKek.length, 32);
});

test("changing apu/apv breaks KEK agreement", async () => {
  const ephem = x25519.generateKeyPair();
  const sender = x25519.generateKeyPair();
  const recipient = x25519.generateKeyPair();
  const apu = new TextEncoder().encode("did:key:zSender#x");

  const k1 = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: sender.privateKey,
    recipientPublic: recipient.publicKey,
    alg: ALG,
    apu,
    apv: new TextEncoder().encode("did:key:zAlice#x"),
  });
  const k2 = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: recipient.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: ALG,
    apu,
    apv: new TextEncoder().encode("did:key:zBob#x"),
  });
  assert.notDeepEqual(k1, k2);
});

test("a third-party keypair can't reproduce the KEK", async () => {
  // Eve has her own X25519 keypair. Given the ephemeral public key
  // + sender public key from the wire, she can compute Ze' via her
  // own private key — but not Zs (that requires the actual
  // recipient's private key). So her derived KEK must differ from
  // the legitimate recipient's.
  const ephem = x25519.generateKeyPair();
  const sender = x25519.generateKeyPair();
  const recipient = x25519.generateKeyPair();
  const eve = x25519.generateKeyPair();
  const apu = new TextEncoder().encode("did:key:zSender#x");
  const apv = new TextEncoder().encode("did:key:zRecipient#x");

  const recipientKek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: recipient.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: ALG,
    apu,
    apv,
  });
  const eveKek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: eve.privateKey,
    ephemeralPublic: ephem.publicKey,
    senderPublic: sender.publicKey,
    alg: ALG,
    apu,
    apv,
  });
  assert.notDeepEqual(recipientKek, eveKek);
});
