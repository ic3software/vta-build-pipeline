// Pack → unpack round-trip is the integration test that catches
// any divergence between the two sides of our authcrypt
// implementation. Every layer is exercised: X25519 key exchange,
// Concat KDF, AES-KW, AES-GCM, JWE structure, base64url encoding.
//
// A future "round-trip against the Rust crate" test (B2 follow-up
// once we wire the vta-service test endpoint) replaces our unpack
// with `affinidi-messaging-didcomm`'s — same shape, different
// side. If THAT passes, the JS pack matches the spec
// byte-for-byte.

import { test } from "node:test";
import assert from "node:assert/strict";

import { pack } from "../src/pack.js";
import { unpack } from "../src/unpack.js";
import * as jwk from "../src/jwk.js";
import * as x25519 from "../src/x25519.js";

function makeParty(kid) {
  const { privateKey, publicKey } = x25519.generateKeyPair();
  return {
    kid,
    privateJwk: jwk.privateJwk("X25519", privateKey, publicKey, kid),
    publicJwk: jwk.publicJwk("X25519", publicKey, kid),
  };
}

test("pack → unpack round-trips a simple message", async () => {
  const sender = makeParty("did:key:zSenderAlice#x25519-1");
  const recipient = makeParty("did:key:zRecipientBob#x25519-1");

  const message = {
    id: "msg-1",
    type: "https://example.com/test/1.0",
    from: sender.kid.split("#")[0],
    to: [recipient.kid.split("#")[0]],
    body: { hello: "didcomm" },
    created_time: 1700000000,
  };

  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  // Quick wire-shape sanity check before unpacking.
  const parsed = JSON.parse(jwe);
  assert.ok(parsed.protected, "JWE has protected");
  assert.ok(Array.isArray(parsed.recipients), "JWE has recipients[]");
  assert.equal(parsed.recipients.length, 1);
  assert.equal(parsed.recipients[0].header.kid, recipient.kid);
  assert.ok(parsed.iv, "JWE has iv");
  assert.ok(parsed.ciphertext, "JWE has ciphertext");
  assert.ok(parsed.tag, "JWE has tag");

  // Unpack on the recipient side.
  const { message: out, senderKid } = await unpack(
    jwe,
    { kid: recipient.kid, privateJwk: recipient.privateJwk },
    { publicJwk: sender.publicJwk },
  );
  assert.deepEqual(out, message);
  assert.equal(senderKid, sender.kid);
});

test("pack output is non-deterministic (ephemeral keypair + IV)", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const message = { id: "m", type: "x", body: {} };
  const args = {
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  };
  const a = await pack(args);
  const b = await pack(args);
  assert.notEqual(a, b, "two packs of the same message must differ (fresh ephemeral + IV)");
});

test("unpack with wrong recipient key throws", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const eve = makeParty("did:key:zEve#x");
  const message = { id: "m", type: "x", body: { secret: "shh" } };

  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  // Eve has the JWE + the sender's public key (it's on the wire
  // anyway via `skid`) — but doesn't have the recipient's private
  // key. The kid mismatch is caught up front; even if we relabel,
  // the unwrap fails because Eve's private key produces the wrong KEK.
  await assert.rejects(
    unpack(
      jwe,
      { kid: recipient.kid, privateJwk: eve.privateJwk },
      { publicJwk: sender.publicJwk },
    ),
  );
});

test("unpack with wrong sender public key throws (auth check)", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const otherSender = makeParty("did:key:zOther#x");
  const message = { id: "m", type: "x", body: {} };

  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  // Recipient resolved skid → otherSender.publicJwk (wrong). KEK
  // mismatch → unwrap fails. This is the authcrypt "sender
  // authenticated" check operating end-to-end.
  await assert.rejects(
    unpack(
      jwe,
      { kid: recipient.kid, privateJwk: recipient.privateJwk },
      { publicJwk: otherSender.publicJwk },
    ),
  );
});

test("unpack with tampered ciphertext throws", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const message = { id: "m", type: "x", body: {} };
  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  // Flip one byte in the ciphertext.
  const parsed = JSON.parse(jwe);
  const ct = parsed.ciphertext;
  // base64url chars '-' and '_' are valid; flip a letter for sanity.
  const flipped = ct[0] === "A" ? "B" + ct.slice(1) : "A" + ct.slice(1);
  parsed.ciphertext = flipped;
  const tampered = JSON.stringify(parsed);

  await assert.rejects(
    unpack(
      tampered,
      { kid: recipient.kid, privateJwk: recipient.privateJwk },
      { publicJwk: sender.publicJwk },
    ),
  );
});

test("unpack with mismatched recipient kid throws", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const message = { id: "m", type: "x", body: {} };
  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });

  // Recipient looks for a different kid in recipients[].
  await assert.rejects(
    unpack(
      jwe,
      {
        kid: "did:key:zSomeoneElse#x",
        privateJwk: recipient.privateJwk,
      },
      { publicJwk: sender.publicJwk },
    ),
    /no recipients\[\] entry/,
  );
});

test("unpack rejects unsupported alg", async () => {
  const recipient = makeParty("did:key:zRecipient#x");
  const sender = makeParty("did:key:zSender#x");
  // Build a JWE with the wrong alg in protected.
  const protectedHeader = {
    typ: "application/didcomm-encrypted+json",
    alg: "ECDH-ES+A256KW", // ANONcrypt, not what we support
    enc: "A256GCM",
    apu: "",
    apv: "",
    skid: sender.kid,
    epk: { kty: "OKP", crv: "X25519", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
  };
  const protectedB64 = Buffer.from(JSON.stringify(protectedHeader)).toString("base64url");
  const jwe = JSON.stringify({
    protected: protectedB64,
    recipients: [{ header: { kid: recipient.kid }, encrypted_key: "AA" }],
    iv: "AAAAAAAAAAAAAAAA",
    ciphertext: "AA",
    tag: "AAAAAAAAAAAAAAAAAAAAAA",
  });
  await assert.rejects(
    unpack(
      jwe,
      { kid: recipient.kid, privateJwk: recipient.privateJwk },
      { publicJwk: sender.publicJwk },
    ),
    /unsupported alg/,
  );
});

test("pack handles realistic-size message (1 KB body)", async () => {
  const sender = makeParty("did:key:zSender#x");
  const recipient = makeParty("did:key:zRecipient#x");
  const body = { data: "x".repeat(1024) };
  const message = { id: "m", type: "x", body };
  const jwe = await pack({
    message,
    sender: { kid: sender.kid, privateJwk: sender.privateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipient.publicJwk },
  });
  const { message: out } = await unpack(
    jwe,
    { kid: recipient.kid, privateJwk: recipient.privateJwk },
    { publicJwk: sender.publicJwk },
  );
  assert.deepEqual(out, message);
});
