import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";

import { packAnoncrypt } from "../src/anoncrypt.js";
import { pack } from "../src/pack.js";
import { unpack } from "../src/unpack.js";
import { buildForward, FORWARD_MESSAGE_TYPE } from "../src/forward.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";
import * as jwk from "../src/jwk.js";

const HELPER = pathResolve(
  process.env.CARGO_TARGET_DIR || pathResolve(import.meta.dirname, "..", "..", "target"),
  "debug",
  "didcomm-unpack",
);

function keypairDid() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  return {
    did: `did:key:${mb}`,
    kid: `did:key:${mb}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

test("packAnoncrypt → unpack round-trips (JS only), no sender required", async () => {
  const recip = keypairDid();
  const jweJson = await packAnoncrypt({
    message: { id: "1", type: "https://example.com/t", to: [recip.did], body: { hi: "anon" } },
    recipient: { kid: recip.kid, publicJwk: jwk.publicJwk("X25519", recip.publicKey) },
  });

  // Unpack with NO sender (anoncrypt).
  const out = await unpack(jweJson, {
    kid: recip.kid,
    privateJwk: jwk.privateJwk("X25519", recip.privateKey, recip.publicKey),
  });
  assert.equal(out.message.body.hi, "anon");
  assert.equal(out.authenticated, false);
  assert.equal(out.senderKid, undefined);
});

test("packAnoncrypt protected header has ECDH-ES alg, no skid/apu", async () => {
  const recip = keypairDid();
  const jweJson = await packAnoncrypt({
    message: { id: "1", type: "t", body: {} },
    recipient: { kid: recip.kid, publicJwk: jwk.publicJwk("X25519", recip.publicKey) },
  });
  const jwe = JSON.parse(jweJson);
  const b64u = await import("../src/base64url.js");
  const header = JSON.parse(new TextDecoder().decode(b64u.decode(jwe.protected)));
  assert.equal(header.alg, "ECDH-ES+A256KW");
  assert.equal(header.enc, "A256CBC-HS512");
  assert.equal(header.skid, undefined, "anoncrypt must not leak a sender skid");
  assert.equal(header.apu, undefined, "anoncrypt has no apu");
  assert.ok(header.apv, "apv present");
  assert.equal(header.epk.crv, "X25519");
});

test("packAnoncrypt → Rust unpack (sender_public omitted)", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }
  const recip = keypairDid();
  const jweJson = await packAnoncrypt({
    message: {
      id: "urn:uuid:abc",
      type: "https://didcomm.org/routing/2.0/forward",
      body: { next: "did:example:vta" },
    },
    recipient: { kid: recip.kid, publicJwk: jwk.publicJwk("X25519", recip.publicKey) },
  });
  const out = await runHelper(HELPER, {
    jwe: jweJson,
    recipient_kid: recip.kid,
    recipient_private_x_b64u: bytesToB64u(recip.privateKey),
    // No sender_public — anoncrypt.
  });
  assert.ok(out.ok, `rust unpack failed: ${JSON.stringify(out)}`);
  assert.equal(out.authenticated, false, "anoncrypt is not authenticated");
  assert.equal(out.plaintext.body.next, "did:example:vta");
});

test("anoncrypt forward: buildForward (no from) → packAnoncrypt → Rust unpacks the forward", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }
  const client = generateEphemeralClient();
  const vta = keypairDid();
  const mediator = keypairDid();

  // Inner authcrypt client → VTA.
  const innerJwe = await pack({
    message: { id: "urn:uuid:inner", type: "https://example.com/op", from: client.did, to: [vta.did], body: {} },
    sender: { kid: client.kid, privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey) },
    recipient: { kid: vta.kid, publicJwk: jwk.publicJwk("X25519", vta.publicKey) },
  });

  // Forward with NO sender (anoncrypt shape).
  const forward = buildForward({ next: vta.did, innerJwe });
  assert.equal(forward.from, undefined, "anoncrypt forward carries no from");
  assert.equal(forward.to, undefined);
  assert.equal(forward.type, FORWARD_MESSAGE_TYPE);

  // Anoncrypt the forward to the mediator.
  const forwardJwe = await packAnoncrypt({
    message: forward,
    recipient: { kid: mediator.kid, publicJwk: jwk.publicJwk("X25519", mediator.publicKey) },
  });

  // Mediator unpacks the forward (anoncrypt — no sender key needed).
  const outer = await runHelper(HELPER, {
    jwe: forwardJwe,
    recipient_kid: mediator.kid,
    recipient_private_x_b64u: bytesToB64u(mediator.privateKey),
  });
  assert.ok(outer.ok, `forward unpack failed: ${JSON.stringify(outer)}`);
  assert.equal(outer.authenticated, false);
  assert.equal(outer.plaintext.body.next, vta.did);
  assert.ok(outer.plaintext.attachments[0].data.json.protected, "inner JWE intact");
});

test("buildForward: rejects from-without-mediator (and vice versa)", () => {
  assert.throws(
    () => buildForward({ next: "did:x", from: "did:c", innerJwe: "{}" }),
    /both `from` and `mediatorDid`, or neither/,
  );
  assert.throws(
    () => buildForward({ next: "did:x", mediatorDid: "did:m", innerJwe: "{}" }),
    /both `from` and `mediatorDid`, or neither/,
  );
});

function bytesToB64u(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function runHelper(helperPath, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(helperPath, [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`helper exit ${code}: ${stderr}`));
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error(`helper output not JSON: ${stdout}`));
      }
    });
    child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}
