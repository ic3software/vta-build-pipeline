import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";

import { buildForward, FORWARD_MESSAGE_TYPE } from "../src/forward.js";
import { pack } from "../src/pack.js";
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

test("buildForward: shape — type, next, single json attachment", () => {
  const fwd = buildForward({
    next: "did:webvh:scid:host:vta",
    from: "did:key:zClient",
    mediatorDid: "did:webvh:scid:host:mediator",
    innerJwe: '{"protected":"x","recipients":[],"iv":"i","ciphertext":"c","tag":"t"}',
  });
  assert.equal(fwd.type, FORWARD_MESSAGE_TYPE);
  assert.equal(fwd.body.next, "did:webvh:scid:host:vta");
  assert.deepEqual(fwd.to, ["did:webvh:scid:host:mediator"]);
  assert.equal(fwd.from, "did:key:zClient");
  assert.equal(fwd.attachments.length, 1);
  assert.equal(fwd.attachments[0].data.json.protected, "x");
  assert.ok(fwd.id.startsWith("urn:uuid:"));
});

test("buildForward: accepts an inner JWE object as well as a string", () => {
  const obj = { protected: "p", recipients: [], iv: "i", ciphertext: "c", tag: "t" };
  const fwd = buildForward({
    next: "did:x:vta",
    from: "did:x:c",
    mediatorDid: "did:x:m",
    innerJwe: obj,
  });
  assert.deepEqual(fwd.attachments[0].data.json, obj);
});

test("buildForward: rejects malformed inner JWE + missing fields", () => {
  assert.throws(
    () => buildForward({ next: "a", from: "b", mediatorDid: "c", innerJwe: "{not json" }),
    /not valid JSON/,
  );
  assert.throws(
    () => buildForward({ next: "", from: "b", mediatorDid: "c", innerJwe: "{}" }),
    /next must be a non-empty string/,
  );
});

test("forward round-trips: inner→VTA authcrypt wrapped + forward→mediator authcrypt, Rust unpacks the forward", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }

  const client = generateEphemeralClient();
  const vta = keypairDid();
  const mediator = keypairDid();

  // 1. Inner message client → VTA, authcrypt to the VTA.
  const innerMsg = {
    id: `urn:uuid:${crypto.randomUUID()}`,
    typ: "application/didcomm-plain+json",
    type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0",
    from: client.did,
    to: [vta.did],
    body: {},
  };
  const innerJwe = await pack({
    message: innerMsg,
    sender: {
      kid: client.kid,
      privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey),
    },
    recipient: { kid: vta.kid, publicJwk: jwk.publicJwk("X25519", vta.publicKey) },
  });

  // 2. Wrap in forward addressed to the mediator (next = VTA).
  const forward = buildForward({
    next: vta.did,
    from: client.did,
    mediatorDid: mediator.did,
    innerJwe,
  });

  // 3. authcrypt the forward to the mediator.
  const forwardJwe = await pack({
    message: forward,
    sender: {
      kid: client.kid,
      privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey),
    },
    recipient: { kid: mediator.kid, publicJwk: jwk.publicJwk("X25519", mediator.publicKey) },
  });

  // 4. The mediator unpacks the OUTER forward (one layer) with its key.
  const outer = await runHelper(HELPER, {
    jwe: forwardJwe,
    recipient_kid: mediator.kid,
    recipient_private_x_b64u: bytesToB64u(mediator.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(outer.ok, `forward unpack failed: ${JSON.stringify(outer)}`);
  assert.equal(outer.plaintext.type, FORWARD_MESSAGE_TYPE);
  assert.equal(outer.plaintext.body.next, vta.did);

  // 5. The inner JWE is intact in the attachment — the VTA (next hop)
  //    can unpack it with its own key. Confirm by unpacking it.
  const innerFromAttachment = outer.plaintext.attachments[0].data.json;
  const innerStr = JSON.stringify(innerFromAttachment);
  const inner = await runHelper(HELPER, {
    jwe: innerStr,
    recipient_kid: vta.kid,
    recipient_private_x_b64u: bytesToB64u(vta.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(inner.ok, `inner unpack failed: ${JSON.stringify(inner)}`);
  assert.equal(
    inner.plaintext.type,
    "https://trusttasks.org/spec/vta/discovery/capabilities/1.0",
  );
  assert.equal(inner.plaintext.from, client.did);
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
