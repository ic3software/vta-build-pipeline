import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";

import { VtaMediatorClient, resolveX25519KeyAgreement } from "../src/vta-didcomm.js";
import { MediatorSession } from "../src/mediator-transport.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import { pack } from "../src/pack.js";
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

class FakeWebSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.sent = [];
    this.onopen = this.onmessage = this.onerror = this.onclose = null;
    FakeWebSocket.last = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  addEventListener() {}
  send(d) {
    this.sent.push(d);
  }
  close() {
    this.onclose && this.onclose();
  }
  inject(d) {
    this.onmessage && this.onmessage({ data: d });
  }
}

test("VtaMediatorClient.sendAndWait: emits forward, resolves on thid-correlated VTA response", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }

  const client = generateEphemeralClient();
  const vta = keypairDid();
  const mediator = keypairDid();

  // Build a session over a fake socket (skip the live mediator auth).
  const session = new MediatorSession({
    mediator: {
      did: mediator.did,
      kid: mediator.kid,
      x25519Pub: mediator.publicKey,
      wsEndpoint: "wss://mediator.test/ws",
    },
    mediatorJwt: "med.jwt",
    client: {
      did: client.did,
      kid: client.kid,
      privateKey: client.privateKey,
      publicKey: client.publicKey,
    },
    senderKeys: new Map([[vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }]]),
    WebSocketImpl: FakeWebSocket,
  });
  await session.connect();
  const ws = FakeWebSocket.last;
  const sentBeforeCall = ws.sent.length; // 1 = the live-delivery-change

  const vtaClient = new VtaMediatorClient({
    session,
    vta: { kid: vta.kid, x25519Pub: vta.publicKey },
    client: {
      did: client.did,
      kid: client.kid,
      privateKey: client.privateKey,
      publicKey: client.publicKey,
    },
    vtaDid: vta.did,
    mediatorDid: mediator.did,
  });

  const callPromise = vtaClient.sendAndWait(
    "https://trusttasks.org/spec/vta/discovery/capabilities/1.0",
    {},
    3000,
  );

  // sendAndWait packs (two async steps) before sending the forward —
  // wait for the frame to flush rather than asserting synchronously.
  await waitUntil(() => ws.sent.length > sentBeforeCall, 1000);

  // The call should have sent exactly one new frame: the forward,
  // authcrypt'd to the mediator. Unpack it as the mediator and verify
  // it's a forward whose inner attachment decrypts to our request.
  assert.equal(ws.sent.length, sentBeforeCall + 1);
  const forwardFrame = ws.sent[ws.sent.length - 1];

  const outer = await runHelper(HELPER, {
    jwe: forwardFrame,
    recipient_kid: mediator.kid,
    recipient_private_x_b64u: bytesToB64u(mediator.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(outer.ok, `forward unpack failed: ${JSON.stringify(outer)}`);
  assert.equal(outer.plaintext.type, "https://didcomm.org/routing/2.0/forward");
  assert.equal(outer.plaintext.body.next, vta.did);

  // Recover the inner request id (the thid the VTA must echo).
  const innerJwe = JSON.stringify(outer.plaintext.attachments[0].data.json);
  const inner = await runHelper(HELPER, {
    jwe: innerJwe,
    recipient_kid: vta.kid,
    recipient_private_x_b64u: bytesToB64u(vta.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(inner.ok, `inner unpack failed: ${JSON.stringify(inner)}`);
  const requestId = inner.plaintext.id;
  assert.equal(inner.plaintext.from, client.did);

  // Now inject the VTA's response (authcrypt VTA→client, thid==requestId).
  const responseJwe = await pack({
    message: {
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0/response",
      thid: requestId,
      from: vta.did,
      to: [client.did],
      body: { capabilities: ["keys", "acl"] },
    },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });
  ws.inject(responseJwe);

  const response = await callPromise;
  assert.equal(response.thid, requestId);
  assert.deepEqual(response.body.capabilities, ["keys", "acl"]);

  vtaClient.close();
});

test("resolveX25519KeyAgreement: extracts X25519 from the live VTA DID", async () => {
  // Live did:webvh resolution (network). Confirms the orchestration's
  // recipient-resolution against the real VTA DID.
  const { kid, x25519Pub } = await resolveX25519KeyAgreement(
    "did:webvh:QmWoJD2kpP6AJknNtj7UFERUstEen258ywj3ruHoh1ZAqr:webvh.storm.ws:glenn-vta",
  );
  assert.ok(kid.endsWith("#key-1"));
  assert.equal(x25519Pub.length, 32);
});

async function waitUntil(pred, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("waitUntil: condition not met within timeout");
}

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
