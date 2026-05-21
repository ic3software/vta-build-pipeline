import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildLiveDeliveryChange,
  peekSkid,
  unpackInbound,
  MediatorSession,
  LIVE_DELIVERY_CHANGE_TYPE,
} from "../src/mediator-transport.js";
import { pack } from "../src/pack.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";
import * as jwk from "../src/jwk.js";

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

// Minimal browser-WebSocket stand-in: records sent frames, fires
// onopen on the next tick, and lets the test push inbound frames.
class FakeWebSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.sent = [];
    this.closed = false;
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    FakeWebSocket.last = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  addEventListener() {}
  send(data) {
    this.sent.push(data);
  }
  close() {
    this.closed = true;
    this.onclose && this.onclose();
  }
  // Test helper: simulate the mediator pushing a frame.
  inject(data) {
    this.onmessage && this.onmessage({ data });
  }
}

test("buildLiveDeliveryChange: correct type, body, return_route", () => {
  const m = buildLiveDeliveryChange({ from: "did:key:zC", mediatorDid: "did:key:zM" });
  assert.equal(m.type, LIVE_DELIVERY_CHANGE_TYPE);
  assert.equal(m.body.live_delivery, true);
  assert.equal(m.return_route, "all");
  assert.equal(m.from, "did:key:zC");
  assert.deepEqual(m.to, ["did:key:zM"]);
});

test("peekSkid: reads skid from a packed authcrypt JWE", async () => {
  const client = generateEphemeralClient();
  const recip = keypairDid();
  const jwe = await pack({
    message: { id: "1", type: "t", from: client.did, to: [recip.did], body: {} },
    sender: {
      kid: client.kid,
      privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey),
    },
    recipient: { kid: recip.kid, publicJwk: jwk.publicJwk("X25519", recip.publicKey) },
  });
  assert.equal(peekSkid(jwe), client.kid);
  assert.equal(peekSkid("not json"), null);
});

test("unpackInbound: dispatches by skid to the right sender key", async () => {
  // Two senders: a 'VTA' and a 'mediator'. A frame from each must
  // unpack via its own seeded key.
  const me = keypairDid();
  const vta = generateEphemeralClient();
  const med = generateEphemeralClient();

  const senderKeys = new Map([
    [vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }],
    [med.did, { publicJwk: jwk.publicJwk("X25519", med.publicKey) }],
  ]);
  const recipient = {
    kid: me.kid,
    privateJwk: jwk.privateJwk("X25519", me.privateKey, me.publicKey),
  };

  const fromVta = await pack({
    message: { id: "r1", type: "resp", thid: "req1", from: vta.did, to: [me.did], body: { ok: 1 } },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: me.kid, publicJwk: jwk.publicJwk("X25519", me.publicKey) },
  });
  const out = await unpackInbound(fromVta, { recipient, senderKeys });
  assert.equal(out.message.thid, "req1");
  assert.equal(out.message.body.ok, 1);
  assert.equal(out.senderKid, vta.kid);
});

test("unpackInbound: errors on unknown sender (no key, no resolver)", async () => {
  const me = keypairDid();
  const stranger = generateEphemeralClient();
  const jwe = await pack({
    message: { id: "x", type: "t", from: stranger.did, to: [me.did], body: {} },
    sender: {
      kid: stranger.kid,
      privateJwk: jwk.privateJwk("X25519", stranger.privateKey, stranger.publicKey),
    },
    recipient: { kid: me.kid, publicJwk: jwk.publicJwk("X25519", me.publicKey) },
  });
  await assert.rejects(
    () =>
      unpackInbound(jwe, {
        recipient: { kid: me.kid, privateJwk: jwk.privateJwk("X25519", me.privateKey, me.publicKey) },
        senderKeys: new Map(),
      }),
    /no sender key/,
  );
});

test("MediatorSession: connect sends live-delivery-change; waitFor resolves on matching thid", async () => {
  const client = generateEphemeralClient();
  const vta = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const mediator = {
    did: mediatorKp.did,
    kid: mediatorKp.kid,
    x25519Pub: mediatorKp.publicKey,
    wsEndpoint: "wss://mediator.test/ws",
  };

  const session = new MediatorSession({
    mediator,
    mediatorJwt: "med.jwt.token",
    client,
    senderKeys: new Map([[vta.did, { publicJwk: jwk.publicJwk("X25519", vta.publicKey) }]]),
    WebSocketImpl: FakeWebSocket,
  });

  await session.connect();
  const ws = FakeWebSocket.last;

  // Subprotocol bearer was used.
  assert.deepEqual(ws.protocols, ["bearer.med.jwt.token"]);
  // connect() sent exactly one frame: the live-delivery-change,
  // authcrypt'd to the mediator. Unpack it as the mediator to verify.
  assert.equal(ws.sent.length, 1);
  const { unpack } = await import("../src/unpack.js");
  const ldc = await unpack(ws.sent[0], {
    kid: mediatorKp.kid,
    privateJwk: jwk.privateJwk("X25519", mediatorKp.privateKey, mediatorKp.publicKey),
  }, { publicJwk: jwk.publicJwk("X25519", client.publicKey) });
  assert.equal(ldc.message.type, LIVE_DELIVERY_CHANGE_TYPE);
  assert.equal(ldc.message.return_route, "all");

  // Now simulate the VTA's response arriving over the socket: a
  // message authcrypt'd VTA→client with thid == our request id.
  const reqId = "urn:uuid:req-42";
  const responseJwe = await pack({
    message: {
      id: "urn:uuid:resp-1",
      type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0/response",
      thid: reqId,
      from: vta.did,
      to: [client.did],
      body: { capabilities: ["a", "b"] },
    },
    sender: { kid: vta.kid, privateJwk: jwk.privateJwk("X25519", vta.privateKey, vta.publicKey) },
    recipient: { kid: client.kid, publicJwk: jwk.publicJwk("X25519", client.publicKey) },
  });

  const waiter = session.waitFor(reqId, 2000);
  ws.inject(responseJwe);
  const response = await waiter;
  assert.equal(response.thid, reqId);
  assert.deepEqual(response.body.capabilities, ["a", "b"]);

  session.close();
  assert.ok(ws.closed);
});

test("MediatorSession: waitFor times out when no matching frame arrives", async () => {
  const client = generateEphemeralClient();
  const mediatorKp = keypairDid();
  const session = new MediatorSession({
    mediator: { did: mediatorKp.did, kid: mediatorKp.kid, x25519Pub: mediatorKp.publicKey, wsEndpoint: "wss://m.test/ws" },
    mediatorJwt: "jwt",
    client,
    WebSocketImpl: FakeWebSocket,
  });
  await session.connect();
  await assert.rejects(() => session.waitFor("nope", 50), /timeout waiting for response/);
  session.close();
});

test("MediatorSession: requires a wsEndpoint", () => {
  const client = generateEphemeralClient();
  assert.throws(
    () =>
      new MediatorSession({
        mediator: { did: "did:key:zM", kid: "did:key:zM#k", x25519Pub: new Uint8Array(32) },
        mediatorJwt: "jwt",
        client,
        WebSocketImpl: FakeWebSocket,
      }),
    /wsEndpoint required/,
  );
});
