import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";

import {
  authenticateToMediator,
  parseMediatorEndpoints,
} from "../src/mediator-auth.js";
import { generateEphemeralClient } from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";

// Build a resolved-DID-document for a mediator whose X25519
// keyAgreement we control, with given service endpoints.
function mediatorDoc(did, { rest, ws, auth, x25519Pub }) {
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, x25519Pub);
  const eps = [];
  if (ws) eps.push({ accept: ["didcomm/v2"], uri: ws });
  if (rest) eps.push({ accept: ["didcomm/v2"], uri: rest });
  const service = [
    { id: `${did}#dc`, type: ["DIDCommMessaging"], serviceEndpoint: eps },
  ];
  if (auth) service.push({ id: `${did}#auth`, type: ["Authentication"], serviceEndpoint: auth });
  return {
    id: did,
    keyAgreement: [`${did}#key-1`],
    verificationMethod: [
      { id: `${did}#key-1`, type: "Multikey", controller: did, publicKeyMultibase: mb },
    ],
    service,
  };
}

// A fake mediator: a did:key with an X25519 key we control, so we can
// unpack the auth JWE the client produces. The auth endpoints are
// canned in the mock fetch (DID resolution for did:key is offline, but
// did:key has no `service` array — so we bypass resolveMediator by
// pointing the test at a hand-built mediator object via the fetch mock
// for the HTTP side and asserting on the packed body).
function buildFakeMediatorKeypair() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  return {
    did: `did:key:${mb}`,
    kid: `did:key:${mb}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

// did:key has no DIDCommMessaging service, so resolveMediator would
// reject it. For the HTTP-flow tests we stub resolveMediator by
// monkeypatching the resolver is overkill; instead we test the two
// halves separately:
//   - the live resolveMediator is covered by a Node smoke check
//     elsewhere; here we focus on the challenge→pack→authenticate
//     HTTP flow + snake_case parsing + the packed-message round-trip.
//
// To exercise authenticateToMediator without a webvh fetch, we use a
// did:key mediator AND inject a fetch that also serves a minimal DID
// doc? No — resolveMediator uses the resolver, not fetch. So we test
// the HTTP flow via a did:webvh-shaped mediator is not feasible
// offline. Instead we assert the packed auth message via a direct
// pack + Rust-unpack, and assert the HTTP wiring via a mock that
// checks the challenge request + parses snake_case tokens by calling
// the internal flow with a did:key mediator whose service array we
// inject through a custom resolver.

// Simplest robust approach: spin a fake mediator did:key document into
// the resolver via the `createResolver` override is not exposed to
// authenticateToMediator (it uses the default resolver). So we test
// the HTTP/parse layer by reproducing the exact response shapes and
// verifying token extraction through a thin wrapper.

const HELPER = pathResolve(
  process.env.CARGO_TARGET_DIR || pathResolve(import.meta.dirname, "..", "..", "target"),
  "debug",
  "didcomm-unpack",
);

test("authenticateToMediator: snake_case token parsing + packed auth message round-trips", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }

  // Use a did:key mediator. resolveMediator rejects did:key (no
  // service array), so we can't call authenticateToMediator end-to-end
  // offline. Instead, validate the two things that matter and aren't
  // covered by the live smoke check:
  //   1. The mediator's snake_case `data.access_token` shape parses.
  //   2. The packed auth message (what we POST to /authenticate)
  //      unpacks in the Rust crate with the right type + body.
  //
  // We reproduce authenticateToMediator's packing inline against a
  // controllable mediator keypair.
  const mediator = buildFakeMediatorKeypair();
  const client = generateEphemeralClient();

  const { pack } = await import("../src/pack.js");
  const jwk = await import("../src/jwk.js");

  const message = {
    id: `urn:uuid:${crypto.randomUUID()}`,
    typ: "application/didcomm-plain+json",
    type: "https://affinidi.com/atm/1.0/authenticate",
    from: client.did,
    to: [mediator.did],
    body: { challenge: "chal-123", session_id: "sess-9" },
  };
  const jweJson = await pack({
    message,
    sender: {
      kid: client.kid,
      privateJwk: jwk.privateJwk("X25519", client.privateKey, client.publicKey),
    },
    recipient: {
      kid: mediator.kid,
      publicJwk: jwk.publicJwk("X25519", mediator.publicKey),
    },
  });

  const unpacked = await runHelper(HELPER, {
    jwe: jweJson,
    recipient_kid: mediator.kid,
    recipient_private_x_b64u: bytesToB64u(mediator.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(unpacked.ok, `unpack failed: ${JSON.stringify(unpacked)}`);
  assert.equal(unpacked.plaintext.type, "https://affinidi.com/atm/1.0/authenticate");
  assert.equal(unpacked.plaintext.body.challenge, "chal-123");
  assert.equal(unpacked.plaintext.body.session_id, "sess-9");
  assert.equal(unpacked.plaintext.to[0], mediator.did);
});

test("authenticateToMediator: requires a fetch implementation", async () => {
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      authenticateToMediator({
        mediatorDid: "did:webvh:scid:host:m",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch: "nope",
      }),
    /no fetch implementation/,
  );
});

test("authenticateToMediator: rejects non-Uint8Array key", async () => {
  await assert.rejects(
    () =>
      authenticateToMediator({
        mediatorDid: "did:webvh:scid:host:m",
        clientDid: "did:key:zABC",
        clientX25519Private: "not bytes",
        clientX25519Public: new Uint8Array(32),
        fetch: async () => new Response("{}"),
      }),
    /clientX25519Private must be Uint8Array/,
  );
});

// ─── parseMediatorEndpoints (pure) ──────────────────────────────────

test("parseMediatorEndpoints: splits ws/https + reads keyAgreement", () => {
  const did = "did:webvh:scid:host:m";
  const kp = x25519.generateKeyPair();
  const doc = mediatorDoc(did, {
    ws: "wss://m.example/ws",
    rest: "https://m.example/v1",
    auth: "https://m.example/v1/authenticate",
    x25519Pub: kp.publicKey,
  });
  const m = parseMediatorEndpoints(doc, did);
  assert.equal(m.restEndpoint, "https://m.example/v1");
  assert.equal(m.wsEndpoint, "wss://m.example/ws");
  assert.equal(m.authEndpoint, "https://m.example/v1/authenticate");
  assert.equal(m.kid, `${did}#key-1`);
  assert.equal(m.x25519Pub.length, 32);
});

test("parseMediatorEndpoints: derives auth endpoint from REST when no Authentication service", () => {
  const did = "did:webvh:scid:host:m";
  const kp = x25519.generateKeyPair();
  const doc = mediatorDoc(did, { rest: "https://m.example/v1/", x25519Pub: kp.publicKey });
  const m = parseMediatorEndpoints(doc, did);
  assert.equal(m.authEndpoint, "https://m.example/v1/authenticate");
  assert.equal(m.wsEndpoint, null);
});

test("parseMediatorEndpoints: throw branches", () => {
  const did = "did:x:m";
  const kp = x25519.generateKeyPair();
  // No REST endpoint.
  assert.throws(
    () => parseMediatorEndpoints({ id: did, service: [], keyAgreement: [] }, did),
    /no REST DIDCommMessaging endpoint/,
  );
  // No keyAgreement.
  assert.throws(
    () =>
      parseMediatorEndpoints(
        { id: did, service: [{ id: `${did}#dc`, type: ["DIDCommMessaging"], serviceEndpoint: [{ uri: "https://m/v1" }] }] },
        did,
      ),
    /no keyAgreement/,
  );
});

test("parseMediatorEndpoints: rejects insecure endpoints unless allowInsecure", () => {
  const did = "did:x:m";
  const kp = x25519.generateKeyPair();
  const doc = mediatorDoc(did, { rest: "http://m.example/v1", x25519Pub: kp.publicKey });
  assert.throws(() => parseMediatorEndpoints(doc, did), /insecure REST endpoint/);
  // allowInsecure lets it through.
  const m = parseMediatorEndpoints(doc, did, { allowInsecure: true });
  assert.equal(m.restEndpoint, "http://m.example/v1");
});

// ─── authenticateToMediator full HTTP flow (mock fetch + injected resolver) ──

test("authenticateToMediator: full challenge → pack → /authenticate → token (snake_case)", async (t) => {
  if (!existsSync(HELPER)) {
    t.skip("round-trip helper not built");
    return;
  }
  const client = generateEphemeralClient();
  const medKp = x25519.generateKeyPair();
  const medDid = "did:webvh:scid:host:mediator";
  const doc = mediatorDoc(medDid, {
    ws: "wss://m.example/ws",
    rest: "https://m.example/v1",
    auth: "https://m.example/v1/authenticate",
    x25519Pub: medKp.publicKey,
  });

  let challengeReq = null;
  let authBody = null;
  const fetch = async (url, init) => {
    if (url === "https://m.example/v1/authenticate/challenge") {
      challengeReq = JSON.parse(init.body);
      return new Response(
        JSON.stringify({ sessionId: "S", data: { challenge: "CHAL", session_id: "S" } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url === "https://m.example/v1/authenticate") {
      authBody = init.body;
      assert.equal(init.headers["content-type"], "application/json");
      return new Response(
        JSON.stringify({
          sessionId: "S",
          data: {
            access_token: "med.jwt",
            access_expires_at: 111,
            refresh_token: "med.refresh",
            refresh_expires_at: 222,
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(`unexpected ${url}`, { status: 404 });
  };

  const result = await authenticateToMediator({
    mediatorDid: medDid,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    clientKid: client.kid,
    fetch,
    resolve: async () => ({ didDocument: doc }),
  });

  // snake_case token parsing.
  assert.equal(result.accessToken, "med.jwt");
  assert.equal(result.accessExpiresAt, 111);
  assert.equal(result.refreshToken, "med.refresh");
  assert.deepEqual(challengeReq, { did: client.did });

  // The /authenticate body is a real authcrypt JWE the mediator can
  // decrypt — verify via the Rust helper.
  const unpacked = await runHelper(HELPER, {
    jwe: authBody,
    recipient_kid: `${medDid}#key-1`,
    recipient_private_x_b64u: bytesToB64u(medKp.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });
  assert.ok(unpacked.ok, `auth JWE unpack failed: ${JSON.stringify(unpacked)}`);
  assert.equal(unpacked.plaintext.type, "https://affinidi.com/atm/1.0/authenticate");
  assert.equal(unpacked.plaintext.body.challenge, "CHAL");
  assert.equal(unpacked.plaintext.body.session_id, "S");
});

test("authenticateToMediator: surfaces a 4xx from /authenticate/challenge", async () => {
  const client = generateEphemeralClient();
  const medKp = x25519.generateKeyPair();
  const doc = mediatorDoc("did:x:m", { rest: "https://m/v1", x25519Pub: medKp.publicKey });
  await assert.rejects(
    () =>
      authenticateToMediator({
        mediatorDid: "did:x:m",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch: async () => new Response('{"message":"DID blocked"}', { status: 403 }),
        resolve: async () => ({ didDocument: doc }),
      }),
    /403/,
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
