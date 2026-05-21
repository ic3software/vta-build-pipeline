import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";

import {
  authenticate,
  refresh,
  generateEphemeralClient,
} from "../src/vta-rest-auth.js";
import * as x25519 from "../src/x25519.js";
import * as multibase from "../src/multibase.js";

// ─── Test fixture: mock VTA with a known X25519 keyAgreement key ────────

/**
 * A fake VTA DID resolver hook: instead of fetching did:webvh, we
 * generate a did:key with an X25519 key we control. The pair lets us
 * actually unpack the produced JWE in the test.
 */
function buildFakeVta() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  return {
    did: `did:key:${mb}`,
    kid: `did:key:${mb}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

/**
 * Build a mock `fetch` that records calls and returns canned
 * responses for the two auth endpoints. The third argument `onAuth`
 * receives the raw JWE body so the test can inspect it.
 */
function mockFetch({ baseUrl, challengeBody, authBody, onChallenge, onAuth }) {
  const calls = [];
  return {
    fetch: async (url, init) => {
      calls.push({ url, method: init.method, headers: init.headers, body: init.body });
      if (url === `${baseUrl}/auth/challenge`) {
        onChallenge?.(JSON.parse(init.body));
        return new Response(JSON.stringify(challengeBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === `${baseUrl}/auth/`) {
        onAuth?.(init.body);
        return new Response(JSON.stringify(authBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(`unexpected url ${url}`, { status: 404 });
    },
    calls,
  };
}

/**
 * Mock `fetch` for the refresh flow — only the `/auth/refresh`
 * endpoint. `onRefresh` receives the raw JWE body.
 */
function mockRefreshFetch({ baseUrl, refreshBody, onRefresh }) {
  const calls = [];
  return {
    fetch: async (url, init) => {
      calls.push({ url, method: init.method, headers: init.headers, body: init.body });
      if (url === `${baseUrl}/auth/refresh`) {
        onRefresh?.(init.body);
        return new Response(JSON.stringify(refreshBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(`unexpected url ${url}`, { status: 404 });
    },
    calls,
  };
}

// ─── Happy path ─────────────────────────────────────────────────────────

test("authenticate: full challenge-response flow", async () => {
  const vta = buildFakeVta();
  const client = generateEphemeralClient();

  const challengeBody = {
    sessionId: "sess-abc123",
    data: { challenge: "deadbeefcafe" },
  };
  const authBody = {
    sessionId: "sess-abc123",
    data: {
      accessToken: "test.jwt.token",
      accessExpiresAt: 1_800_000_000,
      refreshToken: "refresh-xyz",
      refreshExpiresAt: 1_800_086_400,
    },
  };

  let challengeReq = null;
  let authReq = null;
  const { fetch, calls } = mockFetch({
    baseUrl: "https://vta.test",
    challengeBody,
    authBody,
    onChallenge: (b) => (challengeReq = b),
    onAuth: (b) => (authReq = b),
  });

  const result = await authenticate({
    baseUrl: "https://vta.test",
    vtaDid: vta.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    fetch,
  });

  // Result shape
  assert.equal(result.accessToken, "test.jwt.token");
  assert.equal(result.accessExpiresAt, 1_800_000_000);
  assert.equal(result.refreshToken, "refresh-xyz");
  assert.equal(result.sessionId, "sess-abc123");

  // Wire-format checks
  assert.equal(calls.length, 2, "exactly two HTTP calls");
  assert.equal(calls[0].url, "https://vta.test/auth/challenge");
  assert.equal(calls[1].url, "https://vta.test/auth/");
  assert.deepEqual(challengeReq, { did: client.did });
  // /auth/ body is a JSON-shaped JWE string sent with text/plain.
  assert.equal(calls[1].headers["content-type"], "text/plain");
  const jwe = JSON.parse(authReq);
  for (const field of ["protected", "recipients", "iv", "ciphertext", "tag"]) {
    assert.ok(field in jwe, `JWE missing ${field}`);
  }
  assert.equal(jwe.recipients.length, 1);
  assert.equal(jwe.recipients[0].header.kid, vta.kid);
});

test("authenticate: packed message has correct DIDComm fields", async () => {
  // Unpack the produced JWE in a separate test to make sure `from`,
  // `to`, `type`, `body.challenge`, `body.session_id` are all
  // populated as the VTA expects.
  const helperPath = pathResolve(
    process.env.CARGO_TARGET_DIR || pathResolve(import.meta.dirname, "..", "..", "target"),
    "debug",
    "didcomm-unpack",
  );
  if (!existsSync(helperPath)) {
    return; // round-trip helper not built — skip
  }

  const vta = buildFakeVta();
  const client = generateEphemeralClient();
  const challengeBody = {
    sessionId: "sess-xyz",
    data: { challenge: "abc123def456" },
  };

  let capturedJwe = null;
  const { fetch } = mockFetch({
    baseUrl: "https://vta.test",
    challengeBody,
    authBody: { data: { accessToken: "ok", accessExpiresAt: 1 } },
    onAuth: (b) => (capturedJwe = b),
  });

  await authenticate({
    baseUrl: "https://vta.test",
    vtaDid: vta.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    fetch,
  });

  // Now unpack the JWE via the Rust helper to check the inner
  // message structure.
  const unpackResult = await runHelper(helperPath, {
    jwe: capturedJwe,
    recipient_kid: vta.kid,
    recipient_private_x_b64u: bytesToB64u(vta.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });

  assert.ok(unpackResult.ok, `unpack failed: ${JSON.stringify(unpackResult)}`);
  // The helper emits `plaintext` as a JSON value (object), already
  // decoded — no double-parse needed.
  const plaintext = unpackResult.plaintext;
  assert.equal(plaintext.type, "https://affinidi.com/atm/1.0/authenticate");
  assert.equal(plaintext.from, client.did);
  assert.deepEqual(plaintext.to, [vta.did]);
  assert.equal(plaintext.body.challenge, "abc123def456");
  assert.equal(plaintext.body.session_id, "sess-xyz", "body uses snake_case session_id");
  assert.ok(plaintext.id?.startsWith("urn:uuid:"), "id is a uuid urn");
});

// ─── Refresh ─────────────────────────────────────────────────────────────

test("refresh: exchanges a refresh token for a new pair (no challenge call)", async () => {
  const vta = buildFakeVta();
  const client = generateEphemeralClient();

  const refreshBody = {
    sessionId: "sess-abc123",
    data: {
      accessToken: "new.access.jwt",
      accessExpiresAt: 1_800_000_900,
      refreshToken: "rotated-refresh",
      refreshExpiresAt: 1_800_086_400,
    },
  };

  let refreshReq = null;
  const { fetch, calls } = mockRefreshFetch({
    baseUrl: "https://vta.test",
    refreshBody,
    onRefresh: (b) => (refreshReq = b),
  });

  const result = await refresh({
    baseUrl: "https://vta.test",
    vtaDid: vta.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    refreshToken: "old-refresh",
    fetch,
  });

  // Rotation: caller gets the NEW refresh token back.
  assert.equal(result.accessToken, "new.access.jwt");
  assert.equal(result.refreshToken, "rotated-refresh");
  assert.equal(result.refreshExpiresAt, 1_800_086_400);

  // Refresh hits ONLY /auth/refresh — no /auth/challenge round-trip.
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://vta.test/auth/refresh");
  assert.equal(calls[0].headers["content-type"], "text/plain");
  const jwe = JSON.parse(refreshReq);
  for (const field of ["protected", "recipients", "iv", "ciphertext", "tag"]) {
    assert.ok(field in jwe, `JWE missing ${field}`);
  }
  assert.equal(jwe.recipients[0].header.kid, vta.kid);
});

test("refresh: packed message carries the refresh_token + correct type", async () => {
  const helperPath = pathResolve(
    process.env.CARGO_TARGET_DIR || pathResolve(import.meta.dirname, "..", "..", "target"),
    "debug",
    "didcomm-unpack",
  );
  if (!existsSync(helperPath)) {
    return; // round-trip helper not built — skip
  }

  const vta = buildFakeVta();
  const client = generateEphemeralClient();

  let capturedJwe = null;
  const { fetch } = mockRefreshFetch({
    baseUrl: "https://vta.test",
    refreshBody: { data: { accessToken: "ok", accessExpiresAt: 1 } },
    onRefresh: (b) => (capturedJwe = b),
  });

  await refresh({
    baseUrl: "https://vta.test",
    vtaDid: vta.did,
    clientDid: client.did,
    clientX25519Private: client.privateKey,
    clientX25519Public: client.publicKey,
    refreshToken: "the-refresh-token",
    fetch,
  });

  const unpackResult = await runHelper(helperPath, {
    jwe: capturedJwe,
    recipient_kid: vta.kid,
    recipient_private_x_b64u: bytesToB64u(vta.privateKey),
    sender_public_x_b64u: bytesToB64u(client.publicKey),
  });

  assert.ok(unpackResult.ok, `unpack failed: ${JSON.stringify(unpackResult)}`);
  const plaintext = unpackResult.plaintext;
  assert.equal(plaintext.type, "https://affinidi.com/atm/1.0/authenticate/refresh");
  assert.equal(plaintext.body.refresh_token, "the-refresh-token");
  assert.deepEqual(plaintext.to, [vta.did]);
});

test("refresh: requires a non-empty refreshToken", async () => {
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      refresh({
        baseUrl: "https://vta.test",
        vtaDid: "did:key:zABC",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        refreshToken: "",
        fetch: async () => new Response("{}", { status: 200 }),
      }),
    /refreshToken must be a non-empty string/,
  );
});

test("refresh: surfaces 4xx (e.g. rotated/replayed token)", async () => {
  const vta = buildFakeVta();
  const client = generateEphemeralClient();
  const fetch = async () =>
    new Response('{"error":"refresh token not found"}', { status: 401 });
  await assert.rejects(
    () =>
      refresh({
        baseUrl: "https://vta.test",
        vtaDid: vta.did,
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        refreshToken: "stale",
        fetch,
      }),
    /401.*refresh token not found/,
  );
});

// ─── Error paths ─────────────────────────────────────────────────────────

test("authenticate: rejects 4xx from /auth/challenge", async () => {
  const fetch = async (url) => {
    return new Response('{"error":"DID not in ACL"}', { status: 403 });
  };
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      authenticate({
        baseUrl: "https://vta.test",
        vtaDid: "did:key:zABC",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch,
      }),
    /403.*DID not in ACL/,
  );
});

test("authenticate: surfaces a malformed challenge response", async () => {
  const fetch = async () =>
    new Response('{"weird":"shape"}', {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      authenticate({
        baseUrl: "https://vta.test",
        vtaDid: "did:key:zABC",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch,
      }),
    /missing sessionId or challenge/,
  );
});

test("authenticate: rejects when VTA DID has no keyAgreement", async () => {
  // The fake VTA is an Ed25519-only did:key with NO X25519 — but
  // actually did-key resolver always derives a keyAgreement for
  // Ed25519. Use a different shape: P-256 did:key, which we DO
  // emit without keyAgreement.
  const fetch = async (url) => {
    if (url.endsWith("/auth/challenge")) {
      return new Response(JSON.stringify({
        sessionId: "s",
        data: { challenge: "c" },
      }), { status: 200 });
    }
    return new Response("ok", { status: 200 });
  };
  // P-256 multibase from a known did:key vector.
  const p256Did = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      authenticate({
        baseUrl: "https://vta.test",
        vtaDid: p256Did,
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch,
      }),
    /has no keyAgreement/,
  );
});

test("authenticate: errors if fetch is explicitly non-function", async () => {
  // Defensive: a stringly-typed override should be caught early,
  // before any network attempt. `null`/`undefined` are intentionally
  // treated as "use the default" (??) so they're not tested here.
  const client = generateEphemeralClient();
  await assert.rejects(
    () =>
      authenticate({
        baseUrl: "https://vta.test",
        vtaDid: "did:key:zABC",
        clientDid: client.did,
        clientX25519Private: client.privateKey,
        clientX25519Public: client.publicKey,
        fetch: "not a function",
      }),
    /no fetch implementation/,
  );
});

// ─── generateEphemeralClient ────────────────────────────────────────────

test("generateEphemeralClient: produces a valid X25519 did:key", () => {
  const c = generateEphemeralClient();
  assert.ok(c.did.startsWith("did:key:z"));
  assert.equal(c.privateKey.length, 32);
  assert.equal(c.publicKey.length, 32);
  assert.equal(c.kid, `${c.did}#${c.did.slice("did:key:".length)}`);
  // Two consecutive calls produce different keys.
  const d = generateEphemeralClient();
  assert.notDeepEqual(c.publicKey, d.publicKey);
});

// ─── Helpers ────────────────────────────────────────────────────────────

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
      if (code !== 0) {
        return reject(new Error(`helper exit ${code}: ${stderr}`));
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`helper output not JSON: ${stdout}`));
      }
    });
    child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}
