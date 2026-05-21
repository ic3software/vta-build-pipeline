// VTA REST authentication via a DIDComm-packed `/auth/` body.
//
// Flow (matches `vta-sdk::auth_light::challenge_response_light` but
// with the algorithm pair the VTA's `affinidi-messaging-didcomm-0.13`
// decrypt path actually accepts: ECDH-1PU+A256KW + A256CBC-HS512):
//
//   1. POST /auth/challenge with `{ did: <client_did> }` → JSON
//      `{ sessionId, data: { challenge, teeAttestation? } }`.
//   2. Build a DIDComm v2 plaintext message:
//        { id, typ: "application/didcomm-plain+json",
//          type: "https://affinidi.com/atm/1.0/authenticate",
//          from: client_did, to: [vta_did],
//          body: { challenge, session_id } }
//      (the inner body uses snake_case — that's what the VTA reads).
//   3. Authcrypt-pack to the VTA's first keyAgreement key.
//   4. POST /auth/ with the JWE JSON as `text/plain` body
//      (the VTA route handler takes `body: String`).
//   5. JSON-parse the response → `{ sessionId?, data: { accessToken,
//      accessExpiresAt, refreshToken?, refreshExpiresAt? } }`.
//
// `refresh()` reuses the same authcrypt-pack-and-POST machinery
// against `/auth/refresh` (message type `.../authenticate/refresh`,
// body `{ refresh_token }`). The VTA rotates the refresh token on
// every call (RFC 6749 §10.4), so the returned `refreshToken` must
// replace the one the caller held — replaying the spent token fails.
//
// Caller responsibilities:
//   - The `client_did` must already be in the VTA's ACL (the
//     /auth/challenge handler ACL-gates the request). Demos that
//     mint ephemeral did:keys need to run `pnm acl create` first.
//   - The VTA's `cors_origins` must include this page's origin.
//   - Persist the rotated `refreshToken` from each `refresh()` call.

import { resolve as resolveDid } from "./resolver.js";
import { pack } from "./pack.js";
import * as multibase from "./multibase.js";
import * as jwk from "./jwk.js";
import * as x25519 from "./x25519.js";

const AUTH_MESSAGE_TYPE = "https://affinidi.com/atm/1.0/authenticate";
const REFRESH_MESSAGE_TYPE = "https://affinidi.com/atm/1.0/authenticate/refresh";

/**
 * Authenticate to a VTA over REST using DIDComm-packed challenge
 * response.
 *
 * @param {Object} args
 * @param {string} args.baseUrl - VTA base URL (e.g. "https://vta.example").
 * @param {string} args.vtaDid - the VTA's DID. Used to resolve the
 *   recipient keyAgreement key. The DID is supplied externally
 *   because there's no unauth endpoint that returns it.
 * @param {string} args.clientDid - the caller's DID. Must already be
 *   in the VTA's ACL.
 * @param {Uint8Array} args.clientX25519Private - the X25519 secret
 *   for `clientDid`'s keyAgreement key. authcrypt uses it for
 *   ECDH-1PU sender binding.
 * @param {Uint8Array} args.clientX25519Public - the matching public.
 * @param {string} [args.clientKid] - the caller's full kid (DID +
 *   fragment). Defaults to `${clientDid}#${multibase_pub}` which
 *   matches the layout a did:key Ed25519/X25519 resolves to.
 * @param {Function} [args.fetch] - fetch implementation; defaults
 *   to `globalThis.fetch`. Override in tests.
 * @returns {Promise<{
 *   accessToken: string,
 *   accessExpiresAt: number,
 *   refreshToken?: string,
 *   refreshExpiresAt?: number,
 *   sessionId?: string,
 * }>}
 */
export async function authenticate({
  baseUrl,
  vtaDid,
  clientDid,
  clientX25519Private,
  clientX25519Public,
  clientKid,
  fetch: customFetch,
}) {
  assertNonEmptyString("clientDid", clientDid);
  const ctx = buildContext({
    baseUrl,
    vtaDid,
    clientDid,
    clientX25519Private,
    clientX25519Public,
    clientKid,
    customFetch,
  });

  // ── Step 1: request the challenge ────────────────────────────────
  const challenge = await postJson(
    ctx.fetchFn,
    joinUrl(baseUrl, "/auth/challenge"),
    { did: clientDid },
  );
  if (!challenge?.sessionId || !challenge?.data?.challenge) {
    throw new Error(
      `vta-rest-auth: /auth/challenge response missing sessionId or challenge (got ${JSON.stringify(challenge)})`,
    );
  }

  // ── Steps 2-4: pack the response message and POST it to /auth/ ────
  const auth = await packAndPost(ctx, {
    path: "/auth/",
    type: AUTH_MESSAGE_TYPE,
    body: {
      challenge: challenge.data.challenge,
      // The VTA reads `session_id` (snake_case) from the body.
      session_id: challenge.sessionId,
    },
  });
  return tokenResult(auth, "/auth/");
}

/**
 * Exchange a refresh token for a fresh access + refresh token pair.
 *
 * The VTA implements RFC 6749 §10.4 refresh-token rotation: the
 * presented token is single-use, and the response carries a NEW
 * refresh token. Callers MUST persist `result.refreshToken` /
 * `result.refreshExpiresAt` and use them for the next refresh —
 * replaying the original token after a successful refresh fails with
 * "refresh token not found".
 *
 * The refresh message is authcrypt-packed to the VTA exactly like the
 * initial authenticate message (the VTA's `/auth/refresh` handler
 * unpacks it the same way); the VTA looks up the session by the
 * `refresh_token` in the body, so the sender binding is not load-
 * bearing here — but we still pack to the VTA's keyAgreement.
 *
 * @param {Object} args - same `client*` + `vtaDid` + `baseUrl` shape
 *   as {@link authenticate}, plus:
 * @param {string} args.refreshToken - the current refresh token.
 * @returns {Promise<{
 *   accessToken: string,
 *   accessExpiresAt: number,
 *   refreshToken?: string,
 *   refreshExpiresAt?: number,
 *   sessionId?: string,
 * }>}
 */
export async function refresh({
  baseUrl,
  vtaDid,
  clientDid,
  clientX25519Private,
  clientX25519Public,
  clientKid,
  refreshToken,
  fetch: customFetch,
}) {
  assertNonEmptyString("refreshToken", refreshToken);
  const ctx = buildContext({
    baseUrl,
    vtaDid,
    clientDid,
    clientX25519Private,
    clientX25519Public,
    clientKid,
    customFetch,
  });

  const auth = await packAndPost(ctx, {
    path: "/auth/refresh",
    type: REFRESH_MESSAGE_TYPE,
    body: { refresh_token: refreshToken },
  });
  return tokenResult(auth, "/auth/refresh");
}

/**
 * Generate a fresh ephemeral X25519 client identity that's
 * immediately usable as the `client*` parameters of
 * {@link authenticate}. The DID is an X25519-only did:key — fine
 * for authcrypt sender binding but NOT a signing key.
 *
 * @returns {{
 *   did: string,
 *   kid: string,
 *   privateKey: Uint8Array,
 *   publicKey: Uint8Array,
 * }}
 */
export function generateEphemeralClient() {
  const kp = x25519.generateKeyPair();
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, kp.publicKey);
  const did = `did:key:${mb}`;
  return {
    did,
    kid: `${did}#${mb}`,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
  };
}

// ─── Internals ──────────────────────────────────────────────────────────

/**
 * Validate the shared `client*` + transport args once and bundle them
 * into a context object both `authenticate` and `refresh` thread through
 * the pack/post helper.
 */
function buildContext({
  baseUrl,
  vtaDid,
  clientDid,
  clientX25519Private,
  clientX25519Public,
  clientKid,
  customFetch,
}) {
  assertNonEmptyString("baseUrl", baseUrl);
  assertNonEmptyString("vtaDid", vtaDid);
  assertNonEmptyString("clientDid", clientDid);
  assertBytes("clientX25519Private", clientX25519Private, 32);
  assertBytes("clientX25519Public", clientX25519Public, 32);

  const fetchFn = customFetch ?? globalThis.fetch;
  if (typeof fetchFn !== "function") {
    throw new Error("vta-rest-auth: no fetch implementation available");
  }

  return {
    baseUrl,
    vtaDid,
    clientDid,
    clientX25519Private,
    clientX25519Public,
    // If the caller didn't supply a kid, assume their public key is the
    // fragment (matches how did:key X25519-only DIDs are structured).
    clientKid: clientKid ?? defaultClientKid(clientDid, clientX25519Public),
    fetchFn,
  };
}

/**
 * Resolve the VTA's keyAgreement, build a DIDComm message of the given
 * `type` + `body`, authcrypt-pack it, and POST the JWE to `path` as
 * `text/plain`. Returns the parsed JSON response.
 */
async function packAndPost(ctx, { path, type, body }) {
  const recipient = await resolveVtaRecipient(ctx.vtaDid);

  const message = {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type,
    from: ctx.clientDid,
    to: [ctx.vtaDid],
    body,
  };

  const senderPrivateJwk = jwk.privateJwk(
    "X25519",
    ctx.clientX25519Private,
    ctx.clientX25519Public,
  );
  const recipientPublicJwk = jwk.publicJwk("X25519", recipient.x25519Pub);

  const jweJson = await pack({
    message,
    sender: { kid: ctx.clientKid, privateJwk: senderPrivateJwk },
    recipient: { kid: recipient.kid, publicJwk: recipientPublicJwk },
  });

  return postRaw(ctx.fetchFn, joinUrl(ctx.baseUrl, path), jweJson, "text/plain");
}

/** Validate + normalize a `/auth/`-family token response. */
function tokenResult(resp, path) {
  if (!resp?.data?.accessToken) {
    throw new Error(
      `vta-rest-auth: ${path} response missing accessToken (got ${JSON.stringify(resp)})`,
    );
  }
  return {
    accessToken: resp.data.accessToken,
    accessExpiresAt: resp.data.accessExpiresAt,
    refreshToken: resp.data.refreshToken,
    refreshExpiresAt: resp.data.refreshExpiresAt,
    sessionId: resp.sessionId,
  };
}

async function resolveVtaRecipient(vtaDid) {
  const { didDocument } = await resolveDid(vtaDid);
  const ka = didDocument.keyAgreement;
  if (!ka || ka.length === 0) {
    throw new Error(`vta-rest-auth: ${vtaDid} has no keyAgreement entries`);
  }
  // Resolve the first entry — either embedded VM object or a ref into
  // verificationMethod[].
  let vm = ka[0];
  if (typeof vm === "string") {
    const found = (didDocument.verificationMethod ?? []).find((v) => v.id === vm);
    if (!found) {
      throw new Error(`vta-rest-auth: keyAgreement reference ${vm} not in verificationMethod[]`);
    }
    vm = found;
  }
  if (!vm.publicKeyMultibase) {
    throw new Error("vta-rest-auth: keyAgreement entry has no publicKeyMultibase (only Multikey supported)");
  }
  const { codec, key } = multibase.decodeMultikey(vm.publicKeyMultibase);
  if (codec[0] !== 0xec || codec[1] !== 0x01) {
    throw new Error(
      `vta-rest-auth: keyAgreement is not X25519 (multicodec 0x${codec[0].toString(16)}${codec[1].toString(16)})`,
    );
  }
  return { kid: vm.id, x25519Pub: key };
}

function defaultClientKid(did, x25519Public) {
  // Mirror the convention used by `resolver/did-key.js` for X25519-
  // only did:keys: the fragment is the multibase-encoded public key.
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, x25519Public);
  return `${did}#${mb}`;
}

async function postJson(fetchFn, url, body) {
  const resp = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return parseResponse(resp, url);
}

async function postRaw(fetchFn, url, body, contentType) {
  const resp = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
  return parseResponse(resp, url);
}

async function parseResponse(resp, url) {
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(
      `vta-rest-auth: ${resp.status} ${resp.statusText} from ${url}: ${text.slice(0, 200)}`,
    );
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`vta-rest-auth: ${url} returned non-JSON body: ${text.slice(0, 200)}`);
  }
}

function joinUrl(base, path) {
  return base.replace(/\/+$/, "") + path;
}

function randomUuid() {
  // Prefer the native API; fall back to a manual v4 only if a
  // polyfill is needed. All B5-floor browsers have crypto.randomUUID.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // RFC 4122 §4.4 fallback.
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function assertNonEmptyString(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`vta-rest-auth: ${name} must be a non-empty string`);
  }
}

function assertBytes(name, value, exactLen) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`vta-rest-auth: ${name} must be Uint8Array`);
  }
  if (exactLen !== undefined && value.length !== exactLen) {
    throw new Error(`vta-rest-auth: ${name} must be ${exactLen} bytes, got ${value.length}`);
  }
}
