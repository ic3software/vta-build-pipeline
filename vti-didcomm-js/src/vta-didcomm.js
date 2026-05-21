// High-level: talk to a VTA over DIDComm, relayed through its mediator.
//
// Composes the mediator pieces into one request/response call:
//   - resolve the VTA's keyAgreement (recipient for the inner message;
//     also the sender key we unpack its response with),
//   - authenticate to the mediator (mediator-auth),
//   - open a live WebSocket session (mediator-transport),
//   - `sendAndWait(type, body)`:
//       inner = authcrypt(client → VTA),
//       forward = authcrypt(client → mediator, next=VTA, attach inner),
//       send the forward over the WS,
//       await the VTA's response, correlated by thid == inner.id.
//
// Unlike the REST path (`vta-rest-auth.js`) there is NO VTA-side auth
// handshake: the inner authcrypt envelope is self-authenticating and
// the VTA ACL-checks the `from` DID. The only handshake here is with
// the mediator (to authorize using it as a relay).

import { resolve as resolveDid } from "./resolver.js";
import { pack } from "./pack.js";
import { buildForward } from "./forward.js";
import { authenticateToMediator } from "./mediator-auth.js";
import { MediatorSession } from "./mediator-transport.js";
import * as multibase from "./multibase.js";
import * as jwk from "./jwk.js";

/**
 * Connect to a VTA via its mediator and return a client for
 * request/response DIDComm calls.
 *
 * @param {Object} args
 * @param {string} args.vtaDid - the VTA's DID (final recipient).
 * @param {string} args.mediatorDid - the mediator's DID (relay).
 * @param {string} args.clientDid - caller DID (must be in the
 *   mediator's ACL; the VTA ACL-checks it per-operation).
 * @param {Uint8Array} args.clientX25519Private
 * @param {Uint8Array} args.clientX25519Public
 * @param {string} [args.clientKid]
 * @param {Function} [args.fetch] - fetch impl for mediator auth.
 * @param {Function} [args.WebSocketImpl] - WebSocket ctor.
 * @returns {Promise<VtaMediatorClient>}
 */
export async function connectVtaViaMediator({
  vtaDid,
  mediatorDid,
  clientDid,
  clientX25519Private,
  clientX25519Public,
  clientKid,
  fetch: customFetch,
  WebSocketImpl,
}) {
  const vta = await resolveX25519KeyAgreement(vtaDid);
  const resolvedClientKid = clientKid ?? defaultClientKid(clientDid, clientX25519Public);

  const auth = await authenticateToMediator({
    mediatorDid,
    clientDid,
    clientX25519Private,
    clientX25519Public,
    clientKid: resolvedClientKid,
    fetch: customFetch,
  });

  // Seed the VTA's keyAgreement so its responses unpack by skid.
  const senderKeys = new Map([
    [vtaDid, { publicJwk: jwk.publicJwk("X25519", vta.x25519Pub) }],
  ]);

  const client = {
    did: clientDid,
    kid: resolvedClientKid,
    privateKey: clientX25519Private,
    publicKey: clientX25519Public,
  };

  const session = new MediatorSession({
    mediator: auth.mediator,
    mediatorJwt: auth.accessToken,
    client,
    senderKeys,
    // Fallback: resolve any unexpected sender's keyAgreement on demand.
    resolveSender: async (did) => {
      const { x25519Pub } = await resolveX25519KeyAgreement(did);
      return { publicJwk: jwk.publicJwk("X25519", x25519Pub) };
    },
    WebSocketImpl,
  });
  await session.connect();

  return new VtaMediatorClient({ session, vta, client, vtaDid, mediatorDid });
}

/**
 * A connected DIDComm-over-mediator client for one VTA. Construct via
 * {@link connectVtaViaMediator}, or directly (with a pre-opened
 * session) for testing.
 */
export class VtaMediatorClient {
  /**
   * @param {Object} args
   * @param {import('./mediator-transport.js').MediatorSession} args.session
   * @param {{kid:string, x25519Pub:Uint8Array}} args.vta - VTA keyAgreement.
   * @param {{did:string, kid:string, privateKey:Uint8Array, publicKey:Uint8Array}} args.client
   * @param {string} args.vtaDid
   * @param {string} args.mediatorDid
   */
  constructor({ session, vta, client, vtaDid, mediatorDid }) {
    this.session = session;
    this.vta = vta;
    this.client = client;
    this.vtaDid = vtaDid;
    this.mediatorDid = mediatorDid;
  }

  /**
   * Send a DIDComm request to the VTA and wait for the thid-correlated
   * response.
   *
   * @param {string} type - the DIDComm message `type` (operation URI).
   * @param {Object} body - the request body.
   * @param {number} [timeoutMs=30000]
   * @returns {Promise<Object>} the unpacked response message.
   */
  async sendAndWait(type, body, timeoutMs = 30000) {
    const id = `urn:uuid:${randomUuid()}`;
    const inner = {
      id,
      typ: "application/didcomm-plain+json",
      type,
      from: this.client.did,
      to: [this.vtaDid],
      created_time: Math.floor(Date.now() / 1000),
      body: body ?? {},
    };

    const senderForPack = {
      kid: this.client.kid,
      privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
    };

    // 1. authcrypt the inner message to the VTA.
    const innerJwe = await pack({
      message: inner,
      sender: senderForPack,
      recipient: { kid: this.vta.kid, publicJwk: jwk.publicJwk("X25519", this.vta.x25519Pub) },
    });

    // 2. wrap in forward, authcrypt to the mediator.
    const forward = buildForward({
      next: this.vtaDid,
      from: this.client.did,
      mediatorDid: this.mediatorDid,
      innerJwe,
    });
    const forwardJwe = await pack({
      message: forward,
      sender: senderForPack,
      recipient: {
        kid: this.session.mediator.kid,
        publicJwk: jwk.publicJwk("X25519", this.session.mediator.x25519Pub),
      },
    });

    // 3. send + await the response correlated by thid == inner.id.
    //    Register the waiter BEFORE sending to avoid a race where the
    //    response arrives before waitFor is called.
    const waiter = this.session.waitFor(id, timeoutMs);
    this.session.send(forwardJwe);
    return waiter;
  }

  close() {
    this.session.close();
  }
}

// ─── Internals ──────────────────────────────────────────────────────────

/**
 * Resolve a DID and extract its first X25519 keyAgreement key.
 * @param {string} did
 * @returns {Promise<{ kid: string, x25519Pub: Uint8Array }>}
 */
export async function resolveX25519KeyAgreement(did) {
  const { didDocument } = await resolveDid(did);
  if (!didDocument || typeof didDocument !== "object") {
    throw new Error(`vta-didcomm: could not resolve a DID document for ${did}`);
  }
  const ka = didDocument.keyAgreement;
  if (!ka || ka.length === 0) {
    throw new Error(`vta-didcomm: ${did} has no keyAgreement entries`);
  }
  let vm = ka[0];
  if (typeof vm === "string") {
    const found = (didDocument.verificationMethod ?? []).find((v) => v.id === vm);
    if (!found) throw new Error(`vta-didcomm: keyAgreement ref ${vm} not resolvable`);
    vm = found;
  }
  if (!vm.publicKeyMultibase) {
    throw new Error("vta-didcomm: keyAgreement entry has no publicKeyMultibase");
  }
  const { codec, key } = multibase.decodeMultikey(vm.publicKeyMultibase);
  if (codec[0] !== 0xec || codec[1] !== 0x01) {
    throw new Error(
      `vta-didcomm: keyAgreement not X25519 (multicodec 0x${codec[0].toString(16)}${codec[1].toString(16)})`,
    );
  }
  return { kid: vm.id, x25519Pub: key };
}

function defaultClientKid(did, x25519Public) {
  const mb = multibase.encodeMultikey(multibase.MULTICODEC.X25519_PUB, x25519Public);
  return `${did}#${mb}`;
}

function randomUuid() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
