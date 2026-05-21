// Mediator WebSocket transport — message-pickup 3.0 live delivery.
//
// Flow once authenticated (see `mediator-auth.js`):
//   1. Open a browser WebSocket to the mediator's wss endpoint, with
//      the mediator JWT carried as a subprotocol: `["bearer.<jwt>"]`
//      (browsers can't set an Authorization header on a WebSocket;
//      the mediator accepts the bearer subprotocol as an additive,
//      backwards-compatible auth channel alongside the header path
//      that Rust clients use).
//   2. Send a `messagepickup/3.0/live-delivery-change` ({live_delivery:
//      true}, with a top-level `return_route: "all"`), authcrypt'd to
//      the mediator. This tells the mediator to push messages destined
//      for our DID over this socket as they arrive.
//   3. Send the `routing/2.0/forward` (authcrypt'd to the mediator,
//      `next` = VTA) as a WS text frame. The mediator unwraps it,
//      relays the inner JWE to the VTA, and the VTA's response comes
//      back addressed to us.
//   4. The mediator stores the (already-unwrapped) inner response JWE
//      and pushes it over the socket as a raw text frame. We unpack it
//      directly — the mediator does NOT re-wrap it in a forward on
//      live delivery.
//
// Inbound dispatch: frames can come from the VTA (the response,
// authcrypt'd VTA→client) OR the mediator (status / problem-report,
// authcrypt'd mediator→client). We read `skid` from each frame's
// protected header and pick the matching sender public key from a
// seeded map (mediator + VTA), falling back to DID resolution.

import { unpack } from "./unpack.js";
import { pack } from "./pack.js";
import * as b64u from "./base64url.js";
import * as jwk from "./jwk.js";

const LIVE_DELIVERY_CHANGE_TYPE = "https://didcomm.org/messagepickup/3.0/live-delivery-change";

/**
 * Build the `live-delivery-change` plaintext that enables live
 * delivery over the current WebSocket. The caller authcrypt-packs it
 * to the mediator.
 *
 * @param {Object} args
 * @param {string} args.from - client DID
 * @param {string} args.mediatorDid - mediator DID (the `to`)
 * @param {boolean} [args.live=true]
 * @returns {Object} plaintext message, ready to pack
 */
export function buildLiveDeliveryChange({ from, mediatorDid, live = true }) {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type: LIVE_DELIVERY_CHANGE_TYPE,
    from,
    to: [mediatorDid],
    created_time: now,
    expires_time: now + 300,
    // The mediator reads `return_route: all` to mean "deliver replies
    // back over this same channel". It's a top-level message field.
    return_route: "all",
    body: { live_delivery: live },
  };
}

/**
 * Read the `skid` (sender key id) from a JWE's protected header
 * without decrypting. Returns null if absent (anoncrypt) or malformed.
 *
 * @param {string} jweString
 * @returns {string|null}
 */
export function peekSkid(jweString) {
  let jwe;
  try {
    jwe = JSON.parse(jweString);
  } catch {
    return null;
  }
  if (!jwe || typeof jwe.protected !== "string") return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64u.decode(jwe.protected)));
    return typeof header.skid === "string" ? header.skid : null;
  } catch {
    return null;
  }
}

/**
 * Unpack an inbound mediator frame, picking the sender's public key by
 * its `skid`.
 *
 * @param {string} frameString - the raw JWE text frame.
 * @param {Object} args
 * @param {Object} args.recipient - `{ kid, privateJwk }` (our X25519 key).
 * @param {Map<string,Object>} args.senderKeys - map of sender DID
 *   (the part before `#`) → `{ publicJwk }`. Seeded with the mediator
 *   and VTA keys.
 * @param {Function} [args.resolveSender] - async fallback
 *   `(did) => { publicJwk }` when `skid`'s DID isn't in `senderKeys`.
 * @returns {Promise<{ message: Object, senderKid: string }>}
 */
export async function unpackInbound(frameString, { recipient, senderKeys, resolveSender }) {
  const skid = peekSkid(frameString);
  if (!skid) {
    throw new Error("mediator-transport: inbound frame has no skid (anoncrypt not supported)");
  }
  const senderDid = skid.split("#")[0];
  let sender = senderKeys.get(senderDid);
  if (!sender && typeof resolveSender === "function") {
    sender = await resolveSender(senderDid);
  }
  if (!sender) {
    throw new Error(`mediator-transport: no sender key for ${senderDid} (skid ${skid})`);
  }
  return unpack(frameString, recipient, sender);
}

/**
 * A live mediator WebSocket session. Browser-first: uses the global
 * `WebSocket` by default, injectable for tests.
 *
 * Lifecycle: `await session.connect()` opens the socket + enables live
 * delivery; `session.send(jwe)` ships a frame; `session.waitFor(thid,
 * timeoutMs)` resolves with the first inbound message whose `thid`
 * matches; `session.close()` tears down.
 */
export class MediatorSession {
  /**
   * @param {Object} args
   * @param {{wsEndpoint:string, did:string, kid:string, x25519Pub:Uint8Array}} args.mediator
   * @param {string} args.mediatorJwt - mediator access token.
   * @param {{did:string, kid:string, privateKey:Uint8Array, publicKey:Uint8Array}} args.client
   * @param {Map<string,Object>} [args.senderKeys] - seed sender keys.
   * @param {Function} [args.resolveSender] - async sender-key fallback.
   * @param {Function} [args.WebSocketImpl] - WebSocket ctor (default global).
   */
  constructor({ mediator, mediatorJwt, client, senderKeys, resolveSender, WebSocketImpl }) {
    if (!mediator?.wsEndpoint) {
      throw new Error("MediatorSession: mediator.wsEndpoint required (mediator advertises no wss endpoint)");
    }
    this.mediator = mediator;
    this.mediatorJwt = mediatorJwt;
    this.client = client;
    this.senderKeys = senderKeys ?? new Map();
    this.resolveSender = resolveSender;
    this.WebSocketImpl = WebSocketImpl ?? globalThis.WebSocket;
    if (typeof this.WebSocketImpl !== "function") {
      throw new Error("MediatorSession: no WebSocket implementation available");
    }
    // Seed the mediator's own key so status/problem-report frames unpack.
    this.senderKeys.set(mediator.did, {
      publicJwk: jwk.publicJwk("X25519", mediator.x25519Pub),
    });

    this.ws = null;
    // Buffer of unpacked inbound messages not yet claimed by a waiter,
    // plus the set of pending waiters keyed by the thid they want.
    this._inbox = [];
    this._waiters = [];
  }

  /** Our recipient descriptor for unpack. */
  get _recipient() {
    return {
      kid: this.client.kid,
      privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
    };
  }

  /**
   * Open the socket + enable live delivery. Resolves once the socket
   * is open and the live-delivery-change has been sent.
   */
  async connect() {
    await this._openSocket();
    const change = buildLiveDeliveryChange({
      from: this.client.did,
      mediatorDid: this.mediator.did,
    });
    const packed = await pack({
      message: change,
      sender: {
        kid: this.client.kid,
        privateJwk: jwk.privateJwk("X25519", this.client.privateKey, this.client.publicKey),
      },
      recipient: {
        kid: this.mediator.kid,
        publicJwk: jwk.publicJwk("X25519", this.mediator.x25519Pub),
      },
    });
    this.ws.send(packed);
  }

  _openSocket() {
    return new Promise((resolve, reject) => {
      // Subprotocol bearer: ["bearer.<jwt>"]. The mediator reads the
      // JWT from Sec-WebSocket-Protocol when no Authorization header
      // is present (browsers can't set the header).
      const ws = new this.WebSocketImpl(this.mediator.wsEndpoint, [`bearer.${this.mediatorJwt}`]);
      this.ws = ws;
      ws.onmessage = (ev) => this._onFrame(ev.data);
      ws.onerror = (ev) => {
        if (this._waiters.length === 0) return;
        const err = new Error("mediator-transport: WebSocket error");
        for (const w of this._waiters.splice(0)) w.reject(err);
      };
      ws.onclose = () => {
        const err = new Error("mediator-transport: WebSocket closed");
        for (const w of this._waiters.splice(0)) w.reject(err);
      };
      ws.onopen = () => resolve();
      // Some WebSocket impls surface a connect failure only via onerror
      // before onopen — reject the connect promise in that window.
      const onEarlyError = () => reject(new Error("mediator-transport: WebSocket failed to open"));
      ws.addEventListener?.("error", onEarlyError, { once: true });
    });
  }

  /** Send a raw packed JWE as a WS text frame. */
  send(jweString) {
    if (!this.ws) throw new Error("mediator-transport: not connected");
    this.ws.send(jweString);
  }

  async _onFrame(data) {
    const text = typeof data === "string" ? data : new TextDecoder().decode(data);
    let result;
    try {
      result = await unpackInbound(text, {
        recipient: this._recipient,
        senderKeys: this.senderKeys,
        resolveSender: this.resolveSender,
      });
    } catch {
      // Unrelated / unparseable frame (e.g. a sender we don't know).
      // Drop it — correlation only cares about the response we await.
      return;
    }
    // Try to hand it to a matching waiter; else buffer it.
    const thid = result.message.thid ?? result.message.id;
    const idx = this._waiters.findIndex((w) => w.thid === thid);
    if (idx >= 0) {
      const [w] = this._waiters.splice(idx, 1);
      clearTimeout(w.timer);
      w.resolve(result.message);
    } else {
      this._inbox.push({ thid, message: result.message });
    }
  }

  /**
   * Wait for the first inbound message whose `thid` matches `thid`.
   * Checks already-buffered frames first.
   *
   * @param {string} thid - the request message id we're correlating to.
   * @param {number} timeoutMs
   * @returns {Promise<Object>} the unpacked response message.
   */
  waitFor(thid, timeoutMs) {
    const buffered = this._inbox.findIndex((m) => m.thid === thid);
    if (buffered >= 0) {
      const [m] = this._inbox.splice(buffered, 1);
      return Promise.resolve(m.message);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this._waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`mediator-transport: timeout waiting for response (thid ${thid})`));
      }, timeoutMs);
      this._waiters.push({ thid, resolve, reject, timer });
    });
  }

  close() {
    for (const w of this._waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(new Error("mediator-transport: session closed"));
    }
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
    this.ws = null;
  }
}

export { LIVE_DELIVERY_CHANGE_TYPE };

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
