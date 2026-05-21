// DIDComm v2 routing — `https://didcomm.org/routing/2.0/forward`.
//
// A forward envelope wraps an already-encrypted message (the inner
// JWE addressed to the final recipient) so a mediator can relay it
// without being able to read it. The mediator reads `body.next` to
// learn the next hop and pulls the inner JWE out of the single
// attachment.
//
// Shape (matches affinidi-messaging-didcomm's `wrap_in_forward`):
//
//   {
//     "id": "...", "typ": "application/didcomm-plain+json",
//     "type": "https://didcomm.org/routing/2.0/forward",
//     "from": "<client_did>",        // present because we authcrypt
//     "to": ["<mediator_did>"],
//     "body": { "next": "<recipient_did>" },
//     "attachments": [{ "data": { "json": <inner JWE object> } }]
//   }
//
// This plaintext is then authcrypt-packed to the mediator (the
// mediator unpacks it, reads `next`, extracts the attachment, and
// queues/relays the inner JWE to `next`). The inner JWE stays
// authcrypt'd to the final recipient, so the mediator never sees the
// plaintext it carries.

const FORWARD_MESSAGE_TYPE = "https://didcomm.org/routing/2.0/forward";

/**
 * Build a `routing/2.0/forward` plaintext message wrapping an inner
 * encrypted JWE. The result is NOT yet packed — the caller
 * authcrypt-packs it to the mediator.
 *
 * @param {Object} args
 * @param {string} args.next - the DID of the next hop (final recipient).
 * @param {string} args.from - the client/sender DID (for authcrypt).
 * @param {string} args.mediatorDid - the mediator DID (the forward's `to`).
 * @param {string|Object} args.innerJwe - the already-packed inner JWE,
 *   as a JSON string or parsed object. Embedded verbatim in the
 *   attachment.
 * @returns {Object} the forward plaintext message, ready to pack.
 */
export function buildForward({ next, from, mediatorDid, innerJwe }) {
  assertNonEmptyString("next", next);
  // `from` + `mediatorDid` are optional: omit them for an ANONCRYPT
  // forward (the standard DIDComm shape — the mediator is the
  // recipient via the JWE encryption, not the plaintext `to`, and an
  // anoncrypt forward carries no sender). Supply them for an
  // AUTHCRYPT forward, where the sender is bound and `to` names the
  // mediator. If one is given, both must be.
  const hasFrom = from !== undefined && from !== null;
  const hasMediator = mediatorDid !== undefined && mediatorDid !== null;
  if (hasFrom !== hasMediator) {
    throw new TypeError("buildForward: pass both `from` and `mediatorDid`, or neither");
  }
  if (hasFrom) {
    assertNonEmptyString("from", from);
    assertNonEmptyString("mediatorDid", mediatorDid);
  }

  let inner;
  if (typeof innerJwe === "string") {
    try {
      inner = JSON.parse(innerJwe);
    } catch (e) {
      throw new Error(`buildForward: innerJwe is not valid JSON: ${e.message}`);
    }
  } else if (innerJwe && typeof innerJwe === "object") {
    inner = innerJwe;
  } else {
    throw new TypeError("buildForward: innerJwe must be a JWE JSON string or object");
  }

  const message = {
    id: `urn:uuid:${randomUuid()}`,
    typ: "application/didcomm-plain+json",
    type: FORWARD_MESSAGE_TYPE,
    body: { next },
    attachments: [{ data: { json: inner } }],
  };
  if (hasFrom) {
    message.from = from;
    message.to = [mediatorDid];
  }
  return message;
}

export { FORWARD_MESSAGE_TYPE };

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

function assertNonEmptyString(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`buildForward: ${name} must be a non-empty string`);
  }
}
