// ECDH-1PU (One-Pass Unified) key agreement, as used by JOSE per
// draft-madden-jose-ecdh-1pu §2.
//
// Combines:
//   - Ze: ECDH between an EPHEMERAL key (sender-side) and the recipient
//   - Zs: ECDH between the SENDER's static key and the recipient
//
// Inputs to the Concat KDF: Z = Ze || Zs
//
// Compared to plain ECDH-ES (anoncrypt) this binds sender identity
// into the derived key — a recipient who decrypts the JWE knows the
// sender held both the ephemeral and static private keys for the
// declared `epk` + `skid`.
//
// For DIDComm v2 authcrypt the canonical algorithm string is
// "ECDH-1PU+A256KW" (RFC 7518 §4.6 Concat KDF AlgorithmID input).
//
// Key-wrap mode binding: when ECDH-1PU is paired with an A*KW key
// wrap (draft-madden-jose-ecdh-1pu §2.3), the JWE content-encryption
// auth tag is folded into the Concat KDF as SuppPrivInfo. This binds
// the KEK derivation to the ciphertext — a tampered ciphertext
// produces a different KEK, the AES-KW unwrap integrity check fails,
// and the unwrap throws before the recipient even attempts content
// decryption. Callers MUST supply `ccTag` in this mode; both sides
// have to agree byte-for-byte on the tag for the KEKs to match.

import * as concatKdf from "./concat-kdf.js";
import * as x25519 from "./x25519.js";

/**
 * Derive the 256-bit KEK that wraps the CEK in an authcrypt JWE.
 *
 * Caller responsibilities:
 * - `ephemeralPrivate` is freshly generated for this single JWE.
 * - `senderPrivate` is the sender's long-term key-agreement key
 *   (advertised on their DID document's `keyAgreement`).
 * - `apu` / `apv` are the raw byte values that the JWE protected
 *   header will base64url-encode. Common DIDComm convention:
 *     apu = utf8(sender_kid)
 *     apv = utf8(sorted_recipient_kids_joined_by_dot)  // single-recipient: just the kid
 *
 * @param {Object} args
 * @param {Uint8Array} args.ephemeralPrivate - 32-byte X25519 scalar
 * @param {Uint8Array} args.senderPrivate    - 32-byte X25519 scalar
 * @param {Uint8Array} args.recipientPublic  - 32-byte X25519 public key
 * @param {string} args.alg - typically `"ECDH-1PU+A256KW"`
 * @param {Uint8Array} args.apu
 * @param {Uint8Array} args.apv
 * @param {Uint8Array} [args.ccTag] - JWE content-encryption auth tag
 *   for key-wrap mode binding. Required for ECDH-1PU+A*KW; should be
 *   omitted for ECDH-1PU direct.
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
export async function deriveKekAuthcrypt({
  ephemeralPrivate,
  senderPrivate,
  recipientPublic,
  alg,
  apu,
  apv,
  ccTag,
}) {
  const ze = x25519.sharedSecret(ephemeralPrivate, recipientPublic);
  const zs = x25519.sharedSecret(senderPrivate, recipientPublic);
  const z = concat(ze, zs);
  return concatKdf.deriveKey(z, { alg, apu, apv, suppPrivInfo: ccTag }, 256);
}

/**
 * Recipient-side equivalent: derive the same KEK from the
 * ephemeral public key + the sender's static public key, using the
 * recipient's private key.
 *
 * Note the symmetry — `recipientPrivate` is the only secret on
 * this side; the sender's `senderPublic` arrives in the JWE's
 * `skid` after DID resolution.
 *
 * @param {Object} args
 * @param {Uint8Array} args.recipientPrivate - 32-byte X25519 scalar
 * @param {Uint8Array} args.ephemeralPublic  - 32-byte X25519 public key
 * @param {Uint8Array} args.senderPublic     - 32-byte X25519 public key
 * @param {string} args.alg
 * @param {Uint8Array} args.apu
 * @param {Uint8Array} args.apv
 * @param {Uint8Array} [args.ccTag] - JWE content-encryption auth tag
 *   for key-wrap mode binding. Same value the sender used.
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
export async function recipientKekAuthcrypt({
  recipientPrivate,
  ephemeralPublic,
  senderPublic,
  alg,
  apu,
  apv,
  ccTag,
}) {
  const ze = x25519.sharedSecret(recipientPrivate, ephemeralPublic);
  const zs = x25519.sharedSecret(recipientPrivate, senderPublic);
  const z = concat(ze, zs);
  return concatKdf.deriveKey(z, { alg, apu, apv, suppPrivInfo: ccTag }, 256);
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
