// ECDH-ES (Ephemeral-Static) key agreement, as used by JOSE/DIDComm v2
// anoncrypt (RFC 7518 §4.6).
//
// Unlike ECDH-1PU (authcrypt), anoncrypt has NO sender static key:
//   - Z = ECDH(ephemeral, recipient)   — a single shared secret
//
// Inputs to the Concat KDF: Z (no Ze||Zs concatenation, no sender
// binding). And — unlike ECDH-1PU's key-wrap mode — anoncrypt does
// NOT fold the content-encryption tag into the KDF (no SuppPrivInfo).
//
// For DIDComm v2 anoncrypt the algorithm string is "ECDH-ES+A256KW".

import * as concatKdf from "./concat-kdf.js";
import * as x25519 from "./x25519.js";

/**
 * Derive the 256-bit KEK that wraps the CEK in an anoncrypt JWE
 * (sender side).
 *
 * @param {Object} args
 * @param {Uint8Array} args.ephemeralPrivate - 32-byte X25519 scalar
 * @param {Uint8Array} args.recipientPublic  - 32-byte X25519 public key
 * @param {string} args.alg - typically `"ECDH-ES+A256KW"`
 * @param {Uint8Array} args.apu - usually empty for anoncrypt (no sender)
 * @param {Uint8Array} args.apv
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
export async function deriveKekAnoncrypt({
  ephemeralPrivate,
  recipientPublic,
  alg,
  apu,
  apv,
}) {
  const z = x25519.sharedSecret(ephemeralPrivate, recipientPublic);
  // No SuppPrivInfo: anoncrypt's ECDH-ES KEK is independent of the
  // content tag (only ECDH-1PU+A*KW binds it).
  return concatKdf.deriveKey(z, { alg, apu, apv }, 256);
}

/**
 * Recipient-side equivalent: derive the same KEK from the ephemeral
 * public key using the recipient's private key.
 *
 * @param {Object} args
 * @param {Uint8Array} args.recipientPrivate - 32-byte X25519 scalar
 * @param {Uint8Array} args.ephemeralPublic  - 32-byte X25519 public key
 * @param {string} args.alg
 * @param {Uint8Array} args.apu
 * @param {Uint8Array} args.apv
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
export async function recipientKekAnoncrypt({
  recipientPrivate,
  ephemeralPublic,
  alg,
  apu,
  apv,
}) {
  const z = x25519.sharedSecret(recipientPrivate, ephemeralPublic);
  return concatKdf.deriveKey(z, { alg, apu, apv }, 256);
}
