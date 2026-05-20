// X25519 key agreement primitive — wraps `@noble/curves` for the
// browser/Node universal path.
//
// Web Crypto added native X25519 support relatively recently
// (Chrome 132, Firefox 130, Safari 17.4). The B0 design note keeps
// `@noble/curves` as the baseline so older browsers Just Work; a
// future optimisation could route to `crypto.subtle.deriveBits`
// when the API is detected.

import { x25519 } from "@noble/curves/ed25519.js";

/**
 * Generate a fresh X25519 keypair from the OS CSPRNG.
 *
 * @returns {{ privateKey: Uint8Array, publicKey: Uint8Array }}
 */
export function generateKeyPair() {
  const { secretKey, publicKey } = x25519.keygen();
  // `secretKey` and `publicKey` are already Uint8Arrays of length 32.
  return { privateKey: secretKey, publicKey };
}

/**
 * Derive the X25519 public key for a 32-byte secret scalar.
 *
 * @param {Uint8Array} privateKey - 32 bytes
 * @returns {Uint8Array} the corresponding public key (32 bytes)
 */
export function publicKeyFrom(privateKey) {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new TypeError("X25519 privateKey must be 32 bytes");
  }
  return x25519.getPublicKey(privateKey);
}

/**
 * Compute the X25519 shared secret between a private key and a
 * peer's public key.
 *
 * @param {Uint8Array} privateKey - 32 bytes
 * @param {Uint8Array} peerPublicKey - 32 bytes
 * @returns {Uint8Array} the 32-byte shared secret
 *
 * Returns the raw scalar-multiplication output without any KDF
 * applied. ECDH-1PU expects this raw form; the KDF runs separately
 * via `concat-kdf.js`.
 */
export function sharedSecret(privateKey, peerPublicKey) {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new TypeError("X25519 privateKey must be 32 bytes");
  }
  if (!(peerPublicKey instanceof Uint8Array) || peerPublicKey.length !== 32) {
    throw new TypeError("X25519 peerPublicKey must be 32 bytes");
  }
  return x25519.getSharedSecret(privateKey, peerPublicKey);
}
