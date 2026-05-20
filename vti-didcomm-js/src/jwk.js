// JWK ↔ raw byte conversions for the curves we use:
//
//   - X25519 (key-agreement, kty=OKP, crv=X25519)
//   - Ed25519 (signing, kty=OKP, crv=Ed25519)
//
// Both are OKP per RFC 8037. Public JWK has `x`; private JWK adds `d`.
// All values are base64url-encoded raw curve bytes (32 bytes each).
//
// We deliberately don't ship general JWK support — no EC (P-256),
// no RSA, no symmetric keys. Future curve additions land here.

import * as b64u from "./base64url.js";

/** @typedef {{ kty: "OKP", crv: "X25519" | "Ed25519", x: string, d?: string, kid?: string }} OkpJwk */

const OKP_CURVES = new Set(["X25519", "Ed25519"]);

/**
 * Build a public OKP JWK from raw key bytes.
 *
 * @param {"X25519" | "Ed25519"} crv
 * @param {Uint8Array} keyBytes - 32 raw curve bytes
 * @param {string} [kid] - optional `kid` to attach
 * @returns {OkpJwk}
 */
export function publicJwk(crv, keyBytes, kid) {
  assertCurve(crv);
  if (keyBytes.length !== 32) {
    throw new Error(`${crv} public key must be 32 bytes, got ${keyBytes.length}`);
  }
  const jwk = { kty: "OKP", crv, x: b64u.encode(keyBytes) };
  if (kid) jwk.kid = kid;
  return jwk;
}

/**
 * Build a private OKP JWK from raw private + public key bytes.
 *
 * @param {"X25519" | "Ed25519"} crv
 * @param {Uint8Array} privateBytes - 32 raw scalar bytes (d)
 * @param {Uint8Array} publicBytes - 32 raw curve bytes (x)
 * @param {string} [kid]
 * @returns {OkpJwk}
 */
export function privateJwk(crv, privateBytes, publicBytes, kid) {
  const pub = publicJwk(crv, publicBytes, kid);
  if (privateBytes.length !== 32) {
    throw new Error(`${crv} private key must be 32 bytes, got ${privateBytes.length}`);
  }
  return { ...pub, d: b64u.encode(privateBytes) };
}

/**
 * Extract raw public-key bytes from an OKP JWK.
 *
 * @param {OkpJwk} jwk
 * @returns {Uint8Array}
 */
export function rawPublic(jwk) {
  assertOkpShape(jwk);
  const bytes = b64u.decode(jwk.x);
  if (bytes.length !== 32) {
    throw new Error(`${jwk.crv} JWK 'x' must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Extract raw private-key bytes from an OKP JWK. Throws if `d` is
 * absent (caller passed a public-only JWK by mistake).
 *
 * @param {OkpJwk} jwk
 * @returns {Uint8Array}
 */
export function rawPrivate(jwk) {
  assertOkpShape(jwk);
  if (!jwk.d) {
    throw new Error("OKP JWK has no 'd' — this is a public-only key");
  }
  const bytes = b64u.decode(jwk.d);
  if (bytes.length !== 32) {
    throw new Error(`${jwk.crv} JWK 'd' must decode to 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Strip private material from a JWK, leaving only the public
 * portion. Useful when building the `epk` (ephemeral public key)
 * field for a JWE — we hold an X25519 keypair and the JWE only
 * includes the public side.
 *
 * @param {OkpJwk} jwk
 * @returns {OkpJwk}
 */
export function toPublic(jwk) {
  assertOkpShape(jwk);
  const out = { kty: "OKP", crv: jwk.crv, x: jwk.x };
  if (jwk.kid) out.kid = jwk.kid;
  return out;
}

function assertCurve(crv) {
  if (!OKP_CURVES.has(crv)) {
    throw new Error(`unsupported OKP curve: ${crv}. Expected one of ${[...OKP_CURVES].join(", ")}`);
  }
}

function assertOkpShape(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new TypeError("JWK must be an object");
  }
  if (jwk.kty !== "OKP") {
    throw new Error(`JWK kty must be 'OKP', got ${JSON.stringify(jwk.kty)}`);
  }
  assertCurve(jwk.crv);
  if (typeof jwk.x !== "string") {
    throw new Error("JWK 'x' must be a string");
  }
}
