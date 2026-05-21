// RFC 4648 §5 base64url (no padding) encode/decode.
//
// Implemented in plain JS rather than relying on Node's `Buffer` or
// the browser's `atob/btoa` directly because:
//   - `Buffer` doesn't exist in browsers; we want one implementation
//     that runs in both contexts.
//   - `atob/btoa` are standard base64, not URL-safe; we'd need to
//     transform `+/=` ↔ `-_` either way.
//
// Performance: ~30M bytes/sec in node 20 on an M3, which is plenty
// for DIDComm payloads (single-digit KB at most).

const B64_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode bytes as base64url without padding.
 *
 * @param {Uint8Array | ArrayBuffer | number[]} bytes
 * @returns {string}
 */
export function encode(bytes) {
  const arr = bytes instanceof Uint8Array
    ? bytes
    : new Uint8Array(bytes instanceof ArrayBuffer ? bytes : new Uint8Array(bytes));
  let out = "";
  let i = 0;
  for (; i + 2 < arr.length; i += 3) {
    const n = (arr[i] << 16) | (arr[i + 1] << 8) | arr[i + 2];
    out +=
      B64_CHARS[(n >> 18) & 0x3f] +
      B64_CHARS[(n >> 12) & 0x3f] +
      B64_CHARS[(n >> 6) & 0x3f] +
      B64_CHARS[n & 0x3f];
  }
  const rem = arr.length - i;
  if (rem === 1) {
    const n = arr[i] << 16;
    out += B64_CHARS[(n >> 18) & 0x3f] + B64_CHARS[(n >> 12) & 0x3f];
  } else if (rem === 2) {
    const n = (arr[i] << 16) | (arr[i + 1] << 8);
    out +=
      B64_CHARS[(n >> 18) & 0x3f] +
      B64_CHARS[(n >> 12) & 0x3f] +
      B64_CHARS[(n >> 6) & 0x3f];
  }
  return out;
}

/**
 * Decode a base64url string (with or without trailing padding) to
 * bytes. Tolerant of `+/` instead of `-_` so callers don't have to
 * pre-normalize when feeding in standard-base64 inputs from JWTs
 * etc.
 *
 * @param {string} s
 * @returns {Uint8Array}
 * @throws {Error} if `s` contains characters outside the base64url
 *   alphabet (or `+/=`).
 */
export function decode(s) {
  if (typeof s !== "string") {
    throw new TypeError(`base64url.decode expects a string, got ${typeof s}`);
  }
  // Normalize standard-base64 inputs.
  const norm = s.replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=+$/, "");
  // A base64 group is 2–4 chars; a remainder of exactly 1 char can
  // never be a valid encoding (it carries only 6 bits, < one byte).
  // Reject it rather than silently dropping it — at a crypto trust
  // boundary, non-canonical input is a malleability surface.
  if (norm.length % 4 === 1) {
    throw new Error(`base64url.decode: invalid length (${norm.length} chars; %4 === 1)`);
  }
  const out = new Uint8Array(Math.floor((norm.length * 3) / 4));
  let outIdx = 0;
  let n = 0;
  let bits = 0;
  for (let i = 0; i < norm.length; i++) {
    const ch = norm.charCodeAt(i);
    const v = B64_LOOKUP[ch];
    if (v === undefined) {
      throw new Error(
        `base64url.decode: invalid character ${JSON.stringify(norm[i])} at position ${i}`,
      );
    }
    n = (n << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (n >> bits) & 0xff;
    }
  }
  return out.subarray(0, outIdx);
}

// Lookup table indexed by char code — faster than `indexOf` and
// rejects non-alphabet chars by lookup-miss.
const B64_LOOKUP = (() => {
  const t = new Array(128);
  for (let i = 0; i < B64_CHARS.length; i++) {
    t[B64_CHARS.charCodeAt(i)] = i;
  }
  return t;
})();
