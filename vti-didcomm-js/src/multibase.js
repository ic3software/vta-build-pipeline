// Base58btc encoding + unsigned-varint multicodec prefix for the
// subset of multibase shapes we need:
//
//   - Encode/decode `did:key:z…` (raw public-key bytes prefixed with
//     a multicodec identifier, base58btc-encoded, `z` multibase prefix).
//   - Encode/decode `publicKeyMultibase` values on a DID document.
//
// Multicodec table reference (the ones we touch):
//
//   Ed25519 public key   0xed → varint 0xed 0x01
//   X25519 public key    0xec → varint 0xec 0x01
//   P-256 public key     0x1200 → varint 0x80 0x24
//
// Reference: https://github.com/multiformats/multibase
//            https://github.com/multiformats/multicodec/blob/master/table.csv

const B58 =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Multicodec varints we expect to encounter, in the bytewise shape
// they appear at the start of a `did:key` raw byte sequence.
export const MULTICODEC = Object.freeze({
  ED25519_PUB: new Uint8Array([0xed, 0x01]),
  X25519_PUB: new Uint8Array([0xec, 0x01]),
  P256_PUB: new Uint8Array([0x80, 0x24]),
});

/**
 * Base58btc encode raw bytes. Bitcoin's flavor of base58 (no `0OIl`).
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base58btcEncode(bytes) {
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let s = "";
  for (let i = 0; i < zeros; i++) s += "1";
  for (let i = digits.length - 1; i >= 0; i--) s += B58[digits[i]];
  return s;
}

/**
 * Base58btc decode a string back to bytes.
 *
 * @param {string} s
 * @returns {Uint8Array}
 * @throws {Error} on invalid characters.
 */
export function base58btcDecode(s) {
  if (typeof s !== "string") {
    throw new TypeError(`base58btcDecode expects a string`);
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  const bytes = [];
  for (let i = zeros; i < s.length; i++) {
    let carry = B58_LOOKUP[s.charCodeAt(i)];
    if (carry === undefined) {
      throw new Error(`base58btcDecode: invalid char ${JSON.stringify(s[i])} at ${i}`);
    }
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = bytes.length - 1, j = zeros; i >= 0; i--, j++) {
    out[j] = bytes[i];
  }
  return out;
}

const B58_LOOKUP = (() => {
  const t = new Array(128);
  for (let i = 0; i < B58.length; i++) {
    t[B58.charCodeAt(i)] = i;
  }
  return t;
})();

/**
 * Build a multibase-encoded multikey from raw key bytes and a
 * multicodec varint prefix.
 *
 * Example: an Ed25519 public key `pk` becomes
 *   `"z" + base58btcEncode([0xed, 0x01, ...pk])`.
 *
 * @param {Uint8Array} multicodecVarint - one of the constants in `MULTICODEC`
 * @param {Uint8Array} keyBytes
 * @returns {string} the `z…` multibase string
 */
export function encodeMultikey(multicodecVarint, keyBytes) {
  const buf = new Uint8Array(multicodecVarint.length + keyBytes.length);
  buf.set(multicodecVarint, 0);
  buf.set(keyBytes, multicodecVarint.length);
  return "z" + base58btcEncode(buf);
}

/**
 * Decode a multibase multikey string into `{ codec, key }`.
 *
 * @param {string} s - a `z…` multibase string
 * @returns {{ codec: Uint8Array, key: Uint8Array }}
 * @throws {Error} on malformed input.
 */
export function decodeMultikey(s) {
  if (typeof s !== "string" || !s.startsWith("z")) {
    throw new Error("multikey: must be base58btc multibase (starts with 'z')");
  }
  const raw = base58btcDecode(s.slice(1));
  // Read the unsigned varint at the start. We only care about the
  // 2-byte forms we use (0xed01, 0xec01, 0x8024); a general reader
  // would loop while the high bit is set.
  let codecLen = 0;
  for (let i = 0; i < raw.length; i++) {
    codecLen++;
    if ((raw[i] & 0x80) === 0) break;
  }
  return {
    codec: raw.slice(0, codecLen),
    key: raw.slice(codecLen),
  };
}
