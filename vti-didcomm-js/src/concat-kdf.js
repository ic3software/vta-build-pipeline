// NIST SP 800-56A §5.8.1 Concatenation KDF (single-step KDF using
// SHA-256), as used by ECDH-ES and ECDH-1PU in JOSE (RFC 7518 §4.6).
//
// Formula:
//
//   KDF(Z, OtherInfo, keyDataLen):
//     reps = ceil(keyDataLen / hashLen)
//     for i = 1 to reps:
//       counter = uint32_be(i)
//       K_i = H(counter || Z || OtherInfo)
//     DerivedKeyingMaterial = leftmost(K_1 || K_2 || ... || K_reps, keyDataLen)
//
// For JOSE the convention is:
//
//   OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo [|| SuppPrivInfo]
//   AlgorithmID = lenPrefix(alg_utf8)
//   PartyUInfo = lenPrefix(apu_bytes)
//   PartyVInfo = lenPrefix(apv_bytes)
//   SuppPubInfo = uint32_be(keyDataLen_bits)
//   lenPrefix(x) = uint32_be(byteLen(x)) || x
//
// SuppPrivInfo is normally omitted, but for ECDH-1PU in
// Key-Agreement-with-Key-Wrap mode (draft-madden-jose-ecdh-1pu §2.3)
// it carries the JWE content-encryption auth tag (`cc_tag`),
// appended RAW (no length prefix — that's the convention shared by
// affinidi-messaging-didcomm, go-jose, jwx). This binds the KEK
// derivation to the ciphertext.
//
// We only support SHA-256 + JOSE OtherInfo construction — the
// specific shape ECDH-1PU+A256KW needs. A general Concat KDF would
// accept the OtherInfo bytes directly; that's a refactor away if we
// ever need it.
//
// Web Crypto's `digest("SHA-256", buf)` is the only crypto primitive
// touched here.

const HASH_LEN = 32; // SHA-256 output length

/**
 * Run the JOSE-flavored Concat KDF and produce a key of
 * `keyDataLenBits / 8` bytes.
 *
 * @param {Uint8Array} z - Shared secret (Z in spec terminology).
 * @param {Object} otherInfo
 * @param {string} otherInfo.alg - e.g. `"ECDH-1PU+A256KW"`. UTF-8
 *   encoded and length-prefixed as AlgorithmID.
 * @param {Uint8Array} otherInfo.apu - Already-decoded raw bytes
 *   (NOT base64url). The caller is responsible for base64url-decoding
 *   the `apu` header value before passing it here. Empty allowed.
 * @param {Uint8Array} otherInfo.apv - Same shape as `apu`.
 * @param {Uint8Array} [otherInfo.suppPrivInfo] - Optional raw bytes
 *   appended after SuppPubInfo (NOT length-prefixed). Used by
 *   ECDH-1PU+A256KW to carry the JWE content-encryption auth tag.
 * @param {number} keyDataLenBits - Number of bits of derived
 *   keying material to produce. Must be a multiple of 8 and ≤ 4096
 *   (defensive cap to catch order-of-magnitude bugs).
 * @returns {Promise<Uint8Array>}
 */
export async function deriveKey(z, { alg, apu, apv, suppPrivInfo }, keyDataLenBits) {
  if (!(z instanceof Uint8Array)) {
    throw new TypeError("ConcatKDF: Z must be Uint8Array");
  }
  if (typeof alg !== "string" || alg.length === 0) {
    throw new TypeError("ConcatKDF: alg must be a non-empty string");
  }
  if (!(apu instanceof Uint8Array) || !(apv instanceof Uint8Array)) {
    throw new TypeError("ConcatKDF: apu and apv must be Uint8Array");
  }
  if (suppPrivInfo !== undefined && !(suppPrivInfo instanceof Uint8Array)) {
    throw new TypeError("ConcatKDF: suppPrivInfo must be Uint8Array if provided");
  }
  if (
    typeof keyDataLenBits !== "number" ||
    keyDataLenBits <= 0 ||
    keyDataLenBits % 8 !== 0 ||
    keyDataLenBits > 4096
  ) {
    throw new Error(
      `ConcatKDF: keyDataLenBits must be a positive multiple of 8 ≤ 4096; got ${keyDataLenBits}`,
    );
  }
  const keyDataLenBytes = keyDataLenBits / 8;

  const algBytes = new TextEncoder().encode(alg);
  const otherInfo = concatenate(
    lengthPrefix(algBytes),
    lengthPrefix(apu),
    lengthPrefix(apv),
    uint32be(keyDataLenBits),
    suppPrivInfo ?? new Uint8Array(),
  );

  const reps = Math.ceil(keyDataLenBytes / HASH_LEN);
  const out = new Uint8Array(reps * HASH_LEN);
  for (let i = 1; i <= reps; i++) {
    const input = concatenate(uint32be(i), z, otherInfo);
    const digest = await crypto.subtle.digest("SHA-256", input);
    out.set(new Uint8Array(digest), (i - 1) * HASH_LEN);
  }
  return out.subarray(0, keyDataLenBytes);
}

/**
 * Encode `n` as a 32-bit big-endian Uint8Array.
 *
 * @param {number} n
 * @returns {Uint8Array}
 */
export function uint32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`uint32be: out of range: ${n}`);
  }
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

/**
 * `lenPrefix(x) = uint32_be(byteLen(x)) || x` per the JOSE
 * Concat KDF OtherInfo construction.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function lengthPrefix(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  out.set(uint32be(bytes.length), 0);
  out.set(bytes, 4);
  return out;
}

/**
 * Concatenate any number of byte arrays into one.
 *
 * @param  {...Uint8Array} parts
 * @returns {Uint8Array}
 */
export function concatenate(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
