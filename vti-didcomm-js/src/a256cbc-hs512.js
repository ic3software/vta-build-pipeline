// A256CBC-HS512 authenticated encryption (RFC 7518 §5.2.5).
//
// Composite AEAD: AES-256-CBC for confidentiality + HMAC-SHA-512
// (truncated to 256 bits) for authenticity. DIDComm v2's required-to-
// implement content-encryption algorithm; matches what
// affinidi-messaging-didcomm uses.
//
// CEK layout (64 bytes total):
//   - bytes 0..32   → HMAC-SHA-512 key (`macKey`)
//   - bytes 32..64  → AES-256-CBC key (`encKey`)
//
// Tag computation (RFC 7518 §5.2.2.1):
//   AL = uint64_be(bitLen(aad))
//   tagInput = aad || iv || ciphertext || AL
//   fullTag  = HMAC-SHA-512(macKey, tagInput)
//   tag      = fullTag[0..32]    (truncate to 32 bytes)
//
// All primitives via Web Crypto — no AES or HMAC implementation here.

const CEK_BYTES = 64;
const IV_BYTES = 16;
const TAG_BYTES = 32;

/**
 * Encrypt under A256CBC-HS512.
 *
 * @param {Object} args
 * @param {Uint8Array} args.cek         - 64 bytes
 * @param {Uint8Array} args.iv          - 16 bytes
 * @param {Uint8Array} args.aad         - additional auth data (typically
 *                                         the ASCII base64url protected header)
 * @param {Uint8Array} args.plaintext
 * @returns {Promise<{ ciphertext: Uint8Array, tag: Uint8Array }>}
 */
export async function encrypt({ cek, iv, aad, plaintext }) {
  assertBytes("cek", cek, CEK_BYTES);
  assertBytes("iv", iv, IV_BYTES);
  assertBytes("aad", aad);
  assertBytes("plaintext", plaintext);

  const macKey = cek.subarray(0, 32);
  const encKey = cek.subarray(32, 64);

  const ciphertext = await aesCbcEncrypt(encKey, iv, plaintext);
  const tag = await hmacTag(macKey, aad, iv, ciphertext);
  return { ciphertext, tag };
}

/**
 * Decrypt under A256CBC-HS512. Throws on tag-verification failure.
 *
 * @param {Object} args
 * @param {Uint8Array} args.cek
 * @param {Uint8Array} args.iv
 * @param {Uint8Array} args.aad
 * @param {Uint8Array} args.ciphertext
 * @param {Uint8Array} args.tag - 32 bytes
 * @returns {Promise<Uint8Array>} plaintext
 */
export async function decrypt({ cek, iv, aad, ciphertext, tag }) {
  assertBytes("cek", cek, CEK_BYTES);
  assertBytes("iv", iv, IV_BYTES);
  assertBytes("aad", aad);
  assertBytes("ciphertext", ciphertext);
  assertBytes("tag", tag, TAG_BYTES);

  const macKey = cek.subarray(0, 32);
  const encKey = cek.subarray(32, 64);

  // Verify the tag BEFORE decrypting — encrypt-then-MAC ordering
  // means the MAC covers the ciphertext, and a tampered ciphertext
  // is detected by the tag check.
  const expectedTag = await hmacTag(macKey, aad, iv, ciphertext);
  if (!constantTimeEqual(expectedTag, tag)) {
    throw new Error("A256CBC-HS512: authentication tag mismatch");
  }
  return aesCbcDecrypt(encKey, iv, ciphertext);
}

/**
 * Generate a fresh 64-byte CEK + 16-byte IV.
 *
 * @returns {{ cek: Uint8Array, iv: Uint8Array }}
 */
export function generateCekAndIv() {
  const cek = new Uint8Array(CEK_BYTES);
  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(cek);
  crypto.getRandomValues(iv);
  return { cek, iv };
}

// ─── Internals ─────────────────────────────────────────────────────────

async function aesCbcEncrypt(encKey, iv, plaintext) {
  const key = await crypto.subtle.importKey(
    "raw",
    encKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, plaintext);
  return new Uint8Array(ct);
}

async function aesCbcDecrypt(encKey, iv, ciphertext) {
  const key = await crypto.subtle.importKey(
    "raw",
    encKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"],
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
  return new Uint8Array(pt);
}

async function hmacTag(macKey, aad, iv, ciphertext) {
  // AL = bitlen(aad) as a 64-bit big-endian.
  const aadBitsBe = uint64beBitLen(aad.length);
  const macInput = concat(aad, iv, ciphertext, aadBitsBe);
  const key = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, macInput));
  return sig.subarray(0, TAG_BYTES); // first 32 bytes per RFC 7518 §5.2.2.1
}

/** Encode (length-in-BYTES * 8) as a 64-bit big-endian Uint8Array. */
function uint64beBitLen(byteLen) {
  // `BigInt` keeps us correct for AAD > 2^29 bytes (multiplying
  // a JS Number by 8 starts losing precision around 2^50 anyway,
  // but the BigInt path is correct for any input size).
  const bits = BigInt(byteLen) * 8n;
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(bits >> BigInt((7 - i) * 8)) & 0xff;
  }
  return out;
}

function concat(...parts) {
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

/**
 * Constant-time equality for two byte arrays. Returns false on
 * length mismatch (early — length itself isn't secret).
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}

function assertBytes(name, value, exactLen) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
  if (exactLen !== undefined && value.length !== exactLen) {
    throw new Error(`${name} must be ${exactLen} bytes, got ${value.length}`);
  }
}
