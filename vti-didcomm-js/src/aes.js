// AES primitives via Web Crypto. No dependencies, native everywhere
// modern (Node 16+, all browsers since ~2018).
//
// Used by authcrypt JWE for the key-wrapping step only — content
// encryption is A256CBC-HS512, which lives in `a256cbc-hs512.js`.
// (Earlier revisions of this file shipped A256GCM helpers; those
// were removed when we switched to the algorithm DIDComm v2 mandates.)
//
// AES-256-KW (RFC 3394) wraps the 64-byte CEK with the 32-byte KEK
// derived from ECDH-1PU. Output is the CEK length + 8 bytes (one
// extra block of integrity check).
//
// Inner-key gotcha: Web Crypto's `wrapKey` takes a CryptoKey, not
// raw bytes. AES-GCM CryptoKeys are restricted to 128/192/256-bit
// lengths, so they can't hold a 64-byte A256CBC-HS512 CEK. We
// import the CEK as an HMAC key instead — HMAC accepts arbitrary
// key lengths — and target HMAC on unwrap as well.

/**
 * AES-256-KW (RFC 3394) wrap.
 *
 * @param {Uint8Array} kek - 32 bytes
 * @param {Uint8Array} cek - the key to wrap (64 bytes for A256CBC-HS512)
 * @returns {Promise<Uint8Array>} cek.length + 8 bytes
 */
export async function wrapKey(kek, cek) {
  assertBytes("kek", kek, 32);
  assertBytes("cek", cek);
  const kekKey = await importKekForKw(kek, ["wrapKey"]);
  const cekKey = await importInnerKey(cek);
  const wrapped = await crypto.subtle.wrapKey("raw", cekKey, kekKey, "AES-KW");
  return new Uint8Array(wrapped);
}

/**
 * AES-256-KW unwrap.
 *
 * @param {Uint8Array} kek - 32 bytes
 * @param {Uint8Array} wrapped - the wrapped CEK bytes
 * @returns {Promise<Uint8Array>} the original CEK
 */
export async function unwrapKey(kek, wrapped) {
  assertBytes("kek", kek, 32);
  assertBytes("wrapped", wrapped);
  const kekKey = await importKekForKw(kek, ["unwrapKey"]);
  // Target HMAC/SHA-256 because HMAC keys accept any length —
  // important when the inner CEK is 64 bytes (A256CBC-HS512).
  // The unwrapped key comes out as a CryptoKey; export to raw
  // bytes so the caller can hand it to the content-encryption
  // helper.
  const cekKey = await crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    kekKey,
    "AES-KW",
    { name: "HMAC", hash: "SHA-256", length: (wrapped.length - 8) * 8 },
    /* extractable */ true,
    ["sign", "verify"],
  );
  const raw = await crypto.subtle.exportKey("raw", cekKey);
  return new Uint8Array(raw);
}

async function importKekForKw(kek, usages) {
  return crypto.subtle.importKey(
    "raw",
    kek,
    { name: "AES-KW", length: 256 },
    /* extractable */ false,
    usages,
  );
}

// Import the CEK as an HMAC key purely as a vehicle for AES-KW
// wrap. HMAC accepts any byte length; AES-GCM doesn't — and we
// don't care what the inner algorithm is because AES-KW only ships
// the raw bytes.
async function importInnerKey(bytes) {
  return crypto.subtle.importKey(
    "raw",
    bytes,
    { name: "HMAC", hash: "SHA-256", length: bytes.length * 8 },
    /* extractable */ true,
    ["sign", "verify"],
  );
}

function assertBytes(name, value, exactLen) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
  if (exactLen !== undefined && value.length !== exactLen) {
    throw new Error(`${name} must be ${exactLen} bytes, got ${value.length}`);
  }
}
