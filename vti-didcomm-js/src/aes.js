// AES primitives via Web Crypto. No dependencies, native everywhere
// modern (Node 16+, all browsers since ~2018).
//
// Two flavours used by authcrypt JWE:
//
//   - AES-256-KW (RFC 3394): wraps the CEK with the KEK derived
//     from ECDH-1PU. Output is 8 bytes longer than the CEK (one
//     extra block of integrity check).
//   - AES-256-GCM: encrypts the plaintext with the CEK, with the
//     ASCII-encoded protected header as additional authenticated
//     data. 12-byte IV per JWA, 16-byte tag appended.
//
// Web Crypto returns the GCM tag concatenated to the ciphertext;
// we split it out so the JWE structure can carry it in its
// dedicated `tag` field.

/**
 * AES-256-KW (RFC 3394) wrap.
 *
 * @param {Uint8Array} kek - 32 bytes
 * @param {Uint8Array} cek - the key to wrap (32 bytes for A256GCM)
 * @returns {Promise<Uint8Array>} cek.length + 8 bytes
 */
export async function wrapKey(kek, cek) {
  assertBytes("kek", kek, 32);
  assertBytes("cek", cek);
  // The CEK has to be a CryptoKey to be wrapped; we import it as a
  // raw symmetric key with no usages (AES-KW only cares about
  // shipping the bytes, not running them through an algorithm).
  // `"AES-GCM"` is the conventional choice for the inner-key
  // algorithm — its `extractable` requirement matches our use.
  const kekKey = await importKekForKw(kek, ["wrapKey"]);
  const cekKey = await crypto.subtle.importKey(
    "raw",
    cek,
    { name: "AES-GCM", length: cek.length * 8 },
    /* extractable */ true,
    ["encrypt", "decrypt"],
  );
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
  // The unwrapped key comes out as a CryptoKey; export to raw bytes
  // so the caller can hand it to `AES-GCM` decrypt below.
  const cekKey = await crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    kekKey,
    "AES-KW",
    { name: "AES-GCM", length: (wrapped.length - 8) * 8 },
    /* extractable */ true,
    ["encrypt", "decrypt"],
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

/**
 * AES-256-GCM encrypt with `aad` as the additional authenticated
 * data. Returns `{ ciphertext, tag }` split — Web Crypto produces
 * `ciphertext || tag`, we slice apart so the caller can write each
 * to the JWE's `ciphertext` and `tag` fields independently.
 *
 * @param {Object} args
 * @param {Uint8Array} args.key   - 32 bytes
 * @param {Uint8Array} args.iv    - 12 bytes (JWA convention for A256GCM)
 * @param {Uint8Array} args.aad   - bytes — typically the ASCII of the JWE protected header
 * @param {Uint8Array} args.plaintext
 * @returns {Promise<{ ciphertext: Uint8Array, tag: Uint8Array }>}
 */
export async function aesGcmEncrypt({ key, iv, aad, plaintext }) {
  assertBytes("key", key, 32);
  assertBytes("iv", iv, 12);
  assertBytes("aad", aad);
  assertBytes("plaintext", plaintext);
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const out = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      k,
      plaintext,
    ),
  );
  // Web Crypto AES-GCM emits ciphertext || tag (16-byte tag for
  // 128-bit tagLength). Split into separate fields.
  const tagLen = 16;
  const ciphertext = out.subarray(0, out.length - tagLen);
  const tag = out.subarray(out.length - tagLen);
  return { ciphertext, tag };
}

/**
 * AES-256-GCM decrypt. Reassembles `ciphertext || tag` for Web
 * Crypto's expectations.
 *
 * @param {Object} args
 * @param {Uint8Array} args.key
 * @param {Uint8Array} args.iv
 * @param {Uint8Array} args.aad
 * @param {Uint8Array} args.ciphertext
 * @param {Uint8Array} args.tag - 16 bytes
 * @returns {Promise<Uint8Array>} plaintext
 * @throws on auth-tag mismatch.
 */
export async function aesGcmDecrypt({ key, iv, aad, ciphertext, tag }) {
  assertBytes("key", key, 32);
  assertBytes("iv", iv, 12);
  assertBytes("aad", aad);
  assertBytes("ciphertext", ciphertext);
  assertBytes("tag", tag, 16);
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    k,
    combined,
  );
  return new Uint8Array(pt);
}

/**
 * Generate a fresh 256-bit CEK and a 96-bit IV.
 *
 * @returns {{ key: Uint8Array, iv: Uint8Array }}
 */
export function generateAes256GcmKeyAndIv() {
  const key = new Uint8Array(32);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(key);
  crypto.getRandomValues(iv);
  return { key, iv };
}

function assertBytes(name, value, exactLen) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
  if (exactLen !== undefined && value.length !== exactLen) {
    throw new Error(`${name} must be ${exactLen} bytes, got ${value.length}`);
  }
}
