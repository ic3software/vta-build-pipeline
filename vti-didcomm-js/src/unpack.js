// Authcrypt JWE unpack — reverse of `pack.js`.
//
// Inputs the recipient holds:
//   - Their `kid` (so they know which `recipients[]` entry to use).
//   - Their X25519 private key.
//   - The sender's X25519 public key (looked up by `skid` from the
//     JWE protected header). This module takes the resolved public
//     key as a parameter so DID resolution is the caller's concern
//     (see B3 for the resolver).
//
// Unpack steps:
//
//   1. Parse the JWE JSON.
//   2. Decode + validate the protected header.
//   3. Find the recipients[] entry matching our kid.
//   4. Derive the KEK via recipient-side ECDH-1PU.
//   5. Unwrap the CEK with AES-KW.
//   6. AES-GCM decrypt the ciphertext with the CEK + AAD=protected.
//   7. Parse the plaintext as JSON; return { message, senderKid }.

import * as aes from "./aes.js";
import * as b64u from "./base64url.js";
import * as ecdh1pu from "./ecdh-1pu.js";
import * as jwk from "./jwk.js";

const ALG = "ECDH-1PU+A256KW";
const ENC = "A256GCM";

/**
 * Unpack an authcrypt JWE.
 *
 * @param {string} jweJson - JWE as a JSON string
 * @param {Object} recipient - `{ kid, privateJwk }`
 * @param {Object} sender    - `{ publicJwk }` — the sender's X25519
 *   public key, resolved out-of-band from `skid` in the JWE header.
 * @returns {Promise<{ message: Object, senderKid: string }>}
 */
export async function unpack(jweJson, recipient, sender) {
  if (typeof jweJson !== "string") {
    throw new TypeError("unpack: jweJson must be a string");
  }
  if (!recipient?.kid || !recipient?.privateJwk) {
    throw new TypeError("unpack: recipient.{kid, privateJwk} required");
  }
  if (!sender?.publicJwk) {
    throw new TypeError("unpack: sender.publicJwk required");
  }

  let jwe;
  try {
    jwe = JSON.parse(jweJson);
  } catch (e) {
    throw new Error(`unpack: not a JSON document: ${e.message}`);
  }
  assertJweShape(jwe);

  // 1. Decode + validate the protected header.
  const protectedB64 = jwe.protected;
  const protectedBytes = b64u.decode(protectedB64);
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(protectedBytes));
  } catch (e) {
    throw new Error(`unpack: protected header not JSON: ${e.message}`);
  }

  if (header.alg !== ALG) {
    throw new Error(`unpack: unsupported alg ${JSON.stringify(header.alg)}; expected ${ALG}`);
  }
  if (header.enc !== ENC) {
    throw new Error(`unpack: unsupported enc ${JSON.stringify(header.enc)}; expected ${ENC}`);
  }
  if (!header.epk || header.epk.kty !== "OKP" || header.epk.crv !== "X25519") {
    throw new Error(`unpack: epk must be OKP/X25519`);
  }
  if (!header.skid) {
    throw new Error("unpack: protected header missing skid");
  }

  // 2. Find our recipients[] entry. Single-recipient mode in this
  //    implementation — but the JWE structure carries an array, so
  //    handle either an exact kid match or (for compatibility) the
  //    first entry when there's exactly one and no kid header on it.
  const recipientEntry = jwe.recipients.find(
    (r) => r?.header?.kid === recipient.kid,
  );
  if (!recipientEntry) {
    throw new Error(
      `unpack: no recipients[] entry for kid ${JSON.stringify(recipient.kid)}`,
    );
  }
  if (!recipientEntry.encrypted_key) {
    throw new Error("unpack: matched recipients[] entry has no encrypted_key");
  }

  // 3. Derive the KEK via recipient-side ECDH-1PU.
  const recipientPriv = jwk.rawPrivate(recipient.privateJwk);
  const ephemeralPublic = b64u.decode(header.epk.x);
  if (ephemeralPublic.length !== 32) {
    throw new Error(`unpack: epk.x must decode to 32 bytes, got ${ephemeralPublic.length}`);
  }
  const senderPublic = jwk.rawPublic(sender.publicJwk);

  // The KDF inputs use the RAW apu/apv bytes (NOT the base64url
  // strings on the wire). Decode here.
  const apuBytes = header.apu ? b64u.decode(header.apu) : new Uint8Array();
  const apvBytes = header.apv ? b64u.decode(header.apv) : new Uint8Array();

  const kek = await ecdh1pu.recipientKekAuthcrypt({
    recipientPrivate: recipientPriv,
    ephemeralPublic,
    senderPublic,
    alg: ALG,
    apu: apuBytes,
    apv: apvBytes,
  });

  // 4. Unwrap the CEK.
  const encryptedKey = b64u.decode(recipientEntry.encrypted_key);
  const cek = await aes.unwrapKey(kek, encryptedKey);

  // 5. AES-GCM decrypt. AAD is the ASCII bytes of the base64url
  //    protected header — same encoding as the sender used.
  const iv = b64u.decode(jwe.iv);
  const ciphertext = b64u.decode(jwe.ciphertext);
  const tag = b64u.decode(jwe.tag);
  const aad = new TextEncoder().encode(protectedB64);

  let plaintext;
  try {
    plaintext = await aes.aesGcmDecrypt({
      key: cek,
      iv,
      aad,
      ciphertext,
      tag,
    });
  } catch (e) {
    throw new Error(`unpack: AES-GCM decrypt failed: ${e.message}`);
  } finally {
    cek.fill(0);
    kek.fill(0);
  }

  // 6. Parse the plaintext.
  let message;
  try {
    message = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (e) {
    throw new Error(`unpack: plaintext not JSON: ${e.message}`);
  }

  return { message, senderKid: header.skid };
}

function assertJweShape(jwe) {
  if (!jwe || typeof jwe !== "object") {
    throw new Error("unpack: JWE must be a JSON object");
  }
  for (const field of ["protected", "recipients", "iv", "ciphertext", "tag"]) {
    if (typeof jwe[field] === "undefined") {
      throw new Error(`unpack: JWE missing field ${JSON.stringify(field)}`);
    }
  }
  if (!Array.isArray(jwe.recipients) || jwe.recipients.length === 0) {
    throw new Error("unpack: recipients must be a non-empty array");
  }
}
