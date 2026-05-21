// JWE unpack — reverse of `pack.js` (authcrypt) and `anoncrypt.js`.
//
// Dispatches on the protected header's `alg`:
//   - "ECDH-1PU+A256KW" (authcrypt): sender-bound. Requires the
//     sender's X25519 public key (resolved out-of-band from `skid`).
//     The content-encryption tag is folded into the Concat KDF as
//     SuppPrivInfo, so a tampered ciphertext fails the AES-KW
//     integrity check before decryption.
//   - "ECDH-ES+A256KW" (anoncrypt): no sender. No `skid`/`apu`, no
//     SuppPrivInfo. `sender` is ignored and `senderKid` is undefined.
//
// The recipient supplies their `kid` + X25519 private key. For
// authcrypt the caller resolves the sender's public key (see the
// resolver) and passes it in.

import * as a256cbcHs512 from "./a256cbc-hs512.js";
import * as aes from "./aes.js";
import * as b64u from "./base64url.js";
import * as ecdh1pu from "./ecdh-1pu.js";
import * as ecdhEs from "./ecdh-es.js";
import * as jwk from "./jwk.js";

const ALG_AUTHCRYPT = "ECDH-1PU+A256KW";
const ALG_ANONCRYPT = "ECDH-ES+A256KW";
const ENC = "A256CBC-HS512";

/**
 * Unpack an authcrypt or anoncrypt JWE.
 *
 * @param {string} jweJson - JWE as a JSON string
 * @param {Object} recipient - `{ kid, privateJwk }`
 * @param {Object} [sender] - `{ publicJwk }` — the sender's X25519
 *   public key, required for authcrypt (ECDH-1PU), ignored for
 *   anoncrypt (ECDH-ES).
 * @returns {Promise<{ message: Object, senderKid: string|undefined, authenticated: boolean }>}
 */
export async function unpack(jweJson, recipient, sender) {
  if (typeof jweJson !== "string") {
    throw new TypeError("unpack: jweJson must be a string");
  }
  if (!recipient?.kid || !recipient?.privateJwk) {
    throw new TypeError("unpack: recipient.{kid, privateJwk} required");
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

  const isAuthcrypt = header.alg === ALG_AUTHCRYPT;
  const isAnoncrypt = header.alg === ALG_ANONCRYPT;
  if (!isAuthcrypt && !isAnoncrypt) {
    throw new Error(
      `unpack: unsupported alg ${JSON.stringify(header.alg)}; expected ${ALG_AUTHCRYPT} or ${ALG_ANONCRYPT}`,
    );
  }
  if (header.enc !== ENC) {
    throw new Error(`unpack: unsupported enc ${JSON.stringify(header.enc)}; expected ${ENC}`);
  }
  if (!header.epk || header.epk.kty !== "OKP" || header.epk.crv !== "X25519") {
    throw new Error(`unpack: epk must be OKP/X25519`);
  }
  if (isAuthcrypt && !header.skid) {
    throw new Error("unpack: authcrypt protected header missing skid");
  }
  if (isAuthcrypt && !sender?.publicJwk) {
    throw new TypeError("unpack: sender.publicJwk required for authcrypt");
  }

  // 2. Find our recipients[] entry.
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

  // 3. Read IV, ciphertext, tag. For authcrypt the tag is also the
  //    Concat KDF SuppPrivInfo, so it's needed before deriving the KEK.
  const iv = b64u.decode(jwe.iv);
  const ciphertext = b64u.decode(jwe.ciphertext);
  const tag = b64u.decode(jwe.tag);
  const aad = new TextEncoder().encode(protectedB64);

  // 4. Derive the KEK (algorithm-dependent).
  const recipientPriv = jwk.rawPrivate(recipient.privateJwk);
  const ephemeralPublic = b64u.decode(header.epk.x);
  if (ephemeralPublic.length !== 32) {
    throw new Error(`unpack: epk.x must decode to 32 bytes, got ${ephemeralPublic.length}`);
  }
  const apuBytes = header.apu ? b64u.decode(header.apu) : new Uint8Array();
  const apvBytes = header.apv ? b64u.decode(header.apv) : new Uint8Array();

  let kek;
  if (isAuthcrypt) {
    // Bind the authenticated sender identity: `apu` (which is fed into
    // the KDF) must equal utf8(skid) (which selects the sender key we
    // return as `senderKid`). Both my pack and affinidi-messaging-didcomm
    // set apu = sender_kid, so a mismatch is a malformed/forged
    // envelope. The KEK already binds both independently (a swap breaks
    // decryption), but rejecting here keeps the returned `senderKid`
    // unambiguous for callers that authorize on it.
    const apuStr = new TextDecoder().decode(apuBytes);
    if (apuStr !== header.skid) {
      throw new Error(
        `unpack: authcrypt apu (${JSON.stringify(apuStr)}) does not match skid (${JSON.stringify(header.skid)})`,
      );
    }
    kek = await ecdh1pu.recipientKekAuthcrypt({
      recipientPrivate: recipientPriv,
      ephemeralPublic,
      senderPublic: jwk.rawPublic(sender.publicJwk),
      alg: ALG_AUTHCRYPT,
      apu: apuBytes,
      apv: apvBytes,
      ccTag: tag,
    });
  } else {
    kek = await ecdhEs.recipientKekAnoncrypt({
      recipientPrivate: recipientPriv,
      ephemeralPublic,
      alg: ALG_ANONCRYPT,
      apu: apuBytes,
      apv: apvBytes,
    });
  }

  // 5. Unwrap the CEK.
  const encryptedKey = b64u.decode(recipientEntry.encrypted_key);
  const cek = await aes.unwrapKey(kek, encryptedKey);

  // 6. A256CBC-HS512 decrypt.
  let plaintext;
  try {
    plaintext = await a256cbcHs512.decrypt({ cek, iv, aad, ciphertext, tag });
  } catch (e) {
    throw new Error(`unpack: A256CBC-HS512 decrypt failed: ${e.message}`);
  } finally {
    cek.fill(0);
    kek.fill(0);
  }

  // 7. Parse the plaintext.
  let message;
  try {
    message = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (e) {
    throw new Error(`unpack: plaintext not JSON: ${e.message}`);
  }

  return {
    message,
    senderKid: isAuthcrypt ? header.skid : undefined,
    authenticated: isAuthcrypt,
  };
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
