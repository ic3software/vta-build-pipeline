// Anoncrypt JWE pack — assemble a DIDComm v2 anonymous-encryption
// envelope addressed to one recipient.
//
// Anoncrypt vs authcrypt (`pack.js`):
//   - Key agreement is ECDH-ES (ephemeral → recipient only); there is
//     NO sender static key, so the mediator/recipient cannot learn who
//     sent it. This is why DIDComm wraps the `routing/2.0/forward`
//     envelope in anoncrypt — the mediator relays without learning the
//     holder's identity.
//   - The protected header has NO `skid` and NO `apu` (no sender).
//   - The ECDH-ES KEK does NOT bind the content-encryption tag (no
//     SuppPrivInfo), so encryption order doesn't matter.
//
// Everything else matches authcrypt: A256CBC-HS512 content encryption,
// AES-256-KW CEK wrap, the same `apv = sha256(recipient_kid)`.
//
// Wire shape:
//   { "protected": "<b64url(JSON({typ,alg:ECDH-ES+A256KW,enc:A256CBC-HS512,apv,epk}))>",
//     "recipients": [{ "header": { "kid": "<recipient_kid>" },
//                      "encrypted_key": "<b64url(AES-KW(KEK, CEK))>" }],
//     "iv": "<b64url(16 bytes)>",
//     "ciphertext": "<b64url(A256CBC-HS512 ct)>",
//     "tag": "<b64url(32-byte tag)>" }

import * as a256cbcHs512 from "./a256cbc-hs512.js";
import * as aes from "./aes.js";
import * as b64u from "./base64url.js";
import * as ecdhEs from "./ecdh-es.js";
import * as jwk from "./jwk.js";
import * as x25519 from "./x25519.js";

const ALG = "ECDH-ES+A256KW";
const ENC = "A256CBC-HS512";
const TYP = "application/didcomm-encrypted+json";

/**
 * Pack a plaintext DIDComm message as an anoncrypt JWE.
 *
 * @param {Object} args
 * @param {Object} args.message - Plaintext DIDComm v2 message; pack
 *   serialises it to JSON.
 * @param {Object} args.recipient - `{ kid, publicJwk }`. Single
 *   recipient (multi-recipient out of scope).
 * @returns {Promise<string>} the packed JWE as a JSON string
 */
export async function packAnoncrypt({ message, recipient }) {
  if (!recipient?.kid || !recipient?.publicJwk) {
    throw new TypeError("packAnoncrypt: recipient.{kid, publicJwk} required");
  }
  const recipientPub = jwk.rawPublic(recipient.publicJwk);

  // Ephemeral X25519 keypair + CEK/IV (64-byte CEK, 16-byte CBC IV).
  const ephem = x25519.generateKeyPair();
  const { cek, iv } = a256cbcHs512.generateCekAndIv();

  // apu is empty (no sender); apv = sha256(recipient kid).
  const apuBytes = new Uint8Array();
  const apvBytes = await sha256(new TextEncoder().encode(recipient.kid));

  // Protected header — no skid, no apu.
  const protectedHeader = {
    typ: TYP,
    alg: ALG,
    enc: ENC,
    apv: b64u.encode(apvBytes),
    epk: {
      kty: "OKP",
      crv: "X25519",
      x: b64u.encode(ephem.publicKey),
    },
  };
  const protectedJson = JSON.stringify(protectedHeader);
  const protectedB64 = b64u.encode(new TextEncoder().encode(protectedJson));

  // Content encryption (AAD = ASCII bytes of the base64url header).
  const plaintext = new TextEncoder().encode(JSON.stringify(message));
  const { ciphertext, tag } = await a256cbcHs512.encrypt({
    cek,
    iv,
    aad: new TextEncoder().encode(protectedB64),
    plaintext,
  });

  // KEK via ECDH-ES (no content-tag binding).
  const kek = await ecdhEs.deriveKekAnoncrypt({
    ephemeralPrivate: ephem.privateKey,
    recipientPublic: recipientPub,
    alg: ALG,
    apu: apuBytes,
    apv: apvBytes,
  });

  const encryptedKey = await aes.wrapKey(kek, cek);

  const jwe = {
    protected: protectedB64,
    recipients: [
      {
        header: { kid: recipient.kid },
        encrypted_key: b64u.encode(encryptedKey),
      },
    ],
    iv: b64u.encode(iv),
    ciphertext: b64u.encode(ciphertext),
    tag: b64u.encode(tag),
  };

  cek.fill(0);
  kek.fill(0);

  return JSON.stringify(jwe);
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}
