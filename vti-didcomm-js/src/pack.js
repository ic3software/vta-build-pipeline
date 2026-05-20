// Authcrypt JWE pack — assemble a DIDComm v2 encrypted envelope
// addressed to one recipient.
//
// Wire shape (DIDComm v2 §5.2; JWE per RFC 7516; ECDH-1PU per
// draft-madden-jose-ecdh-1pu):
//
//   {
//     "protected": "<base64url(JSON({ typ, alg, enc, apu, apv, skid, epk }))>",
//     "recipients": [
//       { "header": { "kid": "<recipient_kid>" },
//         "encrypted_key": "<base64url(AES-KW(KEK, CEK))>" }
//     ],
//     "iv": "<base64url(16 random bytes)>",
//     "ciphertext": "<base64url(AES-256-CBC(plaintext, key=encKey, iv=iv))>",
//     "tag": "<base64url(HMAC-SHA-512(macKey, aad||iv||ct||AL)[0..32])>"
//   }
//
// Encryption algorithm: A256CBC-HS512 (RFC 7518 §5.2.5). This is
// DIDComm v2's required-to-implement content-encryption algorithm
// and what affinidi-messaging-didcomm uses on the wire — A256GCM
// would round-trip with most JOSE libraries but not with the
// workspace's DIDComm mediator.
//
// Pack steps (ordering matters — see "key-wrap binding" below):
//
//   1. Generate ephemeral X25519 keypair.
//   2. Generate fresh CEK (64 bytes) + IV (16 bytes).
//   3. apu / apv inputs.
//   4. Build the protected header JSON. Encode as base64url. The
//      base64url string is the AAD for content encryption.
//   5. Encrypt plaintext with A256CBC-HS512 (CEK, IV, AAD=protected)
//      to get ciphertext + tag.
//   6. KEK = ConcatKDF over (Ze || Zs) with apu / apv / alg AND the
//      tag from step 5 as SuppPrivInfo.
//   7. Wrap CEK with KEK via AES-KW.
//   8. Assemble and return the JWE JSON string.
//
// Key-wrap binding: ECDH-1PU+A256KW (draft-madden §2.3) folds the
// content-encryption auth tag into Concat KDF as SuppPrivInfo. So
// we must encrypt the content BEFORE deriving the KEK — otherwise
// we'd be using a tag that doesn't exist yet. Tampering with the
// ciphertext changes the tag, which changes the KEK, which makes
// AES-KW unwrap fail before the recipient even looks at the
// ciphertext.

import * as a256cbcHs512 from "./a256cbc-hs512.js";
import * as aes from "./aes.js";
import * as b64u from "./base64url.js";
import * as ecdh1pu from "./ecdh-1pu.js";
import * as jwk from "./jwk.js";
import * as x25519 from "./x25519.js";

const ALG = "ECDH-1PU+A256KW";
const ENC = "A256CBC-HS512";
const TYP = "application/didcomm-encrypted+json";

/**
 * Pack a plaintext DIDComm message as an authcrypt JWE.
 *
 * @param {Object} args
 * @param {Object} args.message  - Plaintext DIDComm v2 message.
 *   Caller supplies `{ id, type, from, to, body, ... }`; pack
 *   serialises it to JSON.
 * @param {Object} args.sender   - `{ kid, privateJwk }`. `kid`
 *   identifies the sender's key on their DID document; the JWE's
 *   `skid` field carries it verbatim so the recipient can resolve
 *   the matching public key.
 * @param {Object} args.recipient - `{ kid, publicJwk }`. Single
 *   recipient (multi-recipient is out of scope per B0).
 * @returns {Promise<string>} the packed JWE as a JSON string
 */
export async function pack({ message, sender, recipient }) {
  if (!sender?.kid || !sender?.privateJwk) {
    throw new TypeError("pack: sender.{kid, privateJwk} required");
  }
  if (!recipient?.kid || !recipient?.publicJwk) {
    throw new TypeError("pack: recipient.{kid, publicJwk} required");
  }
  const senderPriv = jwk.rawPrivate(sender.privateJwk);
  const recipientPub = jwk.rawPublic(recipient.publicJwk);

  // 1. Ephemeral X25519 keypair.
  const ephem = x25519.generateKeyPair();

  // 2. CEK + IV (64-byte CEK split mac||enc, 16-byte CBC IV).
  const { cek, iv } = a256cbcHs512.generateCekAndIv();

  // 3. apu / apv inputs. apu is the raw bytes of the sender kid;
  //    apv is the sha256 of the recipient kid string (DIDComm v2
  //    convention for single-recipient envelopes).
  const apuBytes = new TextEncoder().encode(sender.kid);
  const apvBytes = await sha256(new TextEncoder().encode(recipient.kid));

  // 4. Protected header. JSON-serialised (compact, no whitespace)
  //    then base64url-encoded. The base64url string is the AAD for
  //    content encryption.
  const protectedHeader = {
    typ: TYP,
    alg: ALG,
    enc: ENC,
    apu: b64u.encode(apuBytes),
    apv: b64u.encode(apvBytes),
    skid: sender.kid,
    epk: {
      kty: "OKP",
      crv: "X25519",
      x: b64u.encode(ephem.publicKey),
    },
  };
  const protectedJson = JSON.stringify(protectedHeader);
  const protectedB64 = b64u.encode(new TextEncoder().encode(protectedJson));

  // 5. Encrypt content (A256CBC-HS512). The tag from this step is
  //    the SuppPrivInfo for the Concat KDF — we MUST encrypt before
  //    deriving the KEK.
  const plaintext = new TextEncoder().encode(JSON.stringify(message));
  const { ciphertext, tag } = await a256cbcHs512.encrypt({
    cek,
    iv,
    aad: new TextEncoder().encode(protectedB64),
    plaintext,
  });

  // 6. KEK via ECDH-1PU, with the content-encryption tag folded in.
  const kek = await ecdh1pu.deriveKekAuthcrypt({
    ephemeralPrivate: ephem.privateKey,
    senderPrivate: senderPriv,
    recipientPublic: recipientPub,
    alg: ALG,
    apu: apuBytes,
    apv: apvBytes,
    ccTag: tag,
  });

  // 7. Wrap CEK.
  const encryptedKey = await aes.wrapKey(kek, cek);

  // 8. Assemble the JWE.
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

  // Best-effort zeroize of the CEK / KEK from our local buffer.
  // (CryptoKey objects exported from Web Crypto can't be reliably
  // zeroized, but the raw byte copies we hold can.)
  cek.fill(0);
  kek.fill(0);

  return JSON.stringify(jwe);
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}
