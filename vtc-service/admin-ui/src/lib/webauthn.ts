// WebAuthn helpers used by the install ceremony, login, and any
// step-up reauth flow.
//
// The base64url ↔ ArrayBuffer conversions are unavoidable because
// the daemon serialises ArrayBuffer fields as base64url strings
// (webauthn-rs default JSON shape) and `navigator.credentials.*`
// wants real `BufferSource`. We do the conversion once at the
// seam.

export function base64urlToBuffer(b64: string): ArrayBuffer {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Serialise a `PublicKeyCredential` (registration) for JSON
 * transport to the daemon. Mirrors webauthn-rs's expected
 * `RegisterPublicKeyCredential` shape.
 */
export function serializeRegistration(
  credential: PublicKeyCredential,
): unknown {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  };
}

/**
 * Serialise a `PublicKeyCredential` (assertion / authentication)
 * for JSON transport. Used by passkey login and every step-up UV
 * ceremony.
 */
export function serializeAssertion(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
  };
}

/**
 * Decode the `publicKey` field of a server-issued creation/request
 * challenge: convert the base64url-encoded `challenge`, `user.id`,
 * `excludeCredentials[].id`, and `allowCredentials[].id` to real
 * `ArrayBuffer`s so the browser WebAuthn API accepts them.
 *
 * Operates in-place + returns the same object for convenience.
 * The narrow `unknown` typing reflects what webauthn-rs serialises;
 * callers cast at the boundary where they invoke
 * `navigator.credentials.{create,get}`.
 */
export function decodePublicKeyOptions(publicKey: any): any {
  if (publicKey.challenge && typeof publicKey.challenge === "string") {
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  }
  if (publicKey.user?.id && typeof publicKey.user.id === "string") {
    publicKey.user.id = base64urlToBuffer(publicKey.user.id);
  }
  if (Array.isArray(publicKey.excludeCredentials)) {
    for (const c of publicKey.excludeCredentials) {
      if (typeof c.id === "string") c.id = base64urlToBuffer(c.id);
    }
  }
  if (Array.isArray(publicKey.allowCredentials)) {
    for (const c of publicKey.allowCredentials) {
      if (typeof c.id === "string") c.id = base64urlToBuffer(c.id);
    }
  }
  return publicKey;
}
