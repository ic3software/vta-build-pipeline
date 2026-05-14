// VTC install ceremony — claim the first admin passkey.
//
// Driven by the install URL the `vtc setup` wizard (or
// `vtc admin emergency-bootstrap`) prints. Reads `?token=<jwt>` from
// the URL, runs the WebAuthn registration ceremony, and exchanges
// the result for a setup-session token consumed by
// `POST /v1/admin/bootstrap`.
//
// Modelled on `affinidi-webvh-service/webvh-ui/lib/passkey.ts` +
// `app/enroll.tsx` — the workspace's chosen reference for browser-
// side WebAuthn enrolment.

const TRUST_TASK_START =
  "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";

// ---------------------------------------------------------------------------
// Base64url <-> ArrayBuffer
// webauthn-rs serializes `CreationChallengeResponse` with base64url-
// encoded ArrayBuffer fields; `navigator.credentials.create` wants
// real ArrayBuffer. Convert each direction once at the seam.
// ---------------------------------------------------------------------------

function base64urlToBuffer(b64) {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

function showPhase(phase) {
  for (const id of ["phase-registering", "phase-success", "phase-error"]) {
    document.getElementById(id).hidden = id !== phase;
  }
}

function showError(title, message, hint) {
  document.getElementById("error-title").textContent = title;
  document.getElementById("error-message").textContent = message;
  document.getElementById("error-hint").textContent = hint || "";
  showPhase("phase-error");
}

// ---------------------------------------------------------------------------
// Server calls
// ---------------------------------------------------------------------------

async function postJson(path, trustTask, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Trust-Task": trustTask,
    },
    body: JSON.stringify(body),
  });
  let parsed = null;
  try {
    parsed = await res.json();
  } catch {
    // Non-JSON body — leave `parsed` null.
  }
  return { status: res.status, body: parsed };
}

// ---------------------------------------------------------------------------
// Ceremony
// ---------------------------------------------------------------------------

async function run() {
  const token = new URLSearchParams(window.location.search).get("token");
  if (!token) {
    showError(
      "Missing install token",
      "The install URL must include `?token=<jwt>`.",
      "Re-open the URL the wizard printed at setup time — it includes the token.",
    );
    return;
  }

  // -- claim/start ----------------------------------------------------------
  const startResult = await postJson(
    "/v1/install/claim/start",
    TRUST_TASK_START,
    { install_token: token },
  );
  if (startResult.status === 401) {
    showError(
      "Install URL expired or already used",
      "The install URL is single-use and expires 15 minutes after the wizard prints it.",
      "Ask the daemon operator to mint a new one via `vtc admin emergency-bootstrap` on the host.",
    );
    return;
  }
  if (startResult.status === 409) {
    showError(
      "Install ceremony already in progress",
      "Another browser session is mid-ceremony with this token.",
      "Wait a few minutes for the previous attempt to time out, then retry — or ask the operator for a fresh URL.",
    );
    return;
  }
  if (startResult.status !== 200) {
    showError(
      `Server error (${startResult.status})`,
      startResult.body?.error ||
        startResult.body?.message ||
        "Unexpected response from the daemon.",
      "Check the daemon logs for details.",
    );
    return;
  }

  const { registrationId, options } = startResult.body;

  // -- WebAuthn create ------------------------------------------------------
  // Convert base64url-encoded ArrayBuffer fields to real ArrayBuffers so
  // the platform WebAuthn API accepts them.
  const publicKey = options.publicKey;
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  publicKey.user.id = base64urlToBuffer(publicKey.user.id);
  if (publicKey.excludeCredentials) {
    for (const cred of publicKey.excludeCredentials) {
      cred.id = base64urlToBuffer(cred.id);
    }
  }

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (err) {
    showError(
      "Passkey registration cancelled or failed",
      err.message || String(err),
      "Try again, or use a different authenticator (USB security key, platform passkey).",
    );
    return;
  }

  if (!credential) {
    showError(
      "Passkey registration returned no credential",
      "Your browser dismissed the ceremony without producing a credential.",
      "Retry the install URL.",
    );
    return;
  }

  // Re-serialize the credential for JSON transport. Mirrors the shape
  // webauthn-rs's `RegisterPublicKeyCredential` deserializes.
  const response = credential.response;
  const webauthnResponse = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  };

  // -- claim/finish ---------------------------------------------------------
  const finishResult = await postJson(
    "/v1/install/claim/finish",
    TRUST_TASK_FINISH,
    {
      install_token: token,
      registration_id: registrationId,
      webauthn_response: webauthnResponse,
    },
  );
  if (finishResult.status !== 200) {
    showError(
      `Install ceremony failed (${finishResult.status})`,
      finishResult.body?.error ||
        finishResult.body?.message ||
        "The daemon rejected the WebAuthn response.",
      finishResult.status === 401
        ? "The install token may have expired between start and finish — ask the operator for a fresh URL."
        : "Check the daemon logs for the rejection reason.",
    );
    return;
  }

  // -- success --------------------------------------------------------------
  document.getElementById("admin-did").textContent = finishResult.body.adminDid;
  document.getElementById("setup-session-token").textContent =
    finishResult.body.setupSessionToken;
  showPhase("phase-success");
}

run().catch((err) => {
  showError(
    "Unexpected client error",
    err.message || String(err),
    "Open the browser DevTools console for the stack trace.",
  );
});
