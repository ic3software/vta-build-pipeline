// VTA auth demo — vanilla JS, no build step.
//
// Three flows exercised here:
//
//   1. Passkey login (DID-VM-resolved WebAuthn) — POST start, browser
//      navigator.credentials.get(), POST finish → JWT.
//   2. Session inspection + revoke — GET /auth/sessions, DELETE one.
//   3. Trust-task dispatch — POST /api/trust-tasks with a typed
//      envelope, parse the response payload.
//
// The legacy challenge/authenticate flow is DIDComm-message-based and
// not browser-friendly; use `pnm auth` for that path. See README.

// ─── State ────────────────────────────────────────────────────────────

const state = {
  vtaUrl: null,
  loginSessionId: null,
  loginChallenge: null,
  loginAllowCredentials: [],
  accessToken: null,
  refreshToken: null,
  accessExpiresAt: null,
  currentSessionId: null,
  role: null,
};

// Known trust-task URIs. Curated subset of vta-sdk::trust_tasks::ALL_URIS
// — the ones a freshly-authenticated operator can actually exercise
// without other setup. The dropdown drives the type field; the
// payload textarea is operator-editable.
const KNOWN_URIS = [
  {
    label: "discovery/capabilities — list VTA features",
    type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0",
    payload: {},
  },
  {
    label: "config/get — read VTA configuration",
    type: "https://trusttasks.org/spec/vta/config/get/1.0",
    payload: {},
  },
  {
    label: "acl/list — list ACL entries",
    type: "https://trusttasks.org/spec/vta/acl/list/1.0",
    payload: {},
  },
  {
    label: "contexts/list — list contexts",
    type: "https://trusttasks.org/spec/vta/contexts/list/1.0",
    payload: {},
  },
  {
    label: "keys/list — list keys",
    type: "https://trusttasks.org/spec/vta/keys/list/1.0",
    payload: {},
  },
  {
    label: "seeds/list — list seed records",
    type: "https://trusttasks.org/spec/vta/seeds/list/1.0",
    payload: {},
  },
  {
    label: "audit/list-logs — list audit log entries",
    type: "https://trusttasks.org/spec/vta/audit/list-logs/1.0",
    payload: {},
  },
];

// ─── DOM ──────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const els = {
  vtaUrl: $("vtaUrl"),
  checkHealth: $("checkHealth"),
  healthStatus: $("healthStatus"),

  loginDid: $("loginDid"),
  loginStart: $("loginStart"),
  loginFinish: $("loginFinish"),
  loginOutput: $("loginOutput"),

  sessionSection: $("sessionSection"),
  tokenDisplay: $("tokenDisplay"),
  sessionIdDisplay: $("sessionIdDisplay"),
  roleDisplay: $("roleDisplay"),
  expiresIn: $("expiresIn"),
  listSessions: $("listSessions"),
  revokeCurrent: $("revokeCurrent"),
  signOut: $("signOut"),
  sessionsOutput: $("sessionsOutput"),

  trustTasksSection: $("trustTasksSection"),
  taskUri: $("taskUri"),
  taskPayload: $("taskPayload"),
  sendTask: $("sendTask"),
  taskOutput: $("taskOutput"),
};

// ─── Utilities ────────────────────────────────────────────────────────

function baseUrl() {
  return els.vtaUrl.value.trim().replace(/\/+$/, "");
}

function setOutput(el, text, kind = "ok") {
  el.textContent = text;
  el.className = `output ${kind}`;
}

function clearOutput(el) {
  el.textContent = "";
  el.className = "output";
}

// base64url ⇄ Uint8Array helpers. WebAuthn surfaces ArrayBuffers; the
// wire format is base64url-without-padding.
function b64urlEncode(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  const pad = (s.length % 4 === 0) ? "" : "=".repeat(4 - (s.length % 4));
  const std = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function decodeJwtPayload(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
    const std = padded.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(std));
  } catch {
    return null;
  }
}

function asJson(obj) {
  return JSON.stringify(obj, null, 2);
}

// Wrap fetch with a uniform error path: non-2xx becomes a thrown
// Error with the response body included so the operator can see what
// the VTA said. Saves rewriting error handling in every flow.
async function vtaFetch(path, opts = {}) {
  const url = `${baseUrl()}${path}`;
  const res = await fetch(url, opts);
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const detail = typeof body === "string" ? body : asJson(body);
    throw new Error(`HTTP ${res.status} ${res.statusText}\n${detail}`);
  }
  return body;
}

// ─── Health ───────────────────────────────────────────────────────────

els.checkHealth.addEventListener("click", async () => {
  els.healthStatus.textContent = "checking…";
  els.healthStatus.className = "status muted";
  try {
    const body = await vtaFetch("/health");
    els.healthStatus.textContent = `OK · ${body?.status ?? "responding"}`;
    els.healthStatus.className = "status ok";
  } catch (e) {
    // Either the VTA is down, the URL is wrong, or CORS is blocking us.
    // The browser console will have the CORS message in the latter case.
    els.healthStatus.textContent = `error · ${e.message.split("\n")[0]}`;
    els.healthStatus.className = "status err";
  }
});

// ─── Passkey login ────────────────────────────────────────────────────

els.loginStart.addEventListener("click", async () => {
  const did = els.loginDid.value.trim();
  if (!did) {
    setOutput(els.loginOutput, "DID is required", "err");
    return;
  }
  clearOutput(els.loginOutput);
  try {
    const resp = await vtaFetch("/auth/passkey-login/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ did }),
    });
    state.loginSessionId = resp.sessionId;
    state.loginChallenge = resp.challenge;
    state.loginAllowCredentials = resp.allowCredentials || [];
    setOutput(
      els.loginOutput,
      `Challenge received:\n${asJson(resp)}\n\nClick "Finish" to invoke the browser's WebAuthn API.`,
      "ok",
    );
    els.loginFinish.disabled = false;
  } catch (e) {
    setOutput(els.loginOutput, e.message, "err");
  }
});

els.loginFinish.addEventListener("click", async () => {
  clearOutput(els.loginOutput);
  if (!state.loginSessionId || !state.loginChallenge) {
    setOutput(els.loginOutput, "Run Start first.", "err");
    return;
  }
  try {
    // Server-side challenge is hex-encoded 32 bytes; WebAuthn wants
    // an ArrayBuffer of those bytes. The browser stamps the challenge
    // into clientDataJSON as base64url; the server side decodes both
    // representations the same way (passkey-verify checks against
    // SHA-256(canonical body) for the document-binding case, or the
    // raw nonce for legacy passkey login).
    const challengeBytes = hexToBytes(state.loginChallenge);
    const allowCredentials = state.loginAllowCredentials.map((id) => ({
      id: b64urlDecode(id),
      type: "public-key",
    }));

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challengeBytes,
        allowCredentials,
        userVerification: "preferred",
        timeout: 60_000,
      },
    });

    if (!assertion) {
      setOutput(els.loginOutput, "Browser returned no credential.", "err");
      return;
    }

    const ad = new Uint8Array(assertion.response.authenticatorData);
    const cd = new Uint8Array(assertion.response.clientDataJSON);
    const sig = new Uint8Array(assertion.response.signature);
    const credId = new Uint8Array(assertion.rawId);

    // The browser doesn't tell us which DID-doc VM was used — the
    // server resolves the DID and matches credential_id against the
    // published verificationMethods. Pass the credential_id verbatim;
    // the server uses it to look up the verificationMethod URL.
    // (The wire field `verificationMethod` is required by the SDK
    // type; pass empty and let the server derive it from credId.)
    const reqBody = {
      sessionId: state.loginSessionId,
      credentialId: b64urlEncode(credId),
      authenticatorData: b64urlEncode(ad),
      clientDataJSON: b64urlEncode(cd),
      signature: b64urlEncode(sig),
      verificationMethod: "",
    };

    const resp = await vtaFetch("/auth/passkey-login/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(reqBody),
    });

    storeAuth(resp);
    setOutput(els.loginOutput, `Authenticated.\n${asJson(resp)}`, "ok");
  } catch (e) {
    setOutput(els.loginOutput, e.message, "err");
  }
});

// ─── Auth state UI ────────────────────────────────────────────────────

function storeAuth(authResponse) {
  state.accessToken = authResponse.data.accessToken;
  state.refreshToken = authResponse.data.refreshToken || null;
  state.accessExpiresAt = authResponse.data.accessExpiresAt;
  state.currentSessionId = authResponse.sessionId || null;

  const claims = decodeJwtPayload(state.accessToken);
  state.role = claims?.role || null;

  els.tokenDisplay.textContent = state.accessToken;
  els.sessionIdDisplay.textContent = state.currentSessionId || "(unknown)";
  els.roleDisplay.textContent = state.role || "(unknown)";

  els.sessionSection.classList.remove("hidden");
  els.trustTasksSection.classList.remove("hidden");
  els.loginFinish.disabled = true;

  renderExpiresIn();
}

let expiresTimer = null;
function renderExpiresIn() {
  if (expiresTimer) clearInterval(expiresTimer);
  const tick = () => {
    if (!state.accessExpiresAt) return;
    const nowSec = Math.floor(Date.now() / 1000);
    const remaining = state.accessExpiresAt - nowSec;
    if (remaining <= 0) {
      els.expiresIn.textContent = "EXPIRED";
      els.expiresIn.style.color = "var(--err)";
      clearInterval(expiresTimer);
      return;
    }
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    els.expiresIn.textContent = `${mins}m ${secs}s`;
    els.expiresIn.style.color = remaining < 60 ? "var(--warn)" : "var(--ok)";
  };
  tick();
  expiresTimer = setInterval(tick, 1000);
}

function clearAuth() {
  state.accessToken = null;
  state.refreshToken = null;
  state.accessExpiresAt = null;
  state.currentSessionId = null;
  state.role = null;
  if (expiresTimer) clearInterval(expiresTimer);
  els.sessionSection.classList.add("hidden");
  els.trustTasksSection.classList.add("hidden");
  clearOutput(els.loginOutput);
  clearOutput(els.sessionsOutput);
  clearOutput(els.taskOutput);
}

els.signOut.addEventListener("click", clearAuth);

// ─── Session list + revoke ────────────────────────────────────────────

els.listSessions.addEventListener("click", async () => {
  clearOutput(els.sessionsOutput);
  try {
    const sessions = await vtaFetch("/auth/sessions", {
      headers: { authorization: `Bearer ${state.accessToken}` },
    });
    setOutput(els.sessionsOutput, asJson(sessions), "ok");
  } catch (e) {
    setOutput(els.sessionsOutput, e.message, "err");
  }
});

els.revokeCurrent.addEventListener("click", async () => {
  if (!state.currentSessionId) {
    setOutput(els.sessionsOutput, "No current session id (re-login).", "err");
    return;
  }
  if (!confirm(`Revoke session ${state.currentSessionId}?`)) return;
  clearOutput(els.sessionsOutput);
  try {
    await vtaFetch(`/auth/sessions/${state.currentSessionId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${state.accessToken}` },
    });
    setOutput(els.sessionsOutput, "Current session revoked. Token will no longer authenticate.", "ok");
    // Don't fully clearAuth() so the operator can see the 401 by
    // re-trying — that's an educational side-effect of the demo.
  } catch (e) {
    setOutput(els.sessionsOutput, e.message, "err");
  }
});

// ─── Trust-task dispatch ──────────────────────────────────────────────

function populateUriDropdown() {
  els.taskUri.innerHTML = "";
  KNOWN_URIS.forEach((u, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = u.label;
    els.taskUri.appendChild(opt);
  });
  // Initialise payload to the first entry's body.
  els.taskPayload.value = asJson(KNOWN_URIS[0].payload);
}

els.taskUri.addEventListener("change", () => {
  const idx = parseInt(els.taskUri.value, 10);
  els.taskPayload.value = asJson(KNOWN_URIS[idx].payload);
});

els.sendTask.addEventListener("click", async () => {
  clearOutput(els.taskOutput);
  const idx = parseInt(els.taskUri.value, 10);
  const type = KNOWN_URIS[idx].type;
  let payload;
  try {
    payload = JSON.parse(els.taskPayload.value);
  } catch (e) {
    setOutput(els.taskOutput, `Payload is not valid JSON: ${e.message}`, "err");
    return;
  }
  const id = `urn:uuid:${crypto.randomUUID()}`;
  const envelope = { id, type, payload };

  try {
    const resp = await vtaFetch("/api/trust-tasks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${state.accessToken}`,
      },
      body: JSON.stringify(envelope),
    });
    setOutput(
      els.taskOutput,
      `Request:\n${asJson(envelope)}\n\nResponse:\n${asJson(resp)}`,
      "ok",
    );
  } catch (e) {
    setOutput(els.taskOutput, e.message, "err");
  }
});

// ─── Init ─────────────────────────────────────────────────────────────

populateUriDropdown();
