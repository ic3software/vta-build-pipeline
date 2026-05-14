// `/admin/install?token=<jwt>` — install-claim ceremony.
//
// Distinct from a plugin: the install URL is the public entry point
// for an unauthenticated operator, so it lives outside the plugin
// routing tree (which is gated on auth once login lands). Reads
// `?token=` from the URL, drives `navigator.credentials.create`,
// posts to `/v1/install/claim/{start,finish}`.
//
// Modelled on `affinidi-webvh-service/webvh-ui/lib/passkey.ts` +
// `app/enroll.tsx`: standard WebAuthn registration with no custom
// binding-signature step. The admin DID is carried in the install
// token, not derived from the passkey.

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

const TRUST_TASK_START =
  "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";

type Phase =
  | { kind: "registering" }
  | { kind: "success"; adminDid: string; setupSessionToken: string }
  | { kind: "error"; title: string; message: string; hint?: string };

function base64urlToBuffer(b64: string): ArrayBuffer {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buf: ArrayBuffer): string {
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

async function postJson(
  path: string,
  trustTask: string,
  body: unknown,
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Trust-Task": trustTask,
    },
    body: JSON.stringify(body),
  });
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    /* non-JSON body — leave null */
  }
  return { status: res.status, body: parsed };
}

export function Install() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const [phase, setPhase] = useState<Phase>({ kind: "registering" });

  useEffect(() => {
    if (!token) {
      setPhase({
        kind: "error",
        title: "Missing install token",
        message: "The install URL must include `?token=<jwt>`.",
        hint: "Re-open the URL the wizard printed at setup time.",
      });
      return;
    }

    let cancelled = false;

    (async () => {
      // ── claim/start ──
      const start = await postJson(
        "/v1/install/claim/start",
        TRUST_TASK_START,
        { install_token: token },
      );
      if (cancelled) return;
      if (start.status === 401) {
        setPhase({
          kind: "error",
          title: "Install URL expired or already used",
          message:
            "The install URL is single-use and expires 15 minutes after the wizard prints it.",
          hint: "Ask the daemon operator to mint a new one via `vtc admin invite --did <admin-did>` on the host.",
        });
        return;
      }
      if (start.status === 409) {
        setPhase({
          kind: "error",
          title: "Install ceremony already in progress",
          message:
            "Another browser session is mid-ceremony with this token.",
          hint: "Wait a few minutes for it to time out, then retry — or ask the operator for a fresh URL.",
        });
        return;
      }
      if (start.status !== 200) {
        const b = start.body as { error?: string; message?: string } | null;
        setPhase({
          kind: "error",
          title: `Server error (${start.status})`,
          message: b?.error ?? b?.message ?? "Unexpected response from the daemon.",
        });
        return;
      }

      const startBody = start.body as {
        registrationId: string;
        options: { publicKey: PublicKeyCredentialCreationOptionsJSON };
      };

      // ── browser WebAuthn create ──
      const publicKey = startBody.options
        .publicKey as unknown as PublicKeyCredentialCreationOptions;
      (publicKey as unknown as PublicKeyCredentialCreationOptionsJSON).challenge =
        base64urlToBuffer(
          startBody.options.publicKey.challenge as unknown as string,
        ) as unknown as BufferSource;
      (publicKey as unknown as PublicKeyCredentialCreationOptionsJSON).user.id =
        base64urlToBuffer(
          startBody.options.publicKey.user.id as unknown as string,
        ) as unknown as BufferSource;
      if (publicKey.excludeCredentials) {
        for (const cred of publicKey.excludeCredentials) {
          cred.id = base64urlToBuffer(
            cred.id as unknown as string,
          ) as unknown as BufferSource;
        }
      }

      let credential: PublicKeyCredential | null = null;
      try {
        credential = (await navigator.credentials.create({
          publicKey,
        })) as PublicKeyCredential | null;
      } catch (err) {
        const e = err as Error;
        setPhase({
          kind: "error",
          title: "Passkey registration cancelled or failed",
          message: e.message || String(err),
          hint: "Try again, or use a different authenticator (USB security key, platform passkey).",
        });
        return;
      }
      if (cancelled) return;
      if (!credential) {
        setPhase({
          kind: "error",
          title: "Passkey registration returned no credential",
          message:
            "Your browser dismissed the ceremony without producing a credential.",
          hint: "Retry the install URL.",
        });
        return;
      }

      const response =
        credential.response as AuthenticatorAttestationResponse;
      const webauthnResponse = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferToBase64url(response.attestationObject),
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
        },
      };

      // ── claim/finish ──
      const finish = await postJson(
        "/v1/install/claim/finish",
        TRUST_TASK_FINISH,
        {
          install_token: token,
          registration_id: startBody.registrationId,
          webauthn_response: webauthnResponse,
        },
      );
      if (cancelled) return;
      if (finish.status !== 200) {
        const b = finish.body as { error?: string; message?: string } | null;
        setPhase({
          kind: "error",
          title: `Install ceremony failed (${finish.status})`,
          message: b?.error ?? b?.message ?? "The daemon rejected the WebAuthn response.",
          hint:
            finish.status === 401
              ? "The install token may have expired between start and finish — ask the operator for a fresh URL."
              : "Check the daemon logs for the rejection reason.",
        });
        return;
      }

      const finishBody = finish.body as {
        adminDid: string;
        setupSessionToken: string;
      };
      setPhase({
        kind: "success",
        adminDid: finishBody.adminDid,
        setupSessionToken: finishBody.setupSessionToken,
      });
    })().catch((err) => {
      if (cancelled) return;
      const e = err as Error;
      setPhase({
        kind: "error",
        title: "Unexpected client error",
        message: e.message || String(err),
        hint: "Open the browser DevTools console for the stack trace.",
      });
    });

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <section className="page install-page">
      <h2>Claim Admin Passkey</h2>
      <p className="lead">
        One-shot install ceremony for the first administrator of this
        Verifiable Trust Community.
      </p>

      {phase.kind === "registering" && (
        <section className="card">
          <h3>Registering passkey…</h3>
          <p>
            Follow your browser's prompts to register a passkey for
            this server. The admin DID is decided server-side from
            the install token, so any passkey algorithm your
            authenticator offers (ES256, RS256, EdDSA) is fine.
          </p>
        </section>
      )}

      {phase.kind === "success" && (
        <section className="card">
          <h3>Passkey registered ✅</h3>
          <dl>
            <dt>Admin DID</dt>
            <dd>
              <code>{phase.adminDid}</code>
            </dd>
          </dl>
          <p>
            Save the setup-session token below — your CNM CLI uses it
            to complete the bootstrap handshake.
          </p>
          <pre>{phase.setupSessionToken}</pre>
        </section>
      )}

      {phase.kind === "error" && (
        <section className="card error">
          <h3>{phase.title}</h3>
          <p>{phase.message}</p>
          {phase.hint && <p className="lead">{phase.hint}</p>}
        </section>
      )}

      <footer>
        <p className="lead">
          The install URL is single-use and expires after 15 minutes.
          If yours has expired, the daemon operator can mint a fresh
          one via <code>vtc admin invite --did &lt;admin-did&gt;</code>.
        </p>
      </footer>
    </section>
  );
}

// Minimal type sketch so TS lets us reach into the JSON shape the
// server returns. webauthn-rs serialises ArrayBuffer fields as
// base64url strings; we cast at the seam after converting.
interface PublicKeyCredentialCreationOptionsJSON {
  challenge: BufferSource;
  user: { id: BufferSource } & Record<string, unknown>;
  excludeCredentials?: ReadonlyArray<{ id: BufferSource } & Record<string, unknown>>;
  [k: string]: unknown;
}
