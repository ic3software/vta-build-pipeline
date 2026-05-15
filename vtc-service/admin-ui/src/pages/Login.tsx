// Passkey login page.
//
// Operator clicks "Sign in with passkey" → POST to
// `/v1/auth/passkey-login/start` → run `navigator.credentials.get`
// → POST to `/finish` → daemon sets the `vtc_admin_session` cookie
// (HttpOnly) and the `csrf` cookie (JS-readable). The shell then
// reloads its sign-in probe and renders the authenticated UI.

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";

import { postJson } from "@/lib/api";
import {
  decodePublicKeyOptions,
  serializeAssertion,
} from "@/lib/webauthn";

const TRUST_TASK_START =
  "https://trusttasks.org/openvtc/vtc/auth/passkey-login/start/1.0";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/openvtc/vtc/auth/passkey-login/finish/1.0";

type Phase =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "error"; message: string; hint?: string };

export function Login() {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const queryClient = useQueryClient();

  const signIn = async () => {
    setPhase({ kind: "running" });
    try {
      // ── /passkey-login/start ──
      const start = await postJson<{
        authId: string;
        options: { publicKey: unknown };
      }>("/v1/auth/passkey-login/start", undefined, {
        trustTask: TRUST_TASK_START,
      });

      const publicKey = decodePublicKeyOptions(
        (start.options as { publicKey: unknown }).publicKey,
      );

      // ── navigator.credentials.get ──
      const credential = (await navigator.credentials.get({
        publicKey,
      })) as PublicKeyCredential | null;
      if (!credential) {
        setPhase({
          kind: "error",
          message: "Passkey ceremony returned no credential.",
          hint: "Retry, or use a different authenticator.",
        });
        return;
      }

      // ── /passkey-login/finish ──
      await postJson<unknown>(
        "/v1/auth/passkey-login/finish",
        {
          auth_id: start.authId,
          credential: serializeAssertion(credential),
        },
        { trustTask: TRUST_TASK_FINISH },
      );

      // Success — the daemon set the cookies. Invalidate the
      // whoami probe (the same key App.tsx uses) so the shell
      // re-renders into the authenticated tree without a manual
      // reload. The previous "session-probe" key didn't match any
      // live query, so the shell stayed stuck on this page.
      await queryClient.invalidateQueries({ queryKey: ["whoami"] });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      let hint: string | undefined;
      if (e.status === 401) {
        hint =
          "Your passkey isn't recognised, or the ACL revoked your admin role. " +
          "Ask another admin to issue a fresh `vtc admin invite --did <your-did>`.";
      } else if (e.status === 404) {
        hint = "No passkeys are registered yet — claim the install URL first.";
      } else if (
        err instanceof DOMException &&
        err.name === "NotAllowedError"
      ) {
        hint = "Passkey prompt cancelled or denied by the browser.";
      }
      setPhase({
        kind: "error",
        message: e.message ?? String(err),
        hint,
      });
    }
  };

  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">
          Sign in with the passkey you registered at install.
        </p>
        <button
          type="button"
          className="primary"
          onClick={signIn}
          disabled={phase.kind === "running"}
        >
          <Fingerprint size={16} aria-hidden="true" />
          {phase.kind === "running"
            ? "Waiting for passkey…"
            : "Sign in with passkey"}
        </button>
        {phase.kind === "error" && (
          <section className="card error">
            <h3>Sign-in failed</h3>
            <p>{phase.message}</p>
            {phase.hint && <p className="lead">{phase.hint}</p>}
          </section>
        )}
        <footer>
          <p>
            No passkey yet? Open the install URL the daemon operator
            shared, or ask them to mint a fresh one via{" "}
            <code>vtc admin invite</code>.
          </p>
        </footer>
      </div>
    </section>
  );
}

