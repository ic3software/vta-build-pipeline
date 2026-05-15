// My passkeys plugin — list, register additional, revoke.
//
// Wraps the `/v1/admin/passkeys/*` endpoint family. Register is a
// dual-ceremony: a new-credential `create` plus a step-up UV
// `get` against an existing passkey in the same start/finish pair.
// Revoke is a single UV ceremony.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { getJson, postJson } from "@/lib/api";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
} from "@/lib/webauthn";

const TRUST_TASK_LIST =
  "https://trusttasks.org/openvtc/vtc/admin/passkeys/list/1.0";
const TRUST_TASK_REGISTER =
  "https://trusttasks.org/openvtc/vtc/admin/passkeys/register/1.0";
const TRUST_TASK_REVOKE =
  "https://trusttasks.org/openvtc/vtc/admin/passkeys/revoke/1.0";

void TRUST_TASK_LIST; // GET is auto-tagged by the route layer.

interface RegisteredPasskey {
  credentialId: string;
  label: string;
  transports: string[];
  registeredAt: string;
  lastUsedAt: string | null;
}

interface ListResponse {
  passkeys: RegisteredPasskey[];
}

interface RegisterStartResponse {
  registrationId: string;
  registerOptions: { publicKey: unknown };
  uvOptions: { publicKey: unknown };
}

interface RevokeStartResponse {
  revocationId: string;
  uvOptions: { publicKey: unknown };
}

async function fetchPasskeys(): Promise<ListResponse> {
  return getJson<ListResponse>("/v1/admin/passkeys");
}

async function registerPasskey(args: {
  label: string;
}): Promise<void> {
  // /register/start returns BOTH a create challenge (for the new
  // passkey) and a UV challenge (against existing passkeys, for
  // step-up). The browser runs both ceremonies, then /register/
  // finish takes both responses.
  const start = await postJson<RegisterStartResponse>(
    "/v1/admin/passkeys/register/start",
    undefined,
    { trustTask: TRUST_TASK_REGISTER },
  );

  const createPublicKey = decodePublicKeyOptions(
    (start.registerOptions as { publicKey: unknown }).publicKey,
  );
  const newCred = (await navigator.credentials.create({
    publicKey: createPublicKey,
  })) as PublicKeyCredential | null;
  if (!newCred) {
    throw new Error("Passkey creation returned no credential");
  }

  const uvPublicKey = decodePublicKeyOptions(
    (start.uvOptions as { publicKey: unknown }).publicKey,
  );
  const uvCred = (await navigator.credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postJson<unknown>(
    "/v1/admin/passkeys/register/finish",
    {
      registration_id: start.registrationId,
      register_response: serializeRegistration(newCred),
      uv_response: serializeAssertion(uvCred),
      label: args.label,
      transports: [],
    },
    { trustTask: TRUST_TASK_REGISTER },
  );
}

async function revokePasskey(args: {
  credentialId: string;
}): Promise<void> {
  const start = await postJson<RevokeStartResponse>(
    "/v1/admin/passkeys/revoke/start",
    { credential_id: args.credentialId },
    { trustTask: TRUST_TASK_REVOKE },
  );

  const uvPublicKey = decodePublicKeyOptions(
    (start.uvOptions as { publicKey: unknown }).publicKey,
  );
  const uvCred = (await navigator.credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postJson<unknown>(
    "/v1/admin/passkeys/revoke/finish",
    {
      revocation_id: start.revocationId,
      uv_response: serializeAssertion(uvCred),
    },
    { trustTask: TRUST_TASK_REVOKE },
  );
}

export function MyPasskeys() {
  const queryClient = useQueryClient();
  const [showRegister, setShowRegister] = useState(false);
  const [label, setLabel] = useState("");

  const query = useQuery({
    queryKey: ["my-passkeys"],
    queryFn: fetchPasskeys,
  });

  const registerMutation = useMutation({
    mutationFn: registerPasskey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
      setShowRegister(false);
      setLabel("");
    },
  });

  const revokeMutation = useMutation({
    mutationFn: revokePasskey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
    },
  });

  const passkeys = query.data?.passkeys ?? [];
  const onlyOne = passkeys.length === 1;

  return (
    <section className="page">
      <h2>My passkeys</h2>
      <p className="lead">
        Manage the passkeys bound to your admin DID. Register a
        backup before losing access to your primary device — losing
        your only passkey means using <code>vtc admin emergency-bootstrap</code>{" "}
        on the host to recover.
      </p>

      {query.error && (
        <section className="card error">
          <h3>Failed to load passkeys</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <div className="toolbar">
          <button
            type="button"
            className={showRegister ? "secondary" : "primary"}
            onClick={() => setShowRegister((v) => !v)}
          >
            {showRegister ? "Cancel" : "+ Register new passkey"}
          </button>
        </div>
      </section>

      {showRegister && (
        <section className="card">
          <h3>Register additional passkey</h3>
          <p className="lead">
            Your browser will prompt twice — once to create the new
            credential, then to verify your existing passkey.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              registerMutation.mutate({ label });
            }}
            className="form-stack"
          >
            <label className="field">
              <span className="field-label">Label</span>
              <input
                type="text"
                placeholder="e.g. ‘YubiKey 5C — work’"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                required
              />
            </label>

            {registerMutation.error && (
              <section className="card error">
                <h3>Register failed</h3>
                <p>{(registerMutation.error as Error).message}</p>
              </section>
            )}

            <div className="form-actions">
              <button
                type="submit"
                className="primary"
                disabled={registerMutation.isPending || label.trim() === ""}
              >
                {registerMutation.isPending
                  ? "Verifying…"
                  : "Register"}
              </button>
            </div>
          </form>
        </section>
      )}

      {revokeMutation.error && (
        <section className="card error">
          <h3>Revoke failed</h3>
          <p>{(revokeMutation.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Credential ID</th>
              <th>Registered</th>
              <th>Last used</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {passkeys.length === 0 && !query.isPending && (
              <tr>
                <td colSpan={5}>No passkeys registered.</td>
              </tr>
            )}
            {passkeys.map((p) => (
              <tr key={p.credentialId}>
                <td>{p.label}</td>
                <td>
                  <code className="truncate" title={p.credentialId}>
                    {p.credentialId}
                  </code>
                </td>
                <td>{formatDate(p.registeredAt)}</td>
                <td>
                  {p.lastUsedAt ? (
                    formatDate(p.lastUsedAt)
                  ) : (
                    <span className="muted">never</span>
                  )}
                </td>
                <td>
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={revokeMutation.isPending || onlyOne}
                    title={
                      onlyOne
                        ? "Cannot revoke your last passkey"
                        : undefined
                    }
                    onClick={() => {
                      if (
                        window.confirm(
                          `Revoke "${p.label}"? You'll need to verify with another passkey.`,
                        )
                      ) {
                        revokeMutation.mutate({
                          credentialId: p.credentialId,
                        });
                      }
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {onlyOne && (
          <p className="muted">
            The Revoke button is disabled because you only have one
            passkey. Register a second one first.
          </p>
        )}
      </section>
    </section>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
