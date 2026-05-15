// ACL plugin — list + create + revoke.
//
// Wraps the `/v1/acl` endpoint family. List supports an optional
// context filter (server-side). Create form takes DID, role,
// optional label + allowed contexts + expires_at. Revoke is a
// DELETE on the entry's DID. Edit (PATCH) lands in a follow-up if
// needed — operators can also revoke + recreate today.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { deleteJson, getJson, postJson } from "@/lib/api";

const TRUST_TASK_MANAGE =
  "https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0";
const TRUST_TASK_ENTRY =
  "https://trusttasks.org/openvtc/vtc/acl/legacy/entry/1.0";

interface AclEntry {
  did: string;
  role: string;
  label: string | null;
  allowed_contexts: string[];
  created_at: number;
  created_by: string;
  expires_at: number | null;
}

interface AclListResponse {
  entries: AclEntry[];
}

interface CreateAclRequest {
  did: string;
  role: string;
  label?: string | null;
  allowed_contexts: string[];
  expires_at?: number | null;
}

async function fetchAcl(context: string | null): Promise<AclListResponse> {
  const q = new URLSearchParams();
  if (context) q.set("context", context);
  const suffix = q.toString();
  return getJson<AclListResponse>(`/v1/acl${suffix ? `?${suffix}` : ""}`);
}

async function createAcl(req: CreateAclRequest): Promise<AclEntry> {
  return postJson<AclEntry>("/v1/acl", req, { trustTask: TRUST_TASK_MANAGE });
}

async function deleteAcl(did: string): Promise<void> {
  await deleteJson<unknown>(`/v1/acl/${encodeURIComponent(did)}`, {
    trustTask: TRUST_TASK_ENTRY,
  });
}

export function Acl() {
  const [contextFilter, setContextFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["acl", contextFilter],
    queryFn: () => fetchAcl(contextFilter || null),
    placeholderData: (prev) => prev,
  });

  const revoke = useMutation({
    mutationFn: deleteAcl,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
    },
  });

  return (
    <section className="page">
      <h2>Access control</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Filter by context</span>
            <input
              type="search"
              placeholder="default / ctx-prod / …"
              value={contextFilter}
              onChange={(e) => setContextFilter(e.target.value)}
            />
          </label>
          <button
            type="button"
            className={showCreate ? "secondary" : "primary"}
            onClick={() => setShowCreate((v) => !v)}
          >
            {showCreate ? "Cancel" : "+ Add entry"}
          </button>
        </div>
      </section>

      {showCreate && (
        <CreateAclForm
          onSuccess={() => {
            setShowCreate(false);
            void queryClient.invalidateQueries({ queryKey: ["acl"] });
          }}
        />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load ACL</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {revoke.error && (
        <section className="card error">
          <h3>Revoke failed</h3>
          <p>{(revoke.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>DID</th>
              <th>Role</th>
              <th>Label</th>
              <th>Contexts</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={6}>Loading…</td>
              </tr>
            )}
            {query.data?.entries.length === 0 && (
              <tr>
                <td colSpan={6}>
                  No ACL entries match this filter. Use{" "}
                  <strong>+ Add entry</strong> to grant access.
                </td>
              </tr>
            )}
            {query.data?.entries.map((e) => (
              <tr key={e.did}>
                <td>
                  <code className="truncate" title={e.did}>
                    {e.did}
                  </code>
                </td>
                <td>
                  <code>{e.role}</code>
                </td>
                <td>{e.label ?? "—"}</td>
                <td>
                  {e.allowed_contexts.length === 0 ? (
                    <span className="muted">all</span>
                  ) : (
                    e.allowed_contexts.map((c) => (
                      <code key={c} className="chip">
                        {c}
                      </code>
                    ))
                  )}
                </td>
                <td>
                  {e.expires_at ? (
                    <span title={String(e.expires_at)}>
                      {formatEpoch(e.expires_at)}
                    </span>
                  ) : (
                    <span className="muted">never</span>
                  )}
                </td>
                <td>
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={revoke.isPending}
                    onClick={() => {
                      if (
                        window.confirm(
                          `Revoke ACL entry for ${e.did}? This is immediate and cannot be undone.`,
                        )
                      ) {
                        revoke.mutate(e.did);
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
      </section>
    </section>
  );
}

function CreateAclForm({ onSuccess }: { onSuccess: () => void }) {
  const [did, setDid] = useState("");
  const [role, setRole] = useState("member");
  const [label, setLabel] = useState("");
  const [contexts, setContexts] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const mutation = useMutation({
    mutationFn: createAcl,
    onSuccess,
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const allowed_contexts = contexts
      .split(",")
      .map((c) => c.trim())
      .filter((c) => c.length > 0);
    const exp = expiresAt.trim();
    mutation.mutate({
      did: did.trim(),
      role: role.trim(),
      label: label.trim() === "" ? null : label.trim(),
      allowed_contexts,
      expires_at: exp === "" ? null : Number(exp) || null,
    });
  };

  return (
    <form onSubmit={onSubmit} className="card form-stack">
      <h3>New ACL entry</h3>
      <Field label="DID">
        <input
          type="text"
          placeholder="did:key:z6Mk…"
          value={did}
          onChange={(e) => setDid(e.target.value)}
          required
        />
      </Field>
      <Field label="Role">
        <input
          type="text"
          placeholder="admin / moderator / member / custom:editor"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          required
        />
      </Field>
      <Field label="Label (optional)">
        <input
          type="text"
          placeholder="e.g. ‘Ops on-call rotation 2026 Q1’"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <Field label="Allowed contexts (comma-separated; blank = all)">
        <input
          type="text"
          placeholder="default, ctx-prod"
          value={contexts}
          onChange={(e) => setContexts(e.target.value)}
        />
      </Field>
      <Field label="Expires at (unix seconds; blank = never)">
        <input
          type="number"
          placeholder="1735689600"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
      </Field>

      {mutation.error && (
        <section className="card error">
          <h3>Create failed</h3>
          <p>{(mutation.error as Error).message}</p>
        </section>
      )}

      <div className="form-actions">
        <button type="submit" className="primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Creating…" : "Create entry"}
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

function formatEpoch(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleString();
  } catch {
    return String(epoch);
  }
}
