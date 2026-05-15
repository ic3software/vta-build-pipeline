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
import { Copy, Mail, Plus, ShieldCheck, X } from "lucide-react";

import { deleteJson, getJson, postJson } from "@/lib/api";
import { useToast } from "@/lib/toast";

const TRUST_TASK_MANAGE =
  "https://trusttasks.org/openvtc/vtc/acl/legacy/manage/1.0";
const TRUST_TASK_ENTRY =
  "https://trusttasks.org/openvtc/vtc/acl/legacy/entry/1.0";
const TRUST_TASK_INVITES_MANAGE =
  "https://trusttasks.org/openvtc/vtc/admin/invites/manage/1.0";
const TRUST_TASK_INVITES_REVOKE =
  "https://trusttasks.org/openvtc/vtc/admin/invites/revoke/1.0";

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
  return getJson<AclListResponse>(`/v1/acl${suffix ? `?${suffix}` : ""}`, {
    trustTask: TRUST_TASK_MANAGE,
  });
}

async function createAcl(req: CreateAclRequest): Promise<AclEntry> {
  return postJson<AclEntry>("/v1/acl", req, { trustTask: TRUST_TASK_MANAGE });
}

async function deleteAcl(did: string): Promise<void> {
  await deleteJson<unknown>(`/v1/acl/${encodeURIComponent(did)}`, {
    trustTask: TRUST_TASK_ENTRY,
  });
}

// ── Admin invites ────────────────────────────────────────────

interface InviteSummary {
  jti: string;
  status: "issued" | "consumed" | "expired";
  expiresAt?: string;
  consumedAt?: string;
}

interface InvitesListResponse {
  invites: InviteSummary[];
}

interface CreateInviteRequest {
  did: string;
  ttlSeconds?: number;
  label?: string;
}

interface CreateInviteResponse {
  jti: string;
  installUrl: string;
  expiresAt: string;
  aclEntryCreated: boolean;
}

async function fetchInvites(): Promise<InvitesListResponse> {
  return getJson<InvitesListResponse>("/v1/admin/invites", {
    trustTask: TRUST_TASK_INVITES_MANAGE,
  });
}

async function createInvite(
  req: CreateInviteRequest,
): Promise<CreateInviteResponse> {
  return postJson<CreateInviteResponse>("/v1/admin/invites", req, {
    trustTask: TRUST_TASK_INVITES_MANAGE,
  });
}

async function revokeInvite(jti: string): Promise<void> {
  await deleteJson<unknown>(`/v1/admin/invites/${encodeURIComponent(jti)}`, {
    trustTask: TRUST_TASK_INVITES_REVOKE,
  });
}

export function Acl() {
  const [contextFilter, setContextFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const queryClient = useQueryClient();
  const toast = useToast();

  const query = useQuery({
    queryKey: ["acl", contextFilter],
    queryFn: () => fetchAcl(contextFilter || null),
    placeholderData: (prev) => prev,
  });

  const revoke = useMutation({
    mutationFn: deleteAcl,
    onSuccess: (_, did) => {
      toast.push("success", `Revoked ACL entry for ${did}`);
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
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
          <div className="spacer" />
          <button
            type="button"
            className={showCreate ? "secondary" : "primary"}
            onClick={() => setShowCreate((v) => !v)}
          >
            {showCreate ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Add entry
              </>
            )}
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
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <ShieldCheck />
                    </span>
                    <h4>No ACL entries match this filter</h4>
                    <p>
                      Use <strong>Add entry</strong> to grant access,
                      or clear the context filter to see every entry.
                    </p>
                  </div>
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

      <InvitesPanel />
    </section>
  );
}

// ─────────────────────────────────────────────────────────────
// Admin invites
// ─────────────────────────────────────────────────────────────

function InvitesPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [showCreate, setShowCreate] = useState(false);

  const query = useQuery({
    queryKey: ["admin-invites"],
    queryFn: fetchInvites,
  });

  const revoke = useMutation({
    mutationFn: revokeInvite,
    onSuccess: (_, jti) => {
      toast.push("success", `Revoked invite ${shortJti(jti)}`);
      void queryClient.invalidateQueries({ queryKey: ["admin-invites"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
  });

  const invites = query.data?.invites ?? [];

  return (
    <>
      <section className="card">
        <div className="toolbar">
          <h3 style={{ margin: 0 }}>Admin invites</h3>
          <p className="lead" style={{ margin: 0, flex: "1 1 auto" }}>
            Mint one-shot install URLs for new admins. Each invite
            grants its <code>did</code> the Admin role on first
            passkey claim.
          </p>
          <button
            type="button"
            className={showCreate ? "secondary" : "primary"}
            onClick={() => setShowCreate((v) => !v)}
          >
            {showCreate ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Invite admin
              </>
            )}
          </button>
        </div>
      </section>

      {showCreate && (
        <CreateInviteForm
          onSuccess={() => {
            setShowCreate(false);
            void queryClient.invalidateQueries({ queryKey: ["admin-invites"] });
            // The invite always ensures an ACL grant exists, so
            // refresh the ACL table too.
            void queryClient.invalidateQueries({ queryKey: ["acl"] });
          }}
        />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load invites</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>JTI</th>
              <th>Status</th>
              <th>Expires / consumed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={4}>Loading…</td>
              </tr>
            )}
            {!query.isPending && invites.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <Mail />
                    </span>
                    <h4>No outstanding invites</h4>
                    <p>Use <strong>Invite admin</strong> to mint an install URL.</p>
                  </div>
                </td>
              </tr>
            )}
            {invites.map((i) => (
              <tr key={i.jti}>
                <td>
                  <code className="truncate" title={i.jti}>
                    {shortJti(i.jti)}
                  </code>
                </td>
                <td>
                  <span className={`chip ${chipForStatus(i.status)}`}>
                    {i.status}
                  </span>
                </td>
                <td>
                  {i.status === "consumed" && i.consumedAt
                    ? `consumed ${formatIso(i.consumedAt)}`
                    : i.expiresAt
                      ? formatIso(i.expiresAt)
                      : "—"}
                </td>
                <td>
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={
                      revoke.isPending ||
                      i.status === "consumed" ||
                      i.status === "expired"
                    }
                    title={
                      i.status === "consumed"
                        ? "Consumed invites cannot be revoked"
                        : i.status === "expired"
                          ? "Already expired — nothing to revoke"
                          : undefined
                    }
                    onClick={() => {
                      if (
                        window.confirm(
                          `Revoke invite ${shortJti(i.jti)}? The install URL stops working immediately.`,
                        )
                      ) {
                        revoke.mutate(i.jti);
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
    </>
  );
}

function CreateInviteForm({ onSuccess }: { onSuccess: () => void }) {
  const [did, setDid] = useState("");
  const [label, setLabel] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState("15");
  const [issued, setIssued] = useState<CreateInviteResponse | null>(null);
  const toast = useToast();

  const mutation = useMutation({
    mutationFn: createInvite,
    onSuccess: (resp) => {
      setIssued(resp);
      toast.push(
        "success",
        resp.aclEntryCreated
          ? `Invited ${did} (ACL admin grant created)`
          : `Invited ${did} (ACL already had admin grant)`,
      );
      onSuccess();
    },
    onError: (err) => toast.pushFromError(err, "Invite failed"),
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const ttl = Number(ttlMinutes);
    mutation.mutate({
      did: did.trim(),
      ttlSeconds: Number.isFinite(ttl) && ttl > 0 ? ttl * 60 : undefined,
      label: label.trim() === "" ? undefined : label.trim(),
    });
  };

  if (issued) {
    return (
      <section className="card">
        <h3>Invite minted</h3>
        <p className="lead">
          Share this single-use URL with the new admin. Expires{" "}
          <strong>{formatIso(issued.expiresAt)}</strong>.
        </p>
        <Field label="Install URL">
          <input type="text" readOnly value={issued.installUrl} />
        </Field>
        <div className="form-actions">
          <button
            type="button"
            className="primary"
            onClick={() => {
              void navigator.clipboard
                .writeText(issued.installUrl)
                .then(() => toast.push("success", "Install URL copied"))
                .catch(() => toast.push("error", "Clipboard write failed"));
            }}
          >
            <Copy size={14} aria-hidden="true" /> Copy install URL
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setIssued(null)}
          >
            Mint another
          </button>
        </div>
      </section>
    );
  }

  return (
    <form onSubmit={onSubmit} className="card form-stack">
      <h3>Invite a new admin</h3>
      <p className="lead">
        Mirrors the <code>vtc admin invite</code> CLI: ensures an
        Admin ACL grant for the DID, then mints a single-use install
        URL the recipient claims with a passkey.
      </p>
      <Field label="DID">
        <input
          type="text"
          placeholder="did:key:z6Mk…"
          value={did}
          onChange={(e) => setDid(e.target.value)}
          required
        />
      </Field>
      <Field label="Label (optional)">
        <input
          type="text"
          placeholder="e.g. ‘Sara — ops on-call’"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <Field label="TTL (minutes; max 1440)">
        <input
          type="number"
          min={1}
          max={1440}
          value={ttlMinutes}
          onChange={(e) => setTtlMinutes(e.target.value)}
          required
        />
      </Field>

      <div className="form-actions">
        <button type="submit" className="primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Minting…" : "Mint invite"}
        </button>
      </div>
    </form>
  );
}

function shortJti(jti: string): string {
  return jti.length > 13 ? `${jti.slice(0, 8)}…${jti.slice(-4)}` : jti;
}

function chipForStatus(status: InviteSummary["status"]): string {
  switch (status) {
    case "issued":
      return "accent";
    case "consumed":
      return "success";
    case "expired":
      return "warning";
  }
}

function formatIso(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function CreateAclForm({ onSuccess }: { onSuccess: () => void }) {
  const [did, setDid] = useState("");
  const [role, setRole] = useState("member");
  const [label, setLabel] = useState("");
  const [contexts, setContexts] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const toast = useToast();

  const mutation = useMutation({
    mutationFn: createAcl,
    onSuccess: (entry) => {
      toast.push("success", `Created ACL entry for ${entry.did}`);
      onSuccess();
    },
    onError: (err) => toast.pushFromError(err, "Create failed"),
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
