// Policies plugin — list + view + activate + upload.
//
// Wraps the `/v1/policies` endpoint family. Each policy is a Rego
// source bound to a purpose (`join`, `removal`, `personhood`, etc.).
// The list view shows version + activation state per purpose;
// detail shows the source; activate flips the per-purpose active
// pointer; upload uploads a new revision (doesn't auto-activate).
//
// Skipped for MVP: the `/test` endpoint (needs a JSON-input editor
// + result rendering) — lands in a follow-up.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";

import { getJson, postJson } from "@/lib/api";

// `policies/upload/1.0` is the only registered Trust-Task on the
// `/v1/policies` and `/v1/policies/{id}` mounts today —
// TrustTaskRouter doesn't support per-method selectors yet, so
// list/show/upload all travel under it.
const TRUST_TASK_UPLOAD =
  "https://trusttasks.org/openvtc/vtc/policies/upload/1.0";
const TRUST_TASK_ACTIVATE =
  "https://trusttasks.org/openvtc/vtc/policies/activate/1.0";

const PURPOSES = [
  "join",
  "removal",
  "personhood",
  "registry",
  "directory",
  "roleDefinitions",
  "crossCommunityRoles",
  "crossCommunityRelationships",
  "relationships",
] as const;

type Purpose = (typeof PURPOSES)[number];
type StatusFilter = "" | "active" | "archived";

interface PolicyRow {
  id: string;
  purpose: Purpose;
  regoSource: string;
  sha256: string;
  activatedAt: string | null;
  authorDid: string;
  createdAt: string;
  version: number;
  isActive: boolean;
}

interface PoliciesPage {
  items: PolicyRow[];
  next_cursor: string | null;
  total_estimate?: number;
}

async function fetchPolicies(params: {
  purpose: Purpose | "";
  status: StatusFilter;
  cursor: string | null;
  limit: number;
}): Promise<PoliciesPage> {
  const q = new URLSearchParams();
  if (params.purpose) q.set("purpose", params.purpose);
  if (params.status) q.set("status", params.status);
  if (params.cursor) q.set("cursor", params.cursor);
  q.set("limit", String(params.limit));
  return getJson<PoliciesPage>(`/v1/policies?${q.toString()}`, {
    trustTask: TRUST_TASK_UPLOAD,
  });
}

async function fetchPolicy(id: string): Promise<PolicyRow> {
  return getJson<PolicyRow>(`/v1/policies/${id}`, {
    trustTask: TRUST_TASK_UPLOAD,
  });
}

async function uploadPolicy(args: {
  purpose: Purpose;
  regoSource: string;
}): Promise<PolicyRow> {
  return postJson<PolicyRow>(
    "/v1/policies",
    { purpose: args.purpose, regoSource: args.regoSource },
    { trustTask: TRUST_TASK_UPLOAD },
  );
}

async function activatePolicy(id: string): Promise<unknown> {
  return postJson<unknown>(`/v1/policies/${id}/activate`, undefined, {
    trustTask: TRUST_TASK_ACTIVATE,
  });
}

export function Policies() {
  return (
    <Routes>
      <Route index element={<PoliciesList />} />
      <Route path=":id" element={<PolicyDetail />} />
    </Routes>
  );
}

function PoliciesList() {
  const [purpose, setPurpose] = useState<Purpose | "">("");
  const [status, setStatus] = useState<StatusFilter>("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["policies", purpose, status, cursor],
    queryFn: () =>
      fetchPolicies({
        purpose,
        status,
        cursor,
        limit: 50,
      }),
    placeholderData: (prev) => prev,
  });

  return (
    <section className="page">
      <h2>Policies</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Purpose</span>
            <select
              value={purpose}
              onChange={(e) => {
                setPurpose(e.target.value as Purpose | "");
                setCursor(null);
              }}
            >
              <option value="">All</option>
              {PURPOSES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
          <label className="field inline">
            <span className="field-label">Status</span>
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as StatusFilter);
                setCursor(null);
              }}
            >
              <option value="">All</option>
              <option value="active">Active only</option>
              <option value="archived">Archived</option>
            </select>
          </label>
          <button
            type="button"
            className={showUpload ? "secondary" : "primary"}
            onClick={() => setShowUpload((v) => !v)}
          >
            {showUpload ? "Cancel" : "+ Upload policy"}
          </button>
        </div>
      </section>

      {showUpload && (
        <UploadPolicyForm
          onSuccess={() => {
            setShowUpload(false);
            void queryClient.invalidateQueries({ queryKey: ["policies"] });
          }}
        />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load policies</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Purpose</th>
              <th>Version</th>
              <th>SHA-256</th>
              <th>Author</th>
              <th>Created</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={6}>Loading…</td>
              </tr>
            )}
            {query.data?.items.length === 0 && (
              <tr>
                <td colSpan={6}>
                  No policies match this filter. Use{" "}
                  <strong>+ Upload policy</strong> to add the first
                  revision for a purpose.
                </td>
              </tr>
            )}
            {query.data?.items.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link to={p.id}>
                    <code>{p.purpose}</code>
                  </Link>
                </td>
                <td>v{p.version}</td>
                <td>
                  <code className="truncate" title={p.sha256}>
                    {p.sha256.slice(0, 12)}…
                  </code>
                </td>
                <td>
                  <code className="truncate" title={p.authorDid}>
                    {p.authorDid}
                  </code>
                </td>
                <td>{formatDate(p.createdAt)}</td>
                <td>
                  {p.isActive ? (
                    <span title="Active">✓ active</span>
                  ) : (
                    <span className="muted">archived</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="pagination">
          <button
            type="button"
            className="secondary"
            disabled={cursor === null}
            onClick={() => setCursor(null)}
          >
            First page
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!query.data?.next_cursor}
            onClick={() => setCursor(query.data?.next_cursor ?? null)}
          >
            Next page →
          </button>
        </div>
      </section>
    </section>
  );
}

function PolicyDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["policy", id],
    queryFn: () => fetchPolicy(id),
    enabled: id.length > 0,
  });

  const activate = useMutation({
    mutationFn: activatePolicy,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["policies"] });
      void queryClient.invalidateQueries({ queryKey: ["policy", id] });
    },
  });

  return (
    <section className="page">
      <button type="button" className="link" onClick={() => navigate("..")}>
        ← Back to policies
      </button>
      <h2>Policy detail</h2>

      {query.isPending && <p>Loading…</p>}
      {query.error && (
        <section className="card error">
          <h3>Failed to load policy</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {query.data && (
        <>
          <section className="card">
            <h3>Header</h3>
            <dl>
              <dt>Purpose</dt>
              <dd>
                <code>{query.data.purpose}</code>
              </dd>
              <dt>Version</dt>
              <dd>v{query.data.version}</dd>
              <dt>SHA-256</dt>
              <dd>
                <code>{query.data.sha256}</code>
              </dd>
              <dt>Author DID</dt>
              <dd>
                <code>{query.data.authorDid}</code>
              </dd>
              <dt>Created</dt>
              <dd>
                <code>{query.data.createdAt}</code>
              </dd>
              <dt>Activated</dt>
              <dd>
                {query.data.activatedAt ? (
                  <code>{query.data.activatedAt}</code>
                ) : (
                  <span className="muted">never</span>
                )}
              </dd>
              <dt>Status</dt>
              <dd>
                {query.data.isActive ? (
                  "✓ active"
                ) : (
                  <span className="muted">archived</span>
                )}
              </dd>
            </dl>

            {!query.data.isActive && (
              <div className="form-actions">
                {activate.error && (
                  <section className="card error">
                    <h3>Activate failed</h3>
                    <p>{(activate.error as Error).message}</p>
                  </section>
                )}
                <button
                  type="button"
                  className="primary"
                  disabled={activate.isPending}
                  onClick={() => {
                    if (
                      window.confirm(
                        `Activate ${query.data.purpose} v${query.data.version}? The current active policy for this purpose becomes archived.`,
                      )
                    ) {
                      activate.mutate(id);
                    }
                  }}
                >
                  {activate.isPending ? "Activating…" : "Activate"}
                </button>
              </div>
            )}
          </section>

          <section className="card">
            <h3>Rego source</h3>
            <pre className="rego-source">{query.data.regoSource}</pre>
          </section>
        </>
      )}
    </section>
  );
}

function UploadPolicyForm({ onSuccess }: { onSuccess: () => void }) {
  const [purpose, setPurpose] = useState<Purpose>("join");
  const [source, setSource] = useState("");
  const mutation = useMutation({
    mutationFn: uploadPolicy,
    onSuccess,
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate({ purpose, regoSource: source });
  };

  return (
    <form onSubmit={onSubmit} className="card form-stack">
      <h3>Upload policy revision</h3>
      <p className="lead">
        Uploading does not activate. You'll see the new revision in
        the list with <em>archived</em> status until you click
        Activate on its detail page.
      </p>
      <label className="field">
        <span className="field-label">Purpose</span>
        <select
          value={purpose}
          onChange={(e) => setPurpose(e.target.value as Purpose)}
          required
        >
          {PURPOSES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span className="field-label">Rego source</span>
        <textarea
          rows={12}
          spellCheck={false}
          placeholder="package vtc.join&#10;&#10;default allow := false&#10;allow if { … }"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          required
        />
      </label>
      {mutation.error && (
        <section className="card error">
          <h3>Upload failed</h3>
          <p>{(mutation.error as Error).message}</p>
        </section>
      )}
      <div className="form-actions">
        <button
          type="submit"
          className="primary"
          disabled={mutation.isPending || source.trim().length === 0}
        >
          {mutation.isPending ? "Compiling…" : "Upload"}
        </button>
      </div>
    </form>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
