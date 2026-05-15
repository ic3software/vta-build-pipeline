// Members plugin — list + detail (read-only).
//
// Reads `GET /v1/members` (paginated, optional role filter) and
// `GET /v1/members/{did}` for the detail view. Mutations (promote,
// admin-remove) land in a follow-up commit; this is the read
// surface only.

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, Route, Routes, useNavigate, useParams } from "react-router-dom";

import { getJson } from "@/lib/api";

interface MemberRow {
  did: string;
  role: string;
  label: string | null;
  joinedAt: string;
  publishConsent: boolean;
  departurePreference: string;
  statusListIndex: number | null;
  currentVmcId: string | null;
  currentRoleVecId: string | null;
  extensions: unknown;
  personhood: boolean;
  personhoodAssertedAt: string | null;
}

interface MembersPage {
  items: MemberRow[];
  next_cursor: string | null;
  total_estimate?: number;
}

async function fetchMembers(params: {
  cursor: string | null;
  role: string | null;
  limit: number;
}): Promise<MembersPage> {
  const q = new URLSearchParams();
  if (params.cursor) q.set("cursor", params.cursor);
  if (params.role) q.set("role", params.role);
  q.set("limit", String(params.limit));
  return getJson<MembersPage>(`/v1/members?${q.toString()}`);
}

async function fetchMember(did: string): Promise<MemberRow> {
  return getJson<MemberRow>(`/v1/members/${encodeURIComponent(did)}`);
}

export function Members() {
  return (
    <Routes>
      <Route index element={<MembersList />} />
      <Route path=":did" element={<MemberDetail />} />
    </Routes>
  );
}

function MembersList() {
  const [roleFilter, setRoleFilter] = useState<string>("");
  const [cursor, setCursor] = useState<string | null>(null);
  const limit = 50;

  const query = useQuery({
    queryKey: ["members", roleFilter, cursor, limit],
    queryFn: () =>
      fetchMembers({
        cursor,
        role: roleFilter || null,
        limit,
      }),
    placeholderData: (prev) => prev,
  });

  return (
    <section className="page">
      <h2>Members</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Filter by role</span>
            <input
              type="search"
              placeholder="admin / moderator / custom:editor"
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value);
                setCursor(null);
              }}
            />
          </label>
        </div>
      </section>

      {query.error && (
        <section className="card error">
          <h3>Failed to load members</h3>
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
              <th>Joined</th>
              <th>Personhood</th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {query.data?.items.length === 0 && (
              <tr>
                <td colSpan={5}>No members match this filter.</td>
              </tr>
            )}
            {query.data?.items.map((m) => (
              <tr key={m.did}>
                <td>
                  <Link to={encodeURIComponent(m.did)}>
                    <code className="truncate">{m.did}</code>
                  </Link>
                </td>
                <td>
                  <code>{m.role}</code>
                </td>
                <td>{m.label ?? "—"}</td>
                <td>{formatDate(m.joinedAt)}</td>
                <td>
                  {m.personhood ? (
                    <span title="Asserted">✓</span>
                  ) : (
                    <span title="Not asserted" className="muted">
                      —
                    </span>
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
          {query.data?.total_estimate !== undefined && (
            <span className="muted">
              ~{query.data.total_estimate} total
            </span>
          )}
        </div>
      </section>
    </section>
  );
}

function MemberDetail() {
  const { did = "" } = useParams<{ did: string }>();
  const navigate = useNavigate();
  const decoded = decodeURIComponent(did);

  const query = useQuery({
    queryKey: ["member", decoded],
    queryFn: () => fetchMember(decoded),
    enabled: decoded.length > 0,
  });

  return (
    <section className="page">
      <button type="button" className="link" onClick={() => navigate("..")}>
        ← Back to members
      </button>
      <h2>Member detail</h2>

      {query.isPending && <p>Loading…</p>}
      {query.error && (
        <section className="card error">
          <h3>Failed to load member</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {query.data && (
        <>
          <section className="card">
            <h3>Identity</h3>
            <dl>
              <dt>DID</dt>
              <dd>
                <code>{query.data.did}</code>
              </dd>
              <dt>Role</dt>
              <dd>
                <code>{query.data.role}</code>
              </dd>
              <dt>Label</dt>
              <dd>{query.data.label ?? "—"}</dd>
              <dt>Joined</dt>
              <dd>
                <code>{query.data.joinedAt}</code>
              </dd>
            </dl>
          </section>

          <section className="card">
            <h3>Personhood</h3>
            <dl>
              <dt>Asserted</dt>
              <dd>{query.data.personhood ? "Yes" : "No"}</dd>
              {query.data.personhoodAssertedAt && (
                <>
                  <dt>Asserted at</dt>
                  <dd>
                    <code>{query.data.personhoodAssertedAt}</code>
                  </dd>
                </>
              )}
            </dl>
          </section>

          <section className="card">
            <h3>Credentials</h3>
            <dl>
              <dt>Status-list index</dt>
              <dd>
                {query.data.statusListIndex === null
                  ? "—"
                  : query.data.statusListIndex}
              </dd>
              <dt>Current VMC</dt>
              <dd>
                {query.data.currentVmcId ? (
                  <code>{query.data.currentVmcId}</code>
                ) : (
                  "—"
                )}
              </dd>
              <dt>Current role VEC</dt>
              <dd>
                {query.data.currentRoleVecId ? (
                  <code>{query.data.currentRoleVecId}</code>
                ) : (
                  "—"
                )}
              </dd>
            </dl>
          </section>

          <section className="card">
            <h3>Disposition + consent</h3>
            <dl>
              <dt>Publish consent</dt>
              <dd>{query.data.publishConsent ? "Yes" : "No"}</dd>
              <dt>Departure preference</dt>
              <dd>
                <code>{query.data.departurePreference}</code>
              </dd>
            </dl>
          </section>
        </>
      )}
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
