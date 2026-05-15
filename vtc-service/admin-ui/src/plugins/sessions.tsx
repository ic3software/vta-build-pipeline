// Sessions plugin — list + revoke active sessions.
//
// Wraps the `/v1/auth/sessions` endpoint family. Lists every active
// session in the daemon's session keyspace, marks the caller's own
// session (so an operator who clicks Revoke on themselves understands
// they're about to be signed out), and offers per-session revoke +
// "revoke all of this DID" buttons.
//
// Purpose: if an operator suspects a cookie has been stolen, they
// open this and revoke the suspect session without having to nuke
// every credential they hold. The backend already enforces that you
// can only revoke your own sessions unless you're admin.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Smartphone } from "lucide-react";

import { deleteJson, fetchWhoami, getJson } from "@/lib/api";
import { useToast } from "@/lib/toast";

const TRUST_TASK_MANAGE =
  "https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/manage/1.0";
const TRUST_TASK_REVOKE =
  "https://trusttasks.org/openvtc/vtc/auth/legacy/sessions/revoke/1.0";

type SessionState = "Pending" | "Authenticated" | "Revoked";

interface SessionSummary {
  sessionId: string;
  did: string;
  state: SessionState;
  createdAt: number;
  refreshExpiresAt: number | null;
}

async function fetchSessions(): Promise<SessionSummary[]> {
  return getJson<SessionSummary[]>("/v1/auth/sessions", {
    trustTask: TRUST_TASK_MANAGE,
  });
}

async function revokeSession(sessionId: string): Promise<void> {
  await deleteJson<unknown>(
    `/v1/auth/sessions/${encodeURIComponent(sessionId)}`,
    { trustTask: TRUST_TASK_REVOKE },
  );
}

async function revokeAllForDid(did: string): Promise<void> {
  await deleteJson<unknown>(
    `/v1/auth/sessions?did=${encodeURIComponent(did)}`,
    { trustTask: TRUST_TASK_MANAGE },
  );
}

export function Sessions() {
  const qc = useQueryClient();
  const toast = useToast();

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });

  // Whoami is already cached by the App shell — re-using the same
  // key (with a `staleTime` carry-over) avoids a duplicate round-trip
  // and lets us mark the caller's own row.
  const whoamiQuery = useQuery({
    queryKey: ["whoami"],
    queryFn: fetchWhoami,
    staleTime: 30_000,
  });

  const revokeOne = useMutation({
    mutationFn: revokeSession,
    onSuccess: (_, sessionId) => {
      toast.push("success", `Revoked session ${shortId(sessionId)}`);
      void qc.invalidateQueries({ queryKey: ["sessions"] });
      // If the operator revoked themselves, the whoami probe will
      // flip to null on next refetch and the shell shows Login.
      void qc.invalidateQueries({ queryKey: ["whoami"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
  });

  const revokeMany = useMutation({
    mutationFn: revokeAllForDid,
    onSuccess: (_, did) => {
      toast.push("success", `Revoked every session for ${did}`);
      void qc.invalidateQueries({ queryKey: ["sessions"] });
      void qc.invalidateQueries({ queryKey: ["whoami"] });
    },
    onError: (err) => toast.pushFromError(err, "Bulk revoke failed"),
  });

  const sessions = sessionsQuery.data ?? [];
  const myDid = whoamiQuery.data?.did;
  const mySessionId = whoamiQuery.data?.sessionId;
  // Group "revoke all for this DID" by DID — only show on the first
  // row of each DID block.
  const seenDids = new Set<string>();

  return (
    <section className="page">
      <h2>Sessions</h2>
      <p className="lead">
        Active server-side sessions in the daemon's session store. If a
        cookie has been compromised, revoke its session here — the
        browser holding it will be signed out on its next request.
      </p>

      {sessionsQuery.isPending && (
        <section className="card">
          <p>Loading sessions…</p>
        </section>
      )}

      {sessions.length === 0 && !sessionsQuery.isPending && (
        <section className="card">
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">
              <Smartphone />
            </span>
            <h4>No active sessions</h4>
            <p>Sessions appear here when an operator signs in.</p>
          </div>
        </section>
      )}

      {sessions.length > 0 && (
        <section className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>DID</th>
                <th>Session</th>
                <th>State</th>
                <th>Created</th>
                <th>Refresh expires</th>
                <th aria-label="Actions"></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const isMine = s.sessionId === mySessionId;
                const showBulk = !seenDids.has(s.did);
                seenDids.add(s.did);
                const sameDidCount = sessions.filter(
                  (x) => x.did === s.did,
                ).length;
                return (
                  <tr key={s.sessionId}>
                    <td>
                      <code className="truncate" title={s.did}>
                        {s.did}
                      </code>
                      {s.did === myDid && (
                        <span className="chip accent" title="Your DID">
                          you
                        </span>
                      )}
                    </td>
                    <td>
                      <code className="truncate" title={s.sessionId}>
                        {shortId(s.sessionId)}
                      </code>
                      {isMine && (
                        <span className="chip accent" title="This browser tab">
                          this tab
                        </span>
                      )}
                    </td>
                    <td>
                      <code>{s.state}</code>
                    </td>
                    <td>{formatEpoch(s.createdAt)}</td>
                    <td>
                      {s.refreshExpiresAt ? (
                        formatEpoch(s.refreshExpiresAt)
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="secondary destructive"
                          disabled={revokeOne.isPending}
                          aria-busy={revokeOne.isPending}
                          onClick={() => {
                            const msg = isMine
                              ? "Revoke YOUR session? You'll be signed out of this tab."
                              : `Revoke session ${shortId(s.sessionId)} for ${s.did}?`;
                            if (window.confirm(msg)) {
                              revokeOne.mutate(s.sessionId);
                            }
                          }}
                        >
                          Revoke
                        </button>
                        {showBulk && sameDidCount > 1 && (
                          <button
                            type="button"
                            className="secondary destructive"
                            disabled={revokeMany.isPending}
                            aria-busy={revokeMany.isPending}
                            title={`Revoke all ${sameDidCount} sessions for ${s.did}`}
                            onClick={() => {
                              if (
                                window.confirm(
                                  `Revoke ALL ${sameDidCount} sessions for ${s.did}?`,
                                )
                              ) {
                                revokeMany.mutate(s.did);
                              }
                            }}
                          >
                            Revoke all for DID
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </section>
  );
}

function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

function formatEpoch(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleString();
  } catch {
    return String(epoch);
  }
}
