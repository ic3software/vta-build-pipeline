import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";

import { fetchHealth, fetchBuildInfo } from "@/lib/api";

export function Dashboard() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth });
  const build = useQuery({
    queryKey: ["build-info"],
    queryFn: fetchBuildInfo,
  });

  const status = health.data?.status;
  const mediatorDid = health.data?.mediator_did;
  const vtaDid = health.data?.vta_did;

  return (
    <section className="page">
      <h2>Dashboard</h2>

      <div className="stat-tiles">
        <StatTile
          label="Daemon status"
          value={status ?? "…"}
          foot={
            status === "ok"
              ? "Health check passing"
              : status === undefined
                ? undefined
                : "Investigate `/health` payload"
          }
          tone={
            status === "ok" ? "ok" : status === undefined ? "neutral" : "warn"
          }
        />
        <StatTile
          label="Build"
          value={build.data?.version ?? "…"}
          foot={build.data ? `mode: ${build.data.mode}` : undefined}
          mono
        />
        <StatTile
          label="VTA"
          value={vtaDid ? "Connected" : "Not set"}
          foot={
            vtaDid
              ? "Key-management agent provisioned"
              : "Run `vtc setup` to bind a VTA"
          }
          tone={vtaDid ? "ok" : "warn"}
        />
        <StatTile
          label="Mediator"
          value={mediatorDid ? "Configured" : "Not set"}
          foot={mediatorDid ? "DIDComm transport ready" : "REST-only deployment"}
          tone={mediatorDid ? "ok" : "neutral"}
        />
      </div>

      <section className="card">
        <h3>Identity</h3>
        <dl>
          <dt>VTC DID</dt>
          <dd>
            <code>{health.data?.vtc_did ?? "…"}</code>
          </dd>
          <dt>VTA DID</dt>
          <dd>
            <code>{health.data?.vta_did ?? "(not configured)"}</code>
          </dd>
          <dt>Mediator DID</dt>
          <dd>
            <code>
              {health.data?.mediator_did ?? "(none configured)"}
            </code>
          </dd>
          <dt>Health endpoint</dt>
          <dd>
            <a href="/health" target="_blank" rel="noreferrer">
              <code>GET /health</code>{" "}
              <ExternalLink size={12} aria-hidden="true" />
            </a>
          </dd>
        </dl>
      </section>

      {(health.error || build.error) && (
        <section className="card error">
          <h3>Errors</h3>
          {health.error && <p>health: {String(health.error)}</p>}
          {build.error && <p>build-info: {String(build.error)}</p>}
        </section>
      )}
    </section>
  );
}

function StatTile({
  label,
  value,
  foot,
  tone = "neutral",
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  foot?: string;
  tone?: "ok" | "warn" | "neutral";
  mono?: boolean;
}) {
  return (
    <div className="stat-tile">
      <span className="stat-tile-label">{label}</span>
      <span className={`stat-tile-value${mono ? " mono" : ""}`}>{value}</span>
      {foot && (
        <span
          className={`stat-tile-foot${tone === "ok" ? " ok" : tone === "warn" ? " warn" : ""}`}
        >
          {foot}
        </span>
      )}
    </div>
  );
}
