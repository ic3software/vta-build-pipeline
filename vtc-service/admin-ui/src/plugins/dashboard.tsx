import { useQuery } from "@tanstack/react-query";

import { fetchHealth, fetchBuildInfo } from "@/lib/api";

export function Dashboard() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth });
  const build = useQuery({
    queryKey: ["build-info"],
    queryFn: fetchBuildInfo,
  });

  return (
    <section className="page">
      <h2>Dashboard</h2>

      <section className="card">
        <h3>Community</h3>
        <dl>
          <dt>VTC DID</dt>
          <dd>
            <code>{health.data?.vtc_did ?? "…"}</code>
          </dd>
          <dt>Mediator DID</dt>
          <dd>
            <code>{health.data?.mediator_did ?? "(none configured)"}</code>
          </dd>
        </dl>
      </section>

      <section className="card">
        <h3>Daemon</h3>
        <dl>
          <dt>Status</dt>
          <dd>{health.data ? `${health.data.status} ✅` : "…"}</dd>
          <dt>Version</dt>
          <dd>
            <code>
              {build.data
                ? `${build.data.version} (${build.data.mode})`
                : "…"}
            </code>
          </dd>
          <dt>Health endpoint</dt>
          <dd>
            <a href="/health" target="_blank" rel="noreferrer">
              GET /health
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
