// Tiny fetch wrapper for the daemon's JSON endpoints.
//
// All calls send credentials so cookie-based sessions (post-login)
// ride along. Future expansion: CSRF double-submit cookie, refresh
// retry, typed error variants.

export interface HealthResponse {
  status: string;
  version: string;
  vtc_did?: string;
  mediator_url?: string;
  mediator_did?: string;
}

export interface BuildInfo {
  version: string;
  mode: string;
  indexSha256: string;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: "include" });
  if (!res.ok) {
    throw new Error(`${path} → ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const fetchHealth = (): Promise<HealthResponse> =>
  getJson<HealthResponse>("/health");

export const fetchBuildInfo = (): Promise<BuildInfo> =>
  getJson<BuildInfo>("/admin/build-info.json");
