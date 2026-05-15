// Tiny fetch wrapper for the daemon's JSON endpoints.
//
// Every call sends credentials so the `vtc_admin_session` cookie
// rides along. Mutating requests (POST/PUT/DELETE/PATCH) mirror the
// `csrf` cookie's value into the `X-CSRF-Token` header for the
// double-submit check in `routing::csrf`.

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

export interface ApiError {
  status: number;
  /** Daemon-formatted error message when the body is JSON. */
  message: string;
}

function csrfTokenFromCookie(): string | null {
  // The CSRF cookie is set by login (`/v1/auth/passkey-login/finish`
  // or `/v1/auth/admin-login`). HttpOnly is **not** set on this
  // cookie precisely so JS can read it.
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match?.[1] ?? null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (method !== "GET" && method !== "HEAD") {
    const csrf = csrfTokenFromCookie();
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, {
    ...init,
    method,
    credentials: "include",
    headers,
  });

  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string; message?: string };
      if (body.error) message = body.error;
      else if (body.message) message = body.message;
    } catch {
      /* non-JSON body */
    }
    const err: ApiError = { status: res.status, message };
    throw err;
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const getJson = <T>(
  path: string,
  extra: { trustTask?: string } = {},
): Promise<T> =>
  request<T>(path, {
    method: "GET",
    headers: extra.trustTask ? { "Trust-Task": extra.trustTask } : undefined,
  });

export const postJson = <T>(
  path: string,
  body: unknown,
  extra: { trustTask?: string } = {},
): Promise<T> =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: extra.trustTask ? { "Trust-Task": extra.trustTask } : undefined,
  });

export const putJson = <T>(
  path: string,
  body: unknown,
  extra: { trustTask?: string } = {},
): Promise<T> =>
  request<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: extra.trustTask ? { "Trust-Task": extra.trustTask } : undefined,
  });

export const patchJson = <T>(
  path: string,
  body: unknown,
  extra: { trustTask?: string } = {},
): Promise<T> =>
  request<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: extra.trustTask ? { "Trust-Task": extra.trustTask } : undefined,
  });

export const deleteJson = <T>(
  path: string,
  extra: { trustTask?: string; body?: unknown } = {},
): Promise<T> =>
  request<T>(path, {
    method: "DELETE",
    body: extra.body === undefined ? undefined : JSON.stringify(extra.body),
    headers: extra.trustTask ? { "Trust-Task": extra.trustTask } : undefined,
  });

export const fetchHealth = (): Promise<HealthResponse> =>
  getJson<HealthResponse>("/health");

export const fetchBuildInfo = (): Promise<BuildInfo> =>
  getJson<BuildInfo>("/admin/build-info.json");

/** Probe: returns true if the current cookie session is valid. */
export async function isSignedIn(): Promise<boolean> {
  try {
    await getJson<unknown>("/v1/community/profile", {
      trustTask: "https://trusttasks.org/openvtc/vtc/community/profile/manage/1.0",
    });
    return true;
  } catch (e) {
    const err = e as ApiError;
    if (err.status === 401 || err.status === 403) return false;
    // Anything else (e.g. 404 "profile not initialised") still means
    // the auth layer let us through. Treat as signed-in.
    return true;
  }
}
