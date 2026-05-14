// VTC Admin — bootstrap shell.
//
// This is the MVP placeholder UX. It fetches the daemon's build
// info and health status on page load and renders them. A richer
// SPA (login, member CRUD, profile, policies, audit tail) lands as
// a follow-up after Phase 5 closes.

async function fetchJson(url) {
  const r = await fetch(url, { credentials: "include" });
  if (!r.ok) {
    throw new Error(`${url} → ${r.status}`);
  }
  return r.json();
}

async function refreshStatus() {
  const buildEl = document.getElementById("build-version");
  const healthEl = document.getElementById("health-status");

  try {
    const info = await fetchJson("/admin/build-info.json");
    buildEl.textContent = `${info.version} (${info.mode})`;
  } catch (err) {
    buildEl.textContent = `error: ${err.message}`;
  }

  try {
    const health = await fetchJson("/health");
    healthEl.textContent = JSON.stringify(health);
  } catch (err) {
    healthEl.textContent = `error: ${err.message}`;
  }
}

refreshStatus();
