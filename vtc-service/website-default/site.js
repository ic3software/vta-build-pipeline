// Default community website — bootstrap shell.
//
// Renders the community profile + health status into the placeholder
// nodes in index.html. When `website.root_dir` is set in the daemon
// config, this script is replaced by the operator's site and never
// runs.

async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) {
    throw new Error(`${url} → ${r.status}`);
  }
  return r.json();
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text;
  }
}

async function refresh() {
  // Health probe — small + unauthenticated so it works on a
  // freshly-installed daemon with no auth keys yet.
  try {
    const health = await fetchJson("/health");
    setText("health-status", JSON.stringify(health));
  } catch (err) {
    setText("health-status", `error: ${err.message}`);
  }

  // Community profile — best-effort. The endpoint requires no
  // auth for the public fields used here. On a fresh install the
  // profile may not exist yet; in that case we leave the
  // placeholder text from index.html in place.
  try {
    const profile = await fetchJson("/v1/community/profile");
    if (profile && typeof profile === "object") {
      if (profile.name) {
        setText("community-name", profile.name);
        document.title = profile.name;
      }
      if (profile.description) {
        setText("community-description", profile.description);
      }
      if (profile.vtcDid || profile.vtc_did) {
        setText("community-did", profile.vtcDid ?? profile.vtc_did);
      }
    }
  } catch (err) {
    setText("community-did", `(profile not yet set: ${err.message})`);
  }
}

refresh();
