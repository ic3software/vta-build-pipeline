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
  // freshly-installed daemon with no auth keys yet. Also the
  // canonical source for the VTC's own DID (post-setup).
  let healthJson = null;
  try {
    healthJson = await fetchJson("/health");
    setText("health-status", `${healthJson.status} (v${healthJson.version})`);
    if (healthJson.vtc_did) {
      setText("community-did", healthJson.vtc_did);
    } else {
      setText("community-did", "(not yet provisioned — run `vtc setup`)");
    }
  } catch (err) {
    setText("health-status", `error: ${err.message}`);
    setText("community-did", `error: ${err.message}`);
  }

  // Community profile — best-effort, for the friendly name +
  // description shown in the header. The endpoint requires no
  // auth for the public fields used here. On a fresh install the
  // profile may not exist yet; the placeholder text from
  // index.html stays in place.
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
    }
  } catch {
    // Silent — leave the placeholder text.
  }
}

refresh();
