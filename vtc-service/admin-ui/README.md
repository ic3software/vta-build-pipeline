# vtc-service admin UX

In-tree source for the VTC's admin UX (Phase 5 M5.6).

Per Phase 5 D1 (recorded in `tasks/vtc-mvp/phase-5-plan.md`), the
admin UX lives in this repo rather than in a sibling
`OpenVTC/vtc-admin-ui` repo. The trade-off:

- **Pros**: `cargo build` is self-contained — no npm, no node, no
  network, no signed-tarball verification. Operators read the
  source directly alongside the daemon.
- **Cons**: rich SPA tooling (TypeScript, React, Vite) can't live
  here without dragging node into the build path. The shell is
  plain HTML/CSS/JS.

Files in this directory are baked at compile time by
`include_dir!` (see `src/admin_ui.rs`) and served by the
`/admin/*` sub-router when the `admin-ui` cargo feature is on.

## Replacing the placeholder

Operators wanting a richer UX:

1. Build their SPA elsewhere (Vite, Next.js, etc.).
2. Drop the built `index.html`, JS, CSS into this directory.
3. Run `cargo build --release` to bake the new bundle.

WebAuthn cookie sessions land via `POST /v1/auth/admin-login`
(see Phase 5 M5.2.3); the SPA needs to call that endpoint and
include the session cookie + CSRF token on subsequent fetches.
