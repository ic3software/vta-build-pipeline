# vtc-service admin UX

React + TypeScript + Vite source for the VTC's admin console. Built
by `vtc-service`'s `build.rs` and baked into the daemon binary via
`include_dir!` (see `vtc-service/src/admin_ui.rs`). Served at
`/admin/*` when the `admin-ui` cargo feature is on (default).

## Architecture

The shell is a React app. Each feature ships as a **plugin** that
registers itself against `window.VtcPluginApi.registerPlugin(...)`
(or imports `registerPlugin` directly for in-tree plugins).

```
admin-ui/
├── package.json          npm metadata
├── vite.config.ts        Vite build config (base: "/admin/")
├── tsconfig.json         TypeScript config
├── index.html            Vite entry shim
└── src/
    ├── main.tsx          React root + QueryClient + plugin registry boot
    ├── App.tsx           Layout (nav + content) + plugin routes
    ├── plugin-api.ts     Framework-agnostic plugin registration API
    ├── styles.css        Shell + plugin shared styles
    ├── components/
    │   └── PluginHost.tsx  Renders either a React component (in-tree)
    │                       or a custom element (third-party plugin)
    ├── lib/
    │   └── api.ts        Tiny fetch wrapper for daemon JSON endpoints
    ├── pages/
    │   └── Install.tsx   Public install-claim ceremony (unauth route)
    └── plugins/
        ├── index.ts      Built-in plugin registry
        └── dashboard.tsx Health + community profile readout
```

### Plugin boundary

The shell is React; plugins are framework-agnostic. Plugins register
EITHER:

- A **React component** (`reactComponent`) — for in-tree first-party
  plugins that don't want the custom-element wrapper.
- A **custom-element tag** (`elementTag`) — anyone writing a plugin
  in any framework. The shell mounts the custom element into the
  page and the plugin owns the rest.

Both paths share the same `PluginManifest` shape. Third-party
plugins ship as a JS bundle that calls
`window.VtcPluginApi.registerPlugin({...})` at load time.

### Build

```sh
npm install          # one-time
npm run build        # produces dist/
```

`cargo build` (from `vtc-service/`) runs `npm install && npm run
build` automatically via `build.rs`. To skip the build (e.g. in
air-gapped environments shipping a pre-built `dist/`):

```sh
VTC_SKIP_ADMIN_UI_BUILD=1 cargo build -p vtc-service
```

### Develop

```sh
npm run dev          # Vite dev server on :5173, proxies /v1 + /health
                     # to the daemon on localhost:8200
```

Set `VITE_API_PROXY_TARGET=http://other-host:8200` to point at a
different daemon.

## Adding a plugin

1. Create `src/plugins/<name>/` with an `index.tsx` exporting a
   default React component.
2. Add a `registerPlugin({...})` call in `src/plugins/index.ts`.
3. `npm run build`. The new plugin's nav entry shows up next to the
   existing ones.

Third-party plugin authors: drop your built JS bundle into
`data/admin-ui/plugins/<id>/index.js` and register a manifest entry
(loader implementation pending — see the `plugin-api.ts` doc
comment for the planned wire shape).
