// Plugin API — the framework-agnostic boundary between the React
// shell and individual plugins.
//
// A plugin is a JS module that calls `registerPlugin(...)` (exposed
// on `window.VtcPluginApi`) at load time. The plugin describes:
//
// - `id` — globally unique, used in URLs and DOM ids.
// - `label` — human-readable, shown in the nav.
// - `path` — the route under `/admin/` where the plugin mounts.
// - `element` — the custom-element tag the shell renders. The
//   plugin is responsible for `customElements.define(...)` before
//   `registerPlugin` returns.
// - `icon` (optional) — SVG markup or a single emoji shown in the
//   nav. Falls back to the first letter of `label`.
// - `scopes` (optional) — admin / super-admin / etc. The shell
//   hides the nav entry when the signed-in operator lacks the
//   scope. Plugins should also enforce server-side; this is UX.
//
// Plugin discovery has two sources:
//
// 1. **Built-in plugins** (in `@/plugins/...`) are imported
//    statically from `src/plugins/index.ts::registerBuiltinPlugins`.
//    They ride along with the shell bundle.
//
// 2. **Third-party plugins** are listed in
//    `GET /admin/plugins.json` (served by the daemon) and
//    dynamically `import()`-ed at boot. The daemon serves their
//    files under `/admin/plugins/<id>/`. (Loader implementation
//    lands in a follow-up; the API + registry below already
//    supports it.)
//
// The plugin API surface is intentionally tiny so it can stay
// stable across shell rewrites. Adding capabilities (slot
// extension points, event bus, etc.) is additive — never break
// `registerPlugin`'s shape.

import type { ComponentType } from "react";

export interface PluginManifest {
  /** Stable, unique. Lowercase kebab-case. */
  readonly id: string;
  /** Human-readable nav label. */
  readonly label: string;
  /**
   * Route path under `/admin/`. Leading slash, no trailing.
   * Sub-routes are the plugin's concern (it owns the rest of the
   * URL via its own router).
   */
  readonly path: string;
  /**
   * The custom-element tag name the shell will render when the
   * plugin's route is active. The plugin module is responsible
   * for calling `customElements.define(elementTag, …)` before it
   * calls `registerPlugin`. Mutually exclusive with
   * `reactComponent`.
   */
  readonly elementTag?: string;
  /** Optional SVG / emoji shown in nav. */
  readonly icon?: string;
  /** UX-only scope hint. Server still enforces. */
  readonly scopes?: ReadonlyArray<"admin" | "super-admin">;
  /**
   * **Built-in plugins only**: a React component the shell renders
   * directly instead of a custom element. Lets first-party plugins
   * skip the web-component wrapper without breaking the
   * framework-agnostic boundary for third parties. Set EITHER
   * `elementTag` OR `reactComponent`, never both.
   */
  readonly reactComponent?: ComponentType;
}

// In-memory registry. Plugins register at module load; the shell
// reads on render. The registry is intentionally unsorted (insert
// order = nav order); plugins that care can `path` themselves
// into a particular slot.
const registry: PluginManifest[] = [];

/**
 * Plugin registration entry point.
 *
 * Exposed on `window.VtcPluginApi.registerPlugin` so third-party
 * plugins loaded via `<script type="module">` can call it without
 * importing this module. Built-in plugins import this function
 * directly.
 */
export function registerPlugin(manifest: PluginManifest): void {
  if (manifest.elementTag && manifest.reactComponent) {
    throw new Error(
      `plugin '${manifest.id}' set both elementTag and reactComponent — pick one`,
    );
  }
  if (!manifest.elementTag && !manifest.reactComponent) {
    throw new Error(
      `plugin '${manifest.id}' set neither elementTag nor reactComponent`,
    );
  }
  if (registry.some((p) => p.id === manifest.id)) {
    throw new Error(`plugin '${manifest.id}' is already registered`);
  }
  registry.push(manifest);
}

/** Snapshot of currently-registered plugins, in registration order. */
export function getPlugins(): ReadonlyArray<PluginManifest> {
  return [...registry];
}

/**
 * Resolve a plugin by its `path`. Used by the shell's router to
 * find which plugin owns a given URL.
 */
export function findPluginByPath(path: string): PluginManifest | undefined {
  return registry.find((p) => p.path === path);
}

// Expose the API on `window` so script-tag plugin loaders can use
// it without `import`. Type-safe surface for in-tree plugins (above);
// untyped surface here for third parties.
declare global {
  interface Window {
    VtcPluginApi?: {
      registerPlugin: typeof registerPlugin;
    };
  }
}
if (typeof window !== "undefined") {
  window.VtcPluginApi = { registerPlugin };
}
