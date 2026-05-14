// Built-in plugin registry.
//
// Each first-party plugin lives in its own folder under
// `src/plugins/` and registers itself with the shell here. New
// plugins follow the same shape: write a React component, add a
// `registerPlugin({...})` call below.
//
// Third-party plugins use the same `window.VtcPluginApi
// .registerPlugin` API but call it from their own bundle loaded
// dynamically by the shell. Treating built-ins as plugins
// validates the API every build — if writing a built-in feels
// awkward, the API is wrong.

import { registerPlugin } from "@/plugin-api";
import { Dashboard } from "@/plugins/dashboard";

export function registerBuiltinPlugins(): void {
  registerPlugin({
    id: "dashboard",
    label: "Dashboard",
    path: "/",
    icon: "🏠",
    reactComponent: Dashboard,
  });

  // Later commits add: members, acl, join-requests, profile.
  // Each lands as a self-contained folder under src/plugins/.
}
