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
import { Acl } from "@/plugins/acl";
import { Dashboard } from "@/plugins/dashboard";
import { Members } from "@/plugins/members";
import { Profile } from "@/plugins/profile";

export function registerBuiltinPlugins(): void {
  registerPlugin({
    id: "dashboard",
    label: "Dashboard",
    path: "/",
    icon: "🏠",
    reactComponent: Dashboard,
  });

  registerPlugin({
    id: "members",
    label: "Members",
    path: "/members",
    icon: "👥",
    reactComponent: Members,
  });

  registerPlugin({
    id: "acl",
    label: "Access control",
    path: "/acl",
    icon: "🔐",
    reactComponent: Acl,
  });

  registerPlugin({
    id: "profile",
    label: "Community profile",
    path: "/profile",
    icon: "🏷",
    reactComponent: Profile,
  });

  // Later commits add: join-requests.
}
