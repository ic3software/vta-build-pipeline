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
import { JoinRequests } from "@/plugins/joinRequests";
import { Members } from "@/plugins/members";
import { MyPasskeys } from "@/plugins/myPasskeys";
import { Policies } from "@/plugins/policies";
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
    id: "join-requests",
    label: "Join requests",
    path: "/join-requests",
    icon: "📥",
    reactComponent: JoinRequests,
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
    id: "policies",
    label: "Policies",
    path: "/policies",
    icon: "📜",
    reactComponent: Policies,
  });

  registerPlugin({
    id: "profile",
    label: "Community profile",
    path: "/profile",
    icon: "🏷",
    reactComponent: Profile,
  });

  registerPlugin({
    id: "my-passkeys",
    label: "My passkeys",
    path: "/my-passkeys",
    icon: "🔑",
    reactComponent: MyPasskeys,
  });
}
