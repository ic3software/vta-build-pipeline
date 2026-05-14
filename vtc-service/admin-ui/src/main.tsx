import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";

import App from "@/App";
import { registerBuiltinPlugins } from "@/plugins";
import "@/styles.css";

// Single QueryClient instance per page load. Sane defaults: short
// stale time so the operator's view stays fresh, no automatic
// refetch on window focus (annoying for an admin tool that often
// sits open in a background tab).
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Built-in plugins (dashboard, members, ACL, etc.) register
// themselves into the plugin registry at module load. Third-party
// plugins land in a follow-up — the shell's `<PluginLoader />` will
// fetch their manifests and dynamically `import()` their entry
// modules.
registerBuiltinPlugins();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename="/admin">
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
