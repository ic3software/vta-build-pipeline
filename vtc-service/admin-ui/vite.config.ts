import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// The admin SPA is served by the VTC daemon at `/admin/*`. All
// asset URLs must be relative to that mount, so `base: "/admin/"`.
// The daemon's `admin_ui::serve` handler falls back to `index.html`
// for unknown paths (SPA history mode), so client-side routing
// works for any URL under `/admin/`.
export default defineConfig({
  base: "/admin/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    // `npm run dev` proxies API calls to a locally-running daemon
    // so the React shell can talk to a real backend during
    // development. Operator's local daemon is the default; override
    // via `VITE_API_PROXY_TARGET` if running on a different port.
    port: 5173,
    proxy: {
      "/health": process.env.VITE_API_PROXY_TARGET || "http://localhost:8200",
      "/v1": process.env.VITE_API_PROXY_TARGET || "http://localhost:8200",
    },
  },
});
