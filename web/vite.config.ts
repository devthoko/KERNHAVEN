import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build is embedded into kernhaven-core (internal/core/webui).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/core/webui/dist",
    emptyOutDir: true,
    // The polyfill would inject an inline script, which the CSP forbids.
    modulePreload: { polyfill: false },
    sourcemap: false,
    assetsInlineLimit: 0,
  },
  server: {
    // Development: proxy the API to a locally running Core.
    proxy: { "/api": "http://127.0.0.1:8470" },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
