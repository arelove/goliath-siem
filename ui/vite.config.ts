import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In development the interface runs on Vite's server and sends API requests
// to a goliath running the `api` role on its default address. In production
// goliath serves the built interface itself, on the same origin.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test-setup.ts"],
    restoreMocks: true,
  },
});
