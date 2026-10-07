import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4320",
        changeOrigin: true
      },
      "/health": {
        target: "http://127.0.0.1:4320",
        changeOrigin: true
      }
    }
  },
  build: {
    target: "es2022",
    // Production bundles ship without source maps. Set BOWER_SOURCEMAP=true for a
    // hidden map (written to dist, not referenced by the bundle) when debugging.
    sourcemap: process.env.BOWER_SOURCEMAP === "true" ? "hidden" : false,
    outDir: "dist",
    emptyOutDir: true
  }
});
