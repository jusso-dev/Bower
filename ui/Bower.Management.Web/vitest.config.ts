import { defineConfig } from "vitest/config";

export default defineConfig({
  define: {
    "import.meta.env.VITE_BOWER_AUTH_MODE": JSON.stringify("development")
  },
  test: {
    environment: "jsdom"
  }
});
