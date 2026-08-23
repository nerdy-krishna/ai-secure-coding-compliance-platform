import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react()],
    server: {
      allowedHosts: env.VITE_ALLOWED_HOSTS ? env.VITE_ALLOWED_HOSTS.split(",") : [],
    },
    test: {
      // Browser contracts live under tests/browser and belong exclusively to
      // Playwright. Keep this fast layer scoped to colocated source contracts.
      include: ["src/**/*.test.{ts,tsx}"],
    },
  };
});
