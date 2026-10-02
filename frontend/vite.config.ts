import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [react(), tsconfigPaths()],
  server: {
    port: 3000,
    // host: true removed — binds to 0.0.0.0 by default, security risk
  },
  build: {
    target: "ES2022",
    sourcemap: false, // Security: do not ship sourcemaps in production
  },
});
