import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{js,ts,jsx,tsx}"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      // Regression floors set below the measured totals of the owned suites
      // (statements/lines 24.07, branches 67.40, functions 53.23) so coverage
      // cannot silently collapse while still leaving headroom for normal
      // churn; raise these as owned surface coverage grows.
      thresholds: {
        statements: 20,
        branches: 60,
        functions: 45,
        lines: 20,
      },
    },
  },
});
