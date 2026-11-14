import { defineConfig } from "vitest/config";

// Only src/lib is tested here. Those modules are pure by construction —
// storage, the token provider and the API client are all injected — so they
// run under plain Node with no React Native runtime, no Metro and no
// simulator. The screens are deliberately thin over them.
export default defineConfig({
  test: {
    include: ["src/lib/**/*.test.ts"],
    environment: "node",
  },
});
