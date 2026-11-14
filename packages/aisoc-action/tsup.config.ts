import { defineConfig } from "tsup";

// GitHub Actions run the committed dist/index.js directly with no npm install,
// so everything (@actions/*, aisoc, @aisoc/report-card) must be bundled in.
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["cjs"],
  target: "node20",
  platform: "node",
  clean: true,
  minify: false,
  sourcemap: false,
  splitting: false,
  noExternal: [/.*/],
});
