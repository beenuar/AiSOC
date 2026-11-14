import { defineConfig } from "tsup";

// The `src/cli.ts` entry begins with a `#!/usr/bin/env node` shebang, which
// tsup preserves in the emitted `dist/cli.js` so `npx aisoc` can exec it.
export default defineConfig({
  entry: {
    cli: "src/cli.ts",
    index: "src/index.ts",
  },
  format: ["esm"],
  target: "node20",
  platform: "node",
  dts: { entry: { index: "src/index.ts" } },
  clean: true,
  sourcemap: false,
  minify: false,
  splitting: false,
  // Bundle the shared report-card renderer INTO dist so the published `aisoc`
  // package has no unpublished workspace dependency at install time.
  noExternal: ["@aisoc/report-card"],
});
