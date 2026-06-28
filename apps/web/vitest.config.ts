import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Smoke-test config for `apps/web`. We only need component-level rendering
// (jsdom) — no SSR, no Next.js server runtime. Anything that requires the
// full Next.js stack should live in an e2e suite (Playwright) instead.
//
// Phase 2.2 — coverage gating via v8 provider with explicit floors.
// Measured baseline at the time of introduction:
//   statements 58.08%, branches 51.86%, functions 50.96%, lines 60.08%.
// Floors are baseline minus ~3pp to absorb cherry-picked-test variance
// (a PR that touches only one component re-runs every test, but the
// edge-case branches in untouched code can drift slightly with prod
// dep bumps). Raise these numbers as the suite grows — never lower
// them without a written justification in the PR description.
export default defineConfig({
  // vitest@4 ships against vite@7, which is also what `@vitejs/plugin-react`
  // targets, so the legacy vitest@2 / vite@5 type-bridging cast is no longer
  // needed — `react()` plugs in directly.
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    css: false,
    coverage: {
      // v8 (vitest's recommended provider) reports against code that
      // tests actually import, not against every `src/**/*.ts(x)`.
      // That's the metric we want for a regression gate: removing a
      // test that covers a function will drop coverage, but
      // intentionally untested files (e.g. `src/lib/responder/auth.ts`
      // which is exercised only via the API route layer / e2e) don't
      // pollute the denominator. Whole-tree exhaustive coverage is a
      // separate exercise tracked under Phase 4.8 (Playwright e2e).
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      reportsDirectory: './coverage',
      exclude: [
        // Test infrastructure shouldn't count against itself.
        'src/**/*.{test,spec}.{ts,tsx}',
        'src/test/**',
        // Storybook fixtures are visual-only — no behavioural assertion.
        'src/**/*.stories.{ts,tsx}',
        // Generated types and runtime-only globals.
        'src/**/*.d.ts',
        'src/types/**',
        // Constants module — Phase 1.1 single-source-of-truth file
        // (auto-generated). Nothing to test, would skew the floor.
        'src/data/connectorCount.ts',
      ],
      // CI gate. Baseline measured at Phase 2.2 introduction:
      //   statements 58.08, branches 51.86, functions 50.96, lines 60.08.
      // Floors are baseline minus ~3pp.
      thresholds: {
        statements: 55,
        branches: 48,
        functions: 47,
        lines: 57,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
