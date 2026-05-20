import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Smoke-test config for `apps/web`. We only need component-level rendering
// (jsdom) — no SSR, no Next.js server runtime. Anything that requires the
// full Next.js stack should live in an e2e suite (Playwright) instead.
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
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
