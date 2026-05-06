import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Smoke-test config for `apps/web`. We only need component-level rendering
// (jsdom) — no SSR, no Next.js server runtime. Anything that requires the
// full Next.js stack should live in an e2e suite (Playwright) instead.
export default defineConfig({
  // react() returns vite@7 Plugin types; vitest@2 expects vite@5 Plugin types.
  // Cast through unknown to bridge the version gap without changing the runtime.
  plugins: [react() as unknown as import('vitest/config').UserConfig['plugins']],
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
