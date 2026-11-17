import { defineConfig } from '@playwright/test';

// Kept outside the UI-preview and mocked journey projects: these assertions
// require the actual CORE services and a real bootstrap administrator login.
export default defineConfig({
  testDir: '.',
  testMatch: 'core-byok.spec.ts',
  outputDir: '../../test-results/core-byok',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    browserName: 'chromium',
    baseURL: 'http://localhost:3000',
    viewport: { width: 1440, height: 900 },
    actionTimeout: 10_000,
    // Authenticated requests contain credentials. Retain only the explicit
    // screenshots, not network traces or video.
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
});
