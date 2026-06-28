import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright config for the AiSOC web app.
 *
 * Three projects live here:
 *
 * 1. ``screencast`` (Phase 4.3) — records the 90-second product demo
 *    against a deployed URL configured by ``AISOC_SCREENCAST_URL``.
 *    Default target is the public ``tryaisoc.com`` deployment.
 *
 * 2. ``visual`` (Phase 4.7) — Storybook-driven visual regression. The
 *    ``webServer`` block boots a static `http-server` over
 *    ``storybook-static/`` on port 6007, which the visual spec hits
 *    via ``/iframe.html?id=...``. Run ``pnpm build-storybook`` first,
 *    otherwise the webServer has nothing to serve. Baselines live next
 *    to the spec and are committed to git.
 *
 * 3. ``journey`` (Phase 4.8) — buyer journey E2E. The webServer block
 *    boots ``next dev`` on port 3100 (so it doesn't clash with a
 *    developer's local 3000) and the spec stubs every backend call via
 *    ``page.route()`` so the run is hermetic.
 *
 * Project selection is driven by ``PLAYWRIGHT_PROJECT`` so the
 * webServer block doesn't try to boot a static Storybook for the
 * journey run (or vice versa). When no project is selected (e.g. local
 * ``playwright test`` with no flags), neither webServer is started —
 * the screencast spec is the only one that doesn't need one.
 */
const PROJECT = (process.env.PLAYWRIGHT_PROJECT ?? "").toLowerCase();
const IS_VISUAL = PROJECT === "visual";
const IS_JOURNEY = PROJECT === "journey";

export default defineConfig({
  testDir: "./e2e",
  // Each test gets up to two minutes; the screencast spec itself
  // tops out around 90s of timed shots plus boot overhead. The visual
  // spec is slower (it walks every Storybook story) so we extend the
  // budget only when running that project.
  timeout: IS_VISUAL ? 600_000 : 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 0 : 0,
  workers: 1,
  reporter: process.env.CI ? "line" : "list",
  // Each project gets its own webServer (or none for the screencast,
  // which targets an externally-deployed URL).
  ...(IS_VISUAL && {
    webServer: {
      command:
        "pnpm exec http-server storybook-static -p 6007 -s --cors --silent",
      url: "http://127.0.0.1:6007/index.json",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  }),
  ...(IS_JOURNEY && {
    webServer: {
      // Boot Next on 3100 so a developer's `pnpm dev` on 3000 doesn't
      // collide with this run. `--turbo` keeps the boot under 20s on
      // modern machines. Bind to `localhost` (not `127.0.0.1`) so
      // Next 16's allowedDevOrigins guard doesn't block HMR / asset
      // requests with "Blocked cross-origin request to Next.js dev
      // resource /_next/webpack-hmr from 127.0.0.1".
      command: "pnpm exec next dev -p 3100 --turbo",
      url: "http://localhost:3100",
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      env: {
        // The buyer-journey spec stubs every backend route via
        // `page.route()`. Leaving `NEXT_PUBLIC_API_URL` empty means
        // all API calls go same-origin and our route matcher catches
        // every one of them.
        NEXT_PUBLIC_API_URL: "",
      },
    },
  }),
  use: {
    baseURL: IS_VISUAL
      ? "http://127.0.0.1:6007"
      : IS_JOURNEY
        ? "http://localhost:3100"
        : (process.env.AISOC_SCREENCAST_URL ?? "https://tryaisoc.com"),
    trace: IS_JOURNEY ? "retain-on-failure" : "off",
    screenshot: IS_JOURNEY ? "only-on-failure" : "off",
    video: "off",
    viewport: { width: 1920, height: 1080 },
    actionTimeout: 10_000,
  },
  projects: [
    {
      name: "screencast",
      testMatch: /demo\/screencast\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        deviceScaleFactor: 1,
        // The recorder writes a webm into the test output dir. We
        // override the default codec config so the encoder is
        // deterministic across runner generations.
        video: {
          mode: "on",
          size: { width: 1920, height: 1080 },
        },
      },
    },
    {
      name: "visual",
      testMatch: /visual\/visual\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        // Force 1× DPR so screenshots have a deterministic pixel count
        // regardless of the developer's Retina display vs. the CI VM.
        deviceScaleFactor: 1,
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "journey",
      testMatch: /journeys\/.*\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});
