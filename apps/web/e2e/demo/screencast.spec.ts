import { test, expect } from "@playwright/test";

/**
 * 90-second demo screencast recorder.
 *
 * This spec is the single source of truth for the public product
 * walkthrough video that ships under `apps/web/public/demo/demo.mp4`.
 * Every "Shot N" block below maps 1:1 to a heading in
 * `docs/demo/SCREENCAST_SHOTLIST.md`. Changing the shot order or the
 * narration timing here MUST be reflected in the shot list as part of
 * the same PR — there is no other doc downstream.
 *
 * The CI workflow `.github/workflows/screencast.yml` invokes this
 * spec under `pnpm exec playwright test demo/screencast.spec.ts`. It
 * runs against a deployed AiSOC URL (defaults to `tryaisoc.com`); set
 * `AISOC_SCREENCAST_URL` to point at a preview deploy when recording
 * against an unreleased build.
 *
 * What this spec deliberately does NOT do:
 *   * Assert business behaviour. It's a recorder, not a test. If a
 *     selector goes missing, the recorder still completes and the
 *     resulting video shows the failure visually — the QA value is the
 *     human-reviewed cut, not a green check.
 *   * Mutate state. It only navigates and idles. Action-execution
 *     coverage lives in the Phase 4.8 e2e suite.
 */

const PRE_ROLL_MS = 2_000; // 0:00 → 0:02
const SHOT1_MS = 12_000; // 0:02 → 0:14 (Alert arrival)
const SHOT2_MS = 16_000; // 0:14 → 0:30 (Investigation timeline)
const SHOT3_MS = 14_000; // 0:30 → 0:44 (Tool calls + audit)
const SHOT4_MS = 14_000; // 0:44 → 0:58 (Human approval)
const SHOT5_MS = 12_000; // 0:58 → 1:10 (Action executor)
const SHOT6_MS = 10_000; // 1:10 → 1:20 (Compliance + report)
const OUTRO_MS = 10_000; // 1:20 → 1:30

test.describe.configure({ mode: "serial" });

test("90s product walkthrough", async ({ page }, testInfo) => {
  // The base URL is set from AISOC_SCREENCAST_URL via the playwright
  // config; we just navigate to the marketing page first so the
  // pre-roll uses the wordmark as a clean opening frame.
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(PRE_ROLL_MS);

  // --- Shot 1: alerts list ---
  await page.goto("/dashboard/alerts");
  await page.waitForLoadState("domcontentloaded");
  // We never block on a selector — the recorder must finish even if
  // the seed dataset shape changes. The shot list timings are wall-
  // clock, not event-driven.
  await page.waitForTimeout(SHOT1_MS);

  // --- Shot 2: open the most-recent alert ---
  const firstAlert = page
    .locator("[data-testid='alert-row']")
    .first();
  if (await firstAlert.count()) {
    await firstAlert.click({ trial: false }).catch(() => undefined);
  }
  await page.waitForTimeout(SHOT2_MS);

  // --- Shot 3: open the tool-call rail ---
  const toolCallRail = page.locator(
    "[data-testid='investigation-tool-calls']",
  );
  if (await toolCallRail.count()) {
    await toolCallRail
      .scrollIntoViewIfNeeded()
      .catch(() => undefined);
  }
  await page.waitForTimeout(SHOT3_MS);

  // --- Shot 4: trigger the approval modal ---
  const approveButton = page.locator(
    "[data-testid='action-approve']",
  );
  if (await approveButton.count()) {
    await approveButton.first().click({ trial: false }).catch(() => undefined);
  }
  await page.waitForTimeout(SHOT4_MS);

  // --- Shot 5: action executor running ---
  // No interaction — we just hold on the executor card while the
  // recorder rolls.
  await page.waitForTimeout(SHOT5_MS);

  // --- Shot 6: compliance + report ---
  await page.goto("/dashboard/compliance");
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(SHOT6_MS);

  // --- Outro: back to the marketing wordmark ---
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(OUTRO_MS);

  // Capture a poster frame at the wordmark.
  const posterPath = testInfo.outputPath("demo-poster.png");
  await page.screenshot({ path: posterPath, fullPage: false });
  expect(posterPath).toBeTruthy();
});
