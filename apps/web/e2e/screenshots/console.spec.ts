import { test } from "@playwright/test";
import { join } from "node:path";

/**
 * README hero screenshots — Phase 2 quick-win on-ramp.
 *
 * Captures the four product views the slim README embeds above the
 * fold (`apps/web/public/screenshots/0{1..4}-*.png`). Each test below
 * writes one PNG directly into the Playwright test-output directory;
 * `scripts/aisoc-demo.ts --screenshots` lifts those PNGs into
 * `apps/web/public/screenshots/` once the run is green.
 *
 * Designed to run against a seeded local demo
 * (`pnpm aisoc:demo --no-open` keeps the stack up); set
 * `AISOC_SCREENCAST_URL` to point at a remote deploy when needed.
 *
 * Like the screencast spec, these tests are recorders, not assertions.
 * A missing selector still produces a screenshot (of whatever the page
 * actually renders) — the human reviews the four PNGs before they
 * land on `main`. The CI gate ensures all four files exist; visual
 * regression for the four PNGs themselves lives in the Storybook
 * `visual` project.
 */

const OUT = (name: string) => join(test.info().outputDir, name);

test.describe.configure({ mode: "serial" });

test("01 — Alerts queue (server-anchored SLA countdowns)", async ({ page }) => {
  await page.goto("/queue");
  await page.waitForLoadState("domcontentloaded");
  // Wait for the queue table to settle (skeleton → real rows). We
  // never block hard on a selector — the recorder must still produce
  // a screenshot even when the UI shape has drifted.
  await page.waitForTimeout(2_500);
  await page.screenshot({ path: OUT("01-alerts-queue.png"), fullPage: false });
});

test("02 — Investigation Rail (deterministic correlation narrative)", async ({ page }) => {
  // Land on the seeded LockBit case; the InvestigationRail renders to
  // the right of the alert detail and is the highest-density visual
  // payload in the console.
  await page.goto("/cases/INC-RT-001?tab=ledger");
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(3_500);
  await page.screenshot({ path: OUT("02-investigation-rail.png"), fullPage: false });
});

test("03 — /hunt workbench (natural-language → ES|QL / SPL / KQL)", async ({ page }) => {
  await page.goto("/hunt");
  await page.waitForLoadState("domcontentloaded");
  // Give the editor enough time to mount + render its preset list.
  await page.waitForTimeout(2_500);
  await page.screenshot({ path: OUT("03-hunt-workbench.png"), fullPage: false });
});

test("04 — Marketplace (plugins, playbooks, detections)", async ({ page }) => {
  await page.goto("/marketplace");
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(2_500);
  await page.screenshot({ path: OUT("04-marketplace.png"), fullPage: false });
});
