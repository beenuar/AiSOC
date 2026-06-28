/**
 * Visual regression suite for AiSOC's Storybook design system.
 *
 * Phase 4.7 — Storybook 9 already enumerates every design-system story
 * we have under `apps/web/stories/**` and `apps/web/src/**`. Rather
 * than maintain a hand-rolled list of routes (which would require
 * mocking the entire backend on every release), we build Storybook
 * once, serve it as a static site, and screenshot each story id at
 * desktop + mobile viewports. The result is a deterministic, fully
 * offline visual snapshot of every UI primitive the console exposes.
 *
 * Baselines live next to this spec in
 * ``visual.spec.ts-snapshots/<story-id>-<viewport>.png``. They are
 * captured on Linux (the CI runner) so locally-developed snapshots
 * may differ slightly in font hinting; the CI image is the source of
 * truth and PRs only update the Linux baselines.
 *
 * To refresh baselines intentionally (e.g. after a deliberate visual
 * change), run:
 *
 *   pnpm --filter @aisoc/web exec playwright test \
 *     --project=visual --update-snapshots
 *
 * and commit the updated PNGs.
 */
import { promises as fs } from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";

// Mirrors the layout produced by `pnpm build-storybook`. The
// `index.json` (formerly `stories.json`) sidecar emits one entry per
// story with the routable id we need to feed into `iframe.html`.
const STORYBOOK_INDEX = path.resolve(
  __dirname,
  "..",
  "..",
  "storybook-static",
  "index.json",
);

interface StorybookIndexEntry {
  id: string;
  name: string;
  title: string;
  type?: "story" | "docs";
  tags?: string[];
}

interface StorybookIndex {
  v: number;
  entries: Record<string, StorybookIndexEntry>;
}

// Some stories are deliberately animated / inherently non-deterministic
// (loading shimmer, theme transition, toast portals). We skip them so
// the suite reports real regressions instead of frame-timing noise.
//
// Keep the list short and reviewable; entries here should always come
// with a comment explaining *why* the story is excluded so future
// maintainers can revisit the decision.
const SKIP_STORY_IDS = new Set<string>([
  // Loading shimmer animates continuously; capture is non-deterministic.
  "primitives-skeleton--shimmering",
  // Theme story flips colors mid-transition; the static snapshot races
  // the transition's first frame and produces flaky diffs.
  "foundations-theme--switch",
]);

const VIEWPORTS = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
] as const;

async function loadIndex(): Promise<StorybookIndex> {
  try {
    const raw = await fs.readFile(STORYBOOK_INDEX, "utf8");
    return JSON.parse(raw) as StorybookIndex;
  } catch (err) {
    throw new Error(
      `Storybook index not found at ${STORYBOOK_INDEX}. ` +
        `Run \`pnpm --filter @aisoc/web build-storybook\` before the visual suite. ` +
        `(${(err as Error).message})`,
    );
  }
}

// Stylesheets injected to neutralise non-deterministic effects: caret
// blink, intro animations, CSS transitions, smooth scrolling, etc.
// We apply them after navigation so they take precedence over the
// per-story styles. The values here intentionally over-reach: it is
// fine if a story's "blink" demo no longer blinks in the snapshot, the
// point is that the diff is pixel-stable across runs.
const FREEZE_CSS = `
  *, *::before, *::after {
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0s !important;
    transition-delay: 0s !important;
    caret-color: transparent !important;
  }
  html { scroll-behavior: auto !important; }
`;

const indexPromise = loadIndex();

test.describe("visual regression — Storybook stories", () => {
  // Resolve story IDs once and emit a `test()` per (story, viewport)
  // combo. We do this inside `describe` so Playwright shows a clean
  // hierarchy in the HTML reporter.
  test.beforeAll(async () => {
    await indexPromise;
  });

  for (const viewport of VIEWPORTS) {
    test.describe(`viewport=${viewport.name}`, () => {
      test(`enumerates and snapshots stories`, async ({ page }) => {
        const index = await indexPromise;
        const storyIds = Object.values(index.entries)
          .filter(
            (entry) =>
              entry.type !== "docs" && !SKIP_STORY_IDS.has(entry.id),
          )
          .map((entry) => entry.id)
          .sort();

        expect(
          storyIds.length,
          "Storybook index returned zero stories — did the build succeed?",
        ).toBeGreaterThan(0);

        await page.setViewportSize({
          width: viewport.width,
          height: viewport.height,
        });

        for (const storyId of storyIds) {
          const url = `/iframe.html?id=${encodeURIComponent(
            storyId,
          )}&viewMode=story`;
          await page.goto(url, { waitUntil: "networkidle" });
          // Wait for web-fonts to settle so glyph rasterisation matches
          // across runs. `document.fonts.ready` is the canonical signal.
          await page.evaluate(async () => {
            await (document as Document & {
              fonts: { ready: Promise<unknown> };
            }).fonts.ready;
          });
          await page.addStyleTag({ content: FREEZE_CSS });
          // Brief settle to let the layout reflow after the freeze CSS.
          await page.waitForTimeout(50);
          await expect(page).toHaveScreenshot(
            `${storyId}--${viewport.name}.png`,
            {
              fullPage: true,
              animations: "disabled",
              caret: "hide",
              // 0.5% pixel-diff tolerance per story is enough to ride
              // over GPU-driven anti-aliasing rounding without masking
              // real regressions (which are typically 10-40% diffs).
              maxDiffPixelRatio: 0.005,
              threshold: 0.2,
            },
          );
        }
      });
    });
  }
});
