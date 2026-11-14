# Visual regression (Phase 4.7)

This directory holds the AiSOC design-system visual regression suite.
It runs against the **static Storybook build**, not the live console,
because:

1. Stories are pure UI — they never call out to the FastAPI backend,
   so the suite needs zero API mocking to be deterministic.
2. Stories cover every primitive (`Button`, `Card`, `Badge`,
   `EmptyState`, …) and every composite (`KpiTiles`, `Tabs`,
   `FormFields`, …) the console uses. A regression in those primitives
   ripples into every page; catching it at the story level catches
   it everywhere.
3. The static Storybook bundle is byte-identical run-to-run, so
   Playwright's `toHaveScreenshot()` diff stays at the noise floor.

## Local workflow

```bash
# 1. Build storybook (once per shape-changing edit).
pnpm --filter @aisoc/web build-storybook

# 2. Run the visual suite — first run captures baselines, later runs
#    diff against them.
pnpm --filter @aisoc/web visual

# 3. After an intentional design change, refresh the baselines.
pnpm --filter @aisoc/web visual:update
git add apps/web/e2e/visual/visual.spec.ts-snapshots
git commit -m "design: refresh visual baselines for <change>"
```

The first command produces `apps/web/storybook-static/` and an
`index.json` describing every story id. The visual spec reads that
index, walks each story, and snapshots it at two viewports
(`desktop=1440×900`, `mobile=390×844`).

## CI behaviour

`.github/workflows/visual-regression.yml` runs the suite on every PR
that touches `apps/web/**` or `packages/ui/**`. It uses a pinned
`mcr.microsoft.com/playwright:v1.49.0-jammy` container so font
rendering + Chromium build stay identical between baseline-capture and
diff-runs. Changing that tag invalidates every baseline; expect a
follow-up PR to regenerate them.

On failure the workflow uploads two artifacts:

- `playwright-report/` — the HTML report with diff overlays.
- `playwright-test-results/` — the raw
  `<name>-expected.png` / `<name>-actual.png` / `<name>-diff.png`
  triples for offline review.

## When the diff is real

A genuine regression looks like a 10–40% pixel diff localised to one
component. A run that flags every snapshot is almost always a
container / font / Chromium version drift — bisect by checking the
Playwright tag in `.github/workflows/visual-regression.yml`.

## Excluding non-deterministic stories

Some stories animate continuously (e.g. shimmer loaders) or transition
between states mid-render (e.g. theme switcher). Add their story ids
to `SKIP_STORY_IDS` in `visual.spec.ts` with a one-line comment
explaining why. Keep the list small and reviewable.
