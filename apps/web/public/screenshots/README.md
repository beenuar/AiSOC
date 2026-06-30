# `apps/web/public/screenshots/` — README hero screenshots

This directory holds the four product screenshots that appear in the
`README.md` hero grid:

| Slot | Final path | Today (placeholder) | Caption |
|---|---|---|---|
| 1 | `01-alerts-queue.png` | `01-alerts-queue.svg` | Alerts queue — server-anchored SLA countdowns |
| 2 | `02-investigation-rail.png` | `02-investigation-rail.svg` | Investigation Rail — deterministic correlation narrative |
| 3 | `03-hunt-workbench.png` | `03-hunt-workbench.svg` | `/hunt` workbench — NL → ES&#124;QL / SPL / KQL |
| 4 | `04-marketplace.png` | `04-marketplace.svg` | Marketplace — plugins, playbooks, detections |

## Today

The four `.svg` placeholders ship with the [Phase 2 visuals rollup](../../../../README.md) so the
README image grid never shows a broken image. They are 1440×900 (the
viewport the screenshot spec captures at) and labelled with the path
they will eventually be replaced by.

## After the real screenshots land

When the next maintainer captures the production screenshots:

1. Boot the demo:

   ```bash
   pnpm aisoc:demo --no-open --quick
   ```

2. Capture the four PNGs (writes the files into this directory):

   ```bash
   pnpm aisoc:demo --screenshots
   ```

3. Sanity-check the diff and open a PR:

   ```bash
   git status -s apps/web/public/screenshots/
   git add apps/web/public/screenshots/*.png
   ```

4. In the same PR, swap the four `.svg` references in `README.md`
   to `.png`. Until step 4 lands the README intentionally points at
   the placeholders so a fresh clone never shows a broken image.

The Playwright spec that drives the capture lives at
[`apps/web/e2e/screenshots/console.spec.ts`](../../e2e/screenshots/console.spec.ts).
