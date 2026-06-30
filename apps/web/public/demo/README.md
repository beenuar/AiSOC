# `apps/web/public/demo/` — screencast assets

This directory is the **canonical home** for the 90-second AiSOC product
screencast and its accompanying poster/GIF. The marketing landing page,
documentation, and several READMEs link to file paths under this
directory; treat the paths below as a stable contract.

| Asset | Purpose | Source |
|---|---|---|
| `demo.mp4` | 90 s product walkthrough, 1280×720, H.264 + AAC, ≤ 8 MB | recorded by [`.github/workflows/screencast.yml`](../../../../.github/workflows/screencast.yml) following [`docs/demo/SCREENCAST_SHOTLIST.md`](../../../../docs/demo/SCREENCAST_SHOTLIST.md) |
| `demo-poster.png` | 1280×720 poster frame for the `<video>` tag | captured by [`apps/web/e2e/demo/screencast.spec.ts`](../../e2e/demo/screencast.spec.ts) at the cover frame |
| `hero.gif` | README hero loop (≤ 10 s, ≤ 5 MB) | rendered from `demo.mp4` by `scripts/aisoc-demo.ts --record --gif` (lands in Phase 2 of the GitHub on-ramp fix) |

## Why the files are not committed yet

The screencast workflow runs **manually** (`workflow_dispatch`) and
uploads the rendered `.mp4` + poster as **release assets**, not into
this directory. Until the v8.0 launch cut ships, this directory is
empty (`.gitkeep` only) so:

- The placement contract above is documented and discoverable.
- The marketing-site hero (`apps/web/src/components/onboarding/StartHero.tsx`)
  can ship a graceful fallback when the asset is missing.
- Nothing in the repo lies about the asset being available.

The text-only stub at [`apps/web/public/.demo-mp4-placeholder`](../.demo-mp4-placeholder)
captures the recording brief and the do/don't rules for whoever picks
up the recording. Read it before you commit a real `demo.mp4` to this
directory.

## After the screencast ships

When the next maintainer cuts the v8.0 launch screencast:

1. Run the `90s demo screencast (record)` workflow from the Actions
   tab with `release_tag=v8.0.0`.
2. Download the workflow's `screencast-<sha>` artefact.
3. Copy `demo.mp4` and `demo-poster.png` into this directory.
4. Run `pnpm aisoc:demo --record --gif` (lands in Phase 2) to render
   `hero.gif` from the `.mp4`.
5. Open a PR with all three files; the file-size guard in
   [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml)
   will fail the build if any individual asset exceeds its budget.
