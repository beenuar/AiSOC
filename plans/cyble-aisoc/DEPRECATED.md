# This repository is archived

> **As of 2026-06-27, `beenuar/AISOC-Cyble` is archived and read-only.**

All content from this repository has been merged into the canonical, public,
open-source repository:

## → https://github.com/beenuar/AiSOC

`beenuar/AiSOC` is now the **single source of truth** for the AiSOC project,
including:

- The deployable monorepo at the repo root (`services/`, `apps/`, `infra/`,
  `packages/`, `detections/`, `playbooks/`, etc.).
- The original spec, architecture notes, roadmap, and FastAPI/static
  prototype from this repository, now preserved under
  [`plans/cyble-aisoc/`](https://github.com/beenuar/AiSOC/tree/main/plans/cyble-aisoc).

### How the merge was done

`AISOC-Cyble` was incorporated via `git subtree add --prefix=plans/cyble-aisoc`,
which preserved both founding commits of this repository in the public history:

- `5581d4b Initial import: Cyble AiSOC platform`
- `e4080973 feat(platform): land 13 feature areas from cyble-aisoc-plan.md`

Both commits remain reachable from `main` of `beenuar/AiSOC` via the merge
commit
[`bbaca46e Add 'plans/cyble-aisoc/' from commit 'e4080973…'`](https://github.com/beenuar/AiSOC/commit/bbaca46e)
landed in [PR #324](https://github.com/beenuar/AiSOC/pull/324).

### What to do

- **Update bookmarks and clones** to point at `https://github.com/beenuar/AiSOC`.
- **For the spec doc** (`cyble-aisoc-plan.md`): use
  `https://github.com/beenuar/AiSOC/blob/main/plans/cyble-aisoc/cyble-aisoc-plan.md`.
- **For the prototype code**: it has been superseded by the production
  implementation under `services/` in the new repo. Treat
  `plans/cyble-aisoc/platform/` as historical reference only.

### Why this repo was archived

The project was originally developed here as a private staging area while
the canonical, open-source deployable monorepo lived at `beenuar/AiSOC`.
Keeping two repos in sync became unnecessary friction once the public repo
matured. Consolidation under one MIT-licensed home is simpler for
contributors and clearer for downstream consumers.

— 2026-06-27
