# Cyble AiSOC — historical spec + prototype

This directory is the open-source mirror of the (formerly private) `beenuar/AISOC-Cyble`
repository, merged in via `git subtree` on 2026-06-27 to consolidate all
project history under a single public home.

It is **historical / spec content**, not deployed code. The canonical, deployed,
production implementation lives at the repo root (`services/`, `apps/`,
`infra/`, `packages/`, etc.).

## What's in here

| Path | What it is |
| ---- | ---------- |
| `cyble-aisoc-plan.md` | The 79 KB north-star authoring spec that the public monorepo at the root was built against. Treat as read-only. |
| `architecture/` | Early architecture notes: agent topology, integration matrix. Superseded by `docs/architecture/` at the repo root. |
| `roadmap/` | Original 12-month roadmap. Superseded by `ROADMAP.md` + `plans/aisoc_v8.0_north_star_plan_*.plan.md` at the repo root. |
| `platform/` | FastAPI + static-frontend prototype that proved out the agent mesh, vertical detection packs, MSSP white-label, FinOps ledger, marketplace, academy, supply-chain risk, multi-region routing, observability, streaming runtime, threat-actor profiler, TS connector SDK, and more. Re-implemented (and significantly extended) under `services/api/` in the deployed monorepo. |
| `platform/.github/workflows/detections-validate.yml` | Old detection-validation workflow. Inert here (GitHub Actions only triggers workflows in the repo-root `.github/workflows/`). The active equivalent at the root is `.github/workflows/validate-detections.yml`. |
| `AGENTS.md` | Original workspace AGENTS memory. The active AGENTS file is at the repo root. |
| `index.html` | Original landing page. The live landing page is served from `apps/web/`. |

## Why it's preserved

1. **Provenance** — anyone reading the public history can trace how `services/api/app/agents/*` evolved from `platform/backend/app/agents/*`, file-by-file.
2. **Spec ↔ code** — `cyble-aisoc-plan.md` is the source-of-truth design doc; the deployed monorepo implements it.
3. **Reference detection rules** — `platform/backend/app/detections/rules/` contains ~150 YAML rules across cloud / endpoint / identity / network / email / webserver / vertical (healthcare, finserv, manufacturing, retail, public sector) categories. These were the seed corpus for the production detection pack now under `detections/` at the repo root.

## What NOT to do

- **Don't run `platform/`'s Dockerfile in production.** It was a single-process prototype; the deployed system is a multi-service compose (`docker-compose.yml` + `infra/terraform/`).
- **Don't `pip install` from `platform/backend/requirements.txt`.** Versions are frozen to the prototype era; production dependencies are in `services/*/pyproject.toml`.
- **Don't import from `plans.cyble_aisoc.platform.*` into deployed code.** Use the canonical implementations under `services/`.

## CI / scanning policy

CodeQL is configured (`.github/workflows/codeql.yml`) to skip everything under
`plans/cyble-aisoc/**` — its findings would be informational rather than
actionable because nothing under this tree is shipped to users.

The repo-root `validate-detections` workflow only walks the root-level
`detections/` directory; it does not pick up the prototype YAML rules here.

## Git history

The subtree merge preserved both founding commits of AISOC-Cyble:

- `5581d4b Initial import: Cyble AiSOC platform`
- `e4080973 feat(platform): land 13 feature areas from cyble-aisoc-plan.md`

They are reachable from `main` of this repo via the merge commit titled
`Add 'plans/cyble-aisoc/' from commit '<sha>'`.

For future cross-repo syncs, the original is at
`https://github.com/beenuar/AISOC-Cyble` (private). Use `git subtree pull --prefix=plans/cyble-aisoc aisoc-cyble main` if it ever needs to be refreshed.
