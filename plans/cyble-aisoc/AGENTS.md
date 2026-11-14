# Workspace memory

## Learned User Preferences

- Never edit `cyble-aisoc-plan.md`; it is the authoring spec — implement against it, do not modify it.
- Do not recreate to-dos that already exist; mark them `in_progress` and work through the list.
- Push through long implementations without stopping until every to-do is complete.
- Production domain is `tryaisoc.com`; strip any `aisoc.dev` references on sight.
- When the user reports a broken page, audit and fix the live `tryaisoc.com` surface rather than only the local build.
- Handle GitHub PRs end-to-end: review, fix any problems, and merge them — do not stop at review; also fix open items in the repo's issue tracker.
- When updating documentation, date the changes so readers know what changed and when, and only document real, verified changes — never hallucinate.
- Don't trust green CI alone on a PR: clone the repo and check out the PR with `gh pr checkout` (PRs come from forks), independently reproduce/validate the fix, and fix adjacent errors the PR or issue missed before merging.

## Learned Workspace Facts

- Project name is "Cyble AiSOC"; GitHub remote is `github.com/beenuar/AiSOC`.
- Workspace root holds `cyble-aisoc-plan.md` (spec), `platform/` (working app), `architecture/`, `roadmap/`; the root itself is not a git checkout.
- Run the platform from `platform/`: `make install`, then `make dev`, then `make demo`; `make stop` to shut down.
- Backend is FastAPI on port `8478` (`uvicorn app.main:app`); frontend is a static server on port `8479`.
- Local DB lives at `platform/backend/data/aisoc.db`; `make clean` wipes it.
- Default LLM is the deterministic mock; set `AISOC_LLM_PROVIDER` plus `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` to use a real model.
- Backend deploys via `platform/backend/Dockerfile` (Fly.io is the target).
- Security findings live at `github.com/beenuar/AiSOC/security/code-scanning`; PR reviews go through `github.com/beenuar/AiSOC/pulls`; open issues are tracked at `github.com/beenuar/AiSOC/issues`.
- `tryaisoc.com/signup` redirects to `cyble.com/contact-us/`.
- The live product dashboard is `tryaisoc.com/dashboard`; deploy the latest repo build there and run a customer-journey review to confirm it works.
- The deployable `beenuar/AiSOC` repo (cloned to a temp dir for PR work; the local workspace is not a checkout) is laid out as `services/api` (FastAPI), `services/realtime` (TypeScript WebSocket/SSE), `apps/` (frontend), and `infra/terraform/`.
- `infra/terraform/` holds per-cloud configs (`gcp/`, `azure/`, `aws/`, `byoc/`) plus reusable `modules/` (e.g. rds, elasticache, kafka); validate with `terraform init -backend=false`, `terraform validate`, and `terraform fmt -check -recursive` — the same checks gate CI.
