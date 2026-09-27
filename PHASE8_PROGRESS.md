# Phase 8 progress (local scratch, not committed)

Worktree `/Users/beenu/Desktop/AiSOC-p8`. `main` was `ac218305` at start, moved to
`c95d05fa` during the work (parallel agents merged #925, #926, #927).

## Shipped as open PRs

- **8.1 retro-hunts** — PR #928, branch `feat/phase8-retro-hunts`, rebased onto
  `c95d05fa`, `mergeable: MERGEABLE`. Consumer for `NEW_IOC`, migration 070,
  `check_ioc_lake_mapping.py`, live ClickHouse proof (19 tests).
- **8.2 KEV exposure** — PR #931, branch `feat/phase8-kev-exposure`, **stacked on
  #928** (base is that branch, not main). 65 tests pass.
- **8.4 hunt library** — PR #930, branch `feat/phase8-hunt-library`, based on
  `c95d05fa`. 68 hunts, `check_hunt_scenarios.py`, `run_hunt_evals.py`.

## 8.3 hunting agent — WRITTEN, UNVERIFIED, UNCOMMITTED

Branch `feat/phase8-hunting-agent` (checked out, off `c95d05fa`). The shell
environment died before the test run, so **none of the following is verified
beyond the two checks noted**. Do not open a PR without finishing the list.

Files written:
- `services/agents/app/hunt/plan.py` — closed field/operator vocabulary + schema
- `services/agents/app/hunt/agent.py` — plan/execute/run, ledger, 2-attempt loop
- `services/api/app/services/retro_hunt/hunt_plan_sql.py` — the compiler
- `services/api/app/api/v1/endpoints/agent_tools.py` — `POST /agent-tools/hunt-plan/execute`
- `services/agents/tests/test_hunt_agent.py` — 25-ish tests
- `scripts/check_hunt_agent_boundary.py` — the gate
- `infra/litellm/config.yaml`, `app/llm/model_pins.py`,
  `services/api/app/services/model_aliases.py` — `aisoc-hunt` role
- `services/agents/app/llm/prompt_registry.py` + `prompts.lock.json` — `hunt.system`

Verified before the shell died:
- `check_hunt_agent_boundary.py` passes, and was proven to detect three injected
  faults (open enum, query-shaped property, ghost field).
- `check_llm_model_routing.py` passes (needed `hunt` added to `ROLES` in
  `services/api/app/services/model_aliases.py`, a third declaration site).
- `check_prompt_lock.py` passes after `--write`.
- `check_route_auth.py` passes. Route uses `lake:query` (an existing permission;
  `hunts:read` does not exist and would have been a silent 403 everywhere).
- Plan validator smoke-tested by hand: refuses `raw_payload`, `regex`,
  `contains` on a numeric field.

NOT done for 8.3:
- `pytest services/agents/tests/test_hunt_agent.py` never ran
- ruff check/format not re-run after the last edit (one E501 in agent.py fixed by
  hand; `services/agents/app/hunt/plan.py` had 3 E501s outstanding)
- `check_gate_contract` / `check_gate_coverage` / `check_test_discovery` not run
- eval harness NOT re-graded (required: this PR touches agents, prompts, tools)
- CHANGELOG, claim matrix, tracker, docs page NOT updated for 8.3
- nothing committed or pushed on this branch

## Resume checklist for 8.3

1. `cd /Users/beenu/Desktop/AiSOC-p8 && git branch --show-current` (expect
   `feat/phase8-hunting-agent`)
2. `/tmp/rufenv/bin/ruff format` + `check` the six files above
3. `cd services/agents && /tmp/triageenv/bin/python -m pytest tests/test_hunt_agent.py -q`
4. `scripts/check_hunt_agent_boundary.py --self-test`
5. `python scripts/run_evals.py --suite all` before and after, deltas in the PR body
6. CHANGELOG `[Unreleased]`, 3 claim-matrix rows, tracker 8.3 box,
   `apps/docs/docs/concepts/` page + `sidebars.ts`
7. Wire the gate into `.github/workflows/ci.yml` beside `check_agent_read_tools`
8. `git add -A && git reset PHASE8_PROGRESS.md && git commit -s`
9. `gh pr create --body-file` (never `--body`)

## Notes worth keeping

- `main` moved twice during this work; rebase before pushing and resolve
  CHANGELOG / claim-matrix conflicts as a **union** (a regex union resolver
  worked: keep ours then theirs, then recount with
  `scripts/check_claim_gate_matrix.py`).
- `[Unreleased]` already carries several `### Added` blocks from parallel
  agents. That is the house state, not something to consolidate.
- Local ClickHouse container `p8-clickhouse` on port 9100 may still be running:
  `docker rm -f p8-clickhouse`.
