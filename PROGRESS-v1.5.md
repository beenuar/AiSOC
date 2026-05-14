# v1.5 SOC Console Parity — Execution Progress

Plan: `v1.5 SOC Console Parity (local plan doc, not tracked in repo)`
Started: 2026-05-13
Author: Beenu Arora <beenu@cyble.com>
Branch strategy: one branch per PR (`v1.5/pr-N-<slug>`), all targeting `main`.

## Status

| PR | Workstream | Branch | State |
|---|---|---|---|
| PR-1 | W4 + W5 — TimeWindowContext + tenant/role TopBar | `v1.5/pr-1-topbar-context` | pending |
| PR-2 | W2 + W3 — `critical` severity + alert.confidence + narrative | `v1.5/pr-2-severity-confidence` | pending |
| PR-3 | W1 + W9 — Funnel + Efficiency + Pipeline Health | `v1.5/pr-3-funnel-efficiency` | pending |
| PR-4 | W6 — Structured InvestigationRail | `v1.5/pr-4-investigation-rail` | pending |
| PR-5 | W7 — Investigation Queue workbench | `v1.5/pr-5-queue-workbench` | pending |
| PR-6 | W8 — Rule Tuning workbench | `v1.5/pr-6-rule-tuning` | pending |
| PR-7 | W10 — Exposure Ticket lifecycle | `v1.5/pr-7-exposure-tickets` | pending |
| PR-8 | W11 + W12 — `/console` + Correlation + shortcuts + wallboard | `v1.5/pr-8-console-workbench` | pending |
| meta | Feature flags + demo seed | rolled into PRs above | pending |
| meta | Docs + CHANGELOG + AGENTS + v1.5.0 bump | rolled into PRs above | pending |

## Quality gates per PR

- `pnpm -w typecheck` (or per-package) green for touched packages.
- `pnpm -w lint` green for touched packages.
- `pytest services/<svc>` green for touched services.
- New endpoints have unit tests; new components have a snapshot/render test.
- PRs that touch fusion/severity (PR-2) re-grade eval harness and include delta in body.

## Conventions

- Feature flags: `AISOC_FEATURE_CONSOLE`, `AISOC_FEATURE_EXPOSURE_TICKETS`, `AISOC_FEATURE_CRITICAL_SEVERITY` (all default OFF in prod, ON in demo seed).
- Backwards compat: every flat page stays — `/console` is additive.
- All commits authored as `Beenu Arora <beenu@cyble.com>` via `GIT_AUTHOR_*` / `GIT_COMMITTER_*` env vars (no global git config mutation).
