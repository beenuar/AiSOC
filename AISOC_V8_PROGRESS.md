# AiSOC v8.0 — Parallel Team Kickoff Progress

> Tracking doc for the v8.0 north-star release. Mirrors the convention used by
> `AI_STACK_PLAN_PROGRESS.md`: `[ ]` → `[~]` (in flight) → `[x]` (shipped).
> Each task tag (`T1.1` etc.) maps to the v8.0 plan handed to the eng team.

**Branch**: `v8.0/parallel-team-kickoff`
**Started**: 2026-05-13
**Coordinator**: parent agent (this conversation)
**Mode**: 7-track parallel team, kicked off via background subagents

---

## Track-by-track status

### Track 1 — Graph at ingest
- [ ] T1.1 Ingest-side graph writer (P0, L)
- [ ] T1.2 Config snapshots (P0, M) → T1.1
- [x] T1.3 Publish graph schema (P0, S) → T1.1
- [ ] T1.4 Real-time graph-update WebSocket (P1, S) → T1.1

### Track 2 — Agent reasoning: latency + cost
- [ ] T2.1 Pre-fetched context bundle (P0, M) → T1.1
- [ ] T2.2 LangGraph parallel topology (P0, M) → T2.1
- [ ] T2.3 LLM-input contract (P0, M) → T2.1
- [ ] T2.4 Token + USD eval telemetry (P0, S)
- [ ] T2.5 Four-agent brand consolidation (P0, S)

### Track 3 — UI
- [ ] T3.1 SOC Insights dashboard (P1, M) → T2.4
- [ ] T3.2 Effective Permissions (P0, L) → T1.1
- [ ] T3.3 Attack Chains (P0, L) → T1.1
- [ ] T3.4 /hunt NL surface (P0, S-M)
- [ ] T3.5 Business Context Rules (P1, M)
- [ ] T3.6 Slack/Teams Block Kit approvals (P1, M)
- [ ] T3.7 NL → playbook generator (P1, M) → T3.4
- [ ] T3.8 Design system v2 + Storybook (P1, M)

### Track 4 — Connector wave (15 new)
- [ ] T4.1 Cloudflare WAF + Zero Trust (M)
- [ ] T4.2 Tines (S)
- [ ] T4.3 Torq (S)
- [ ] T4.4 Sublime Security (M)
- [ ] T4.5 Abnormal Security (M)
- [ ] T4.6 Lacework — policy violations stream (S, extend)
- [ ] T4.7 Sysdig (M)
- [ ] T4.8 Falco (S)
- [ ] T4.9 HashiCorp Vault audit (M)
- [ ] T4.10 PagerDuty / Opsgenie (S)
- [ ] T4.11 Atlassian Confluence audit (S)
- [ ] T4.12 Box / Dropbox audit (M)
- [ ] T4.13 Datadog logs + APM (M)
- [ ] T4.14 Snowflake audit (M)
- [ ] T4.15 OCI (Oracle Cloud) (M)

### Track 5 — Public benchmark + eval extensions
- [ ] T5.1 Speed + token + USD published (P0, S) → T2.4
- [ ] T5.2 Methodology page (P0, S) → T5.1
- [ ] T5.3 Public-dataset fidelity benchmark (P1, M)
- [ ] T5.4 Public scoreboard page (P1, M) → T5.1
- [ ] T5.5 Wet-eval weekly CI job (P1, S) → T2.4

### Track 6 — Hosted SaaS + GTM surface
- [ ] T6.1 app.aisoc.dev managed waitlist (P0, L) → T1.1, T2.2, T3.2, T3.3
- [x] T6.2 Reference-customer page template (P0, S)
- [x] T6.3 Sovereign + air-gap landing page (P1, S)
- [ ] T6.4 Demo seeder + screencast polish (P1, S)

### Track 7 — Narrative + IDE-driven SOC
- [~] T7.1 Cursor extension (P0, M) — scaffold landed at `services/mcp/cursor-extension/`; marketplace publish deferred
- [ ] T7.2 L0–L4 white paper (P1, S)
- [ ] T7.3 Three anchor blog posts (P1, S) → T5.1, T7.1

---

## Wave-1 kickoff (parallel — weeks 1–3 from the plan)

These independent tasks fire concurrently as background subagents:

| Subagent | Task | Files |
|---|---|---|
| A | T2.5 four-agent rebrand | `services/agents/app/agents/__init__.py`, `apps/docs/docs/architecture/agents.md`, landing copy |
| B | T2.4 token/USD telemetry | `scripts/run_evals.py`, `scripts/render_eval_charts.py`, `apps/docs/docs/benchmark.md` |
| C | T3.4 `/hunt` rebrand + saved/scheduled hunts | `apps/web/src/app/(app)/hunt/`, `services/api/app/api/v1/endpoints/hunts.py` |
| D | T1.1 ingest-side graph writer | `services/ingest/internal/graph/*` |
| E | T1.3 graph schema publication | `apps/docs/docs/architecture/graph-schema.md`, `schemas/graph-schema.yaml`, `scripts/export_graph_schema.py` |
| F | T4 wave-1 connectors (Tines, Torq, Falco, PagerDuty, Confluence) | `services/connectors/app/connectors/<id>.py`, `plugins/<id>/plugin.yaml`, `apps/docs/docs/connectors/<id>.md` |
| G | T7.1 Cursor extension kickoff | `services/mcp/cursor-extension/` |
| H | T5.1 + T5.2 published benchmark + methodology | `apps/docs/docs/benchmark.md`, `apps/docs/docs/benchmark-methodology.md` |
| I | T3.1 SOC Insights dashboard | `apps/web/src/app/(app)/dashboards/soc-insights/page.tsx`, `services/api/app/api/v1/endpoints/insights.py` |

---

## Coordination notes

- **Branch model**: every subagent commits to `v8.0/parallel-team-kickoff`. Conflicts resolved by the coordinator at merge time.
- **No secrets**: no API keys, tokens, or credentials committed (workspace rule).
- **No competitor names** in code/docs/comments (workspace rule).
- **No plan-file edits**: the plan in `plans/` is the source of truth; this file is the progress mirror.
- **CI gate**: each wave-1 finish must keep `pnpm lint` and `python -m pytest services/agents/tests/` green.

---

## Changelog

- 2026-05-13 — Branch created, progress tracker initialised, wave-1 subagents dispatched.
- 2026-05-13 — T1.3 shipped: graph schema v1.0 published (`schemas/graph-schema.yaml`, `apps/docs/docs/architecture/graph-schema.md`) with Mermaid ER diagram, 17 labels, 14 relationships, event-edge convention. CI drift gate at `.github/workflows/graph-schema-check.yml` runs `scripts/export_graph_schema.py --check` on PRs touching the schema or `services/ingest/internal/graph/**`.
- 2026-05-13 — T7.1 IDE extension scaffold landed at `services/mcp/cursor-extension/` (4 MCP-backed commands, typed JSON-RPC client, webview renderer, 19 passing smoke tests; marketplace publish deferred to follow-up).
- 2026-05-13 — T6.2 + T6.3 shipped: GTM marketing surface live without engineering involvement. New `/customers` index + `/customers/[slug]` MDX-driven case-study template (`apps/web/content/customers/example.mdx` template, `apps/web/src/lib/customers.ts` loader, `next-mdx-remote` + `gray-matter` wired into the web app). New `/sovereign` deployment-flexibility one-pager with deployment-mode matrix and any-cloud × any-region grid citing the air-gap overlay, Helm chart, and Terraform modules. Marketing nav (`LandingNav`) and footer (`Footer`) now surface the two new pages.
