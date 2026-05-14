# AiSOC v8.0 — Parallel Team Kickoff Progress

> Tracking doc for the v8.0 north-star release. Mirrors the convention used by
> `AI_STACK_PLAN_PROGRESS.md`: `[ ]` → `[~]` (in flight) → `[x]` (shipped).
> Each task tag (`T1.1` etc.) maps to the v8.0 plan handed to the eng team.

**Branch**: `v8.0/agentic-soc-foundation` (renamed mid-session from `v8.0/parallel-team-kickoff`; rename commit is `20bbb749`)
**Started**: 2026-05-13
**Coordinator**: parent agent (this conversation)
**Mode**: 7-track parallel team, kicked off via background subagents
**Author**: Prince Sinha · [@prince30121](https://github.com/prince30121) · Senior Director, Innovations at Cyble

### Git remote model

- `origin` → `https://github.com/prince30121/AiSOC.git` (fork — push target)
- `upstream` → `https://github.com/beenuar/AiSOC.git` (canonical — PR target)

Work lands on the fork; the integration PR is raised against `upstream/main`.

PR compare URL (click to finalise on GitHub):
`https://github.com/beenuar/AiSOC/compare/main...prince30121:AiSOC:v8.0/agentic-soc-foundation?expand=1`

PR title: `v8.0 wave-1 shipped + wave-2 checkpoint`

PR body: see `.pr-body-wave1.md` (gitignored — local working copy). Paste the full contents into the GitHub web UI when opening the PR.

Status (refreshed 2026-05-14, 11:35 IST): wave-2 worker subagents errored mid-task; their checkpoint output is now committed as 11 per-track `(wip)` commits + 2 progress-doc commits on top of the wave-1 base. Branch was renamed to `v8.0/agentic-soc-foundation` mid-session and pushed to fork at HEAD `7c822a5f` (44 commits ahead of `upstream/main`). `gh` CLI is unauthenticated on this workstation, so the PR is **pending — paste the compare URL above into the browser** with the body from `.pr-body-wave1.md`.

Wave-2 commits (most recent first, all SSH-signed, attributed Prince Sinha):
- `ecf2ffe1` T7.3 three anchor blog posts (graph, latency, L0–L4) (wip)
- `6dba7234` T5.4 public benchmark scoreboard + bench page polish (wip)
- `700a9452` T5.5 wet-eval weekly CI workflow + secrets doc (wip)
- `23d92541` T5.3 fidelity benchmark on public datasets (wip)
- `ee52d642` T4 wave-2 — Cloudflare ZT, Sysdig, Vault, Snowflake, OCI, Sublime, Abnormal, Box, Dropbox, Datadog (wip)
- `57f93a98` T3.6 Block Kit + Adaptive Cards + email fallback (wip)
- `0efe3da5` T3.5 business-context rule engine + Monaco editor (wip)
- `8df637b9` T3.3 attack-chain timeline + ranking (wip)
- `a6ce3342` T3.2 effective permissions resolver (AWS done, others scaffolded) (wip)
- `87c151a7` T2.3 LLM input contract — fail-closed validator (wip)
- `5a0d179f` T1.2 config snapshots — :CONFIGURED_AS {ts} edges (wip)
- `2c7a66c1` T2.1 pre-fetched ContextBundle

### Commit signing

- Local repo only (workspace rule: no global config touched)
- SSH-based signing via `~/.ssh/id_rsa.pub` (`commit.gpgsign = true`, `tag.gpgsign = true`)
- Allowed signers at `.git/allowed_signers` (untracked — local only)
- All wave-1 commits re-signed via `git rebase --exec 'git commit --amend --no-edit --reset-author -S'` against `upstream/main`
- New commits also carry `Signed-off-by: Prince Sinha <prince.sinha@cyble.com>` (DCO trailer)

---

## Track-by-track status

### Track 1 — Graph at ingest
- [~] T1.1 Ingest-side graph writer (P0, L) — scaffold landed: schema v1.0 + Neo4j writer + extractors for `aws_security_hub` / `github_audit` / `okta_system_log` / `kubernetes_audit` + generic fallback for the other 10 source types + `security.graph_updates` Kafka topic + fan-out wiring (failures NEVER block fusion); 16 Go unit tests green; Python integration test stubbed (`services/agents/tests/test_graph_freshness.py`, `pytest -m integration`). 360-event corpus + remaining connector mappings deferred to T1.2 / T4 wave.
- [~] T1.2 Config snapshots (P0, M) → T1.1 — partial / wip — `5a0d179f` (`:CONFIGURED_AS {ts}` edges + connector overrides for AWS / GitHub / Okta; Azure + GCP overrides pending)
- [x] T1.3 Publish graph schema (P0, S) → T1.1
- [ ] T1.4 Real-time graph-update WebSocket (P1, S) → T1.1

### Track 2 — Agent reasoning: latency + cost
- [~] T2.1 Pre-fetched context bundle (P0, M) → T1.1 — partial / wip — `2c7a66c1` (ContextBundle dataclass + parallel pre-fetch from graph/RAG/threat-intel; integration into LangGraph pending T2.2)
- [ ] T2.2 LangGraph parallel topology (P0, M) → T2.1
- [~] T2.3 LLM-input contract (P0, M) → T2.1 — partial / wip — `87c151a7` (fail-closed Pydantic validator on tool input/output; wiring into all agents pending)
- [x] T2.4 Token + USD eval telemetry (P0, S)
- [x] T2.5 Four-agent brand consolidation (P0, S)

### Track 3 — UI
- [x] T3.1 SOC Insights dashboard (P1, M) → T2.4
- [~] T3.2 Effective Permissions (P0, L) → T1.1 — partial / wip — `4ff1b7f4` (graph schema edge) + `a6ce3342` (resolver — AWS done, Azure / GCP / Okta / Google Workspace scaffolded; Cytoscape UI pending)
- [~] T3.3 Attack Chains (P0, L) → T1.1 — partial / wip — `8df637b9` (timeline ranking service + `041_attack_chains.sql` migration + `/v1/cases/{id}/attack-chain` endpoint; UI pending)
- [~] T3.4 /hunt NL surface (P0, S-M) — endpoints/UI/redirect shipped; scheduler is feature-flagged off by default (`AISOC_HUNT_SCHEDULER_ENABLED=0`) with execution stub pending real ES|QL runner wiring
- [~] T3.5 Business Context Rules (P1, M) — partial / wip — `0efe3da5` (rule engine + Monaco editor scaffold; eval engine + persistence pending)
- [~] T3.6 Slack/Teams Block Kit approvals (P1, M) — partial / wip — `57f93a98` (Block Kit + Adaptive Cards + email fallback + HMAC verify + audit/timeout services)
- [~] T3.7 NL → playbook generator (P1, M) → T3.4 — partial / wip (covered alongside T3.5 in `0efe3da5`; schema-validation retry loop pending)
- [~] T3.8 Design system v2 + Storybook (P1, M) — partial / wip (Storybook scaffold landed with T3.6 commit; full token sweep pending)

### Track 4 — Connector wave (15 new)
- [~] T4.1 Cloudflare WAF + Zero Trust (M) — partial / wip — landed in `ee52d642` (Zero Trust audit; WAF rules pending)
- [x] T4.2 Tines (S)
- [x] T4.3 Torq (S)
- [~] T4.4 Sublime Security (M) — partial / wip — landed in `ee52d642`
- [~] T4.5 Abnormal Security (M) — partial / wip — landed in `ee52d642`
- [~] T4.6 Lacework — policy violations stream (S, extend) — partial / wip — extension landed in `ee52d642` (`_normalize_policy` for policy-violation events)
- [~] T4.7 Sysdig (M) — partial / wip — landed in `ee52d642`
- [x] T4.8 Falco (S)
- [~] T4.9 HashiCorp Vault audit (M) — partial / wip — landed in `ee52d642`
- [x] T4.10 PagerDuty / Opsgenie (S)
- [x] T4.11 Atlassian Confluence audit (S)
- [~] T4.12 Box / Dropbox audit (M) — partial / wip — landed in `ee52d642`
- [~] T4.13 Datadog logs + APM (M) — partial / wip — landed in `ee52d642` (logs scaffolded; APM trace correlation pending)
- [~] T4.14 Snowflake audit (M) — partial / wip — landed in `ee52d642`
- [~] T4.15 OCI (Oracle Cloud) (M) — partial / wip — landed in `ee52d642`

### Track 5 — Public benchmark + eval extensions
- [x] T5.1 Speed + token + USD published (P0, S) → T2.4
- [x] T5.2 Methodology page (P0, S) → T5.1
- [~] T5.3 Public-dataset fidelity benchmark (P1, M) — partial / wip — `23d92541` (CICIDS-2017 micro fixture + fidelity harness scaffold; CTU-13 dataset + benchmark page sweep pending)
- [~] T5.4 Public scoreboard page (P1, M) → T5.1 — partial / wip — `6dba7234` (`/benchmark-scoreboard` MDX page + scoreboard.json data file + `/benchmark` page polish; live data feed pending)
- [~] T5.5 Wet-eval weekly CI job (P1, S) → T2.4 — partial / wip — `700a9452` (`.github/workflows/wet-eval.yml` + secrets doc + `wet_eval_check.py`; OPENAI_API_KEY secret needs setting in repo)

### Track 6 — Hosted SaaS + GTM surface
- [ ] T6.1 app.aisoc.dev managed waitlist (P0, L) → T1.1, T2.2, T3.2, T3.3
- [x] T6.2 Reference-customer page template (P0, S)
- [x] T6.3 Sovereign + air-gap landing page (P1, S)
- [x] T6.4 Demo seeder + screencast polish (P1, S)

### Track 7 — Narrative + IDE-driven SOC
- [~] T7.1 Cursor extension (P0, M) — scaffold landed at `services/mcp/cursor-extension/`; marketplace publish deferred
- [x] T7.2 L0–L4 white paper (P1, S)
- [~] T7.3 Three anchor blog posts (P1, S) → T5.1, T7.1 — partial / wip — `ecf2ffe1` (three drafts: graph-at-ingest, sub-minute latency, L0–L4 maturity; copy edit pass pending)

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

- **Branch model**: every subagent commits to `v8.0/agentic-soc-foundation`. Conflicts resolved by the coordinator at merge time.
- **Push target**: `origin` (fork at `prince30121/AiSOC`).
- **PR target**: `upstream/main` (`beenuar/AiSOC:main`).
- **No secrets**: no API keys, tokens, or credentials committed (workspace rule).
- **No competitor names** in code/docs/comments (workspace rule).
- **No plan-file edits**: the plan in `plans/` is the source of truth; this file is the progress mirror.
- **CI gate**: each wave-1 finish must keep `pnpm lint` and `python -m pytest services/agents/tests/` green.
- **DCO**: all commits sign-off with `Signed-off-by: Prince Sinha <prince.sinha@cyble.com>` and SSH-sign via `id_rsa`.

## Wave-1 summary

- **29 commits** on `v8.0/agentic-soc-foundation` since `upstream/main`
- **12 of 12** subagents finished (10 `[x]` shipped, 2 `[~]` scaffold-landed: T1.1 graph writer foundation, T7.1 IDE extension scaffold)
- **0 secrets** committed (workspace rule)
- **0 competitor names** introduced (workspace rule)
- **Foundation laid for wave-2**: T1.1 unblocks T1.2 / T1.4 / T2.1 / T3.2 / T3.3 / T6.1; T2.4 telemetry unblocks T5.4 / T5.5; T3.4 `/hunt` unblocks T3.7 NL→playbook

---

## Changelog

- 2026-05-13 — Wave-1 integration: 29 commits re-signed and re-authored as `Prince Sinha <prince.sinha@cyble.com>` via `git rebase --exec '... --reset-author -S'` against `upstream/main`; SSH commit signing configured locally with `~/.ssh/id_rsa.pub`; `Signed-off-by` DCO trailer applied to new commits. Branch ready to push to `origin` (fork) and PR against `upstream/main`.
- 2026-05-13 — T1.1 ingest-side graph writer scaffold landed (status `[~]`). New package `services/ingest/internal/graph/` with `schema.go` (versioned v1.0 — 17 node labels + 14 relationships matching `schemas/graph-schema.yaml`), `writer.go` (Neo4j Bolt driver, batched UNWIND upserts keyed on `(label, natural_key)` + props_hash, bounded queue with drop-and-metric so failures never block fusion, root-context cancellation for prompt shutdown), and `extractor.go` (real extractors for `aws_security_hub` / `github_audit` / `okta_system_log` / `kubernetes_audit` plus a generic fallback that pulls actor + endpoint nodes from any OCSF event so the other 10 source types still produce a non-empty projection). `services/ingest/internal/handler/handler.go` fan-outs into the writer concurrently with the fusion publish (graph failure never blocks). New `PublishGraphUpdate` on the Kafka publisher emits `{entity_id, change_type, ts, label, rel_type, schema_version}` envelopes to a new `security.graph_updates` topic for T1.4. New env config: `AISOC_GRAPH_ENABLED` (default off), `AISOC_NEO4J_URI` / `AISOC_NEO4J_USER` / `AISOC_NEO4J_PASSWORD` (env-only, never committed), `AISOC_GRAPH_BATCH_SIZE`, `AISOC_GRAPH_FLUSH_INTERVAL_MS`, `AISOC_GRAPH_QUEUE_SIZE`, `AISOC_GRAPH_UPDATES_TOPIC`. 16 Go unit tests at `services/ingest/internal/graph/{writer,extractor}_test.go` green in 1.3s — exercise UNWIND batching, idempotency on natural_key, partial-failure surfacing, queue-full drop, the never-blocks-on-failure contract (blocking fake driver hangs but `WriteEvent` returns immediately), and per-extractor entity/edge shapes. Python integration test at `services/agents/tests/test_graph_freshness.py` (`@pytest.mark.integration`) probes p95 < 2s graph freshness end-to-end, skips cleanly when Kafka or Neo4j aren't available. New `integration` marker registered in `services/agents/pyproject.toml`. `services/ingest/go.mod` adds `github.com/neo4j/neo4j-go-driver/v5 v5.27.0`. T1.2 (config snapshots) and the 360-event synthetic corpus expansion are explicitly deferred — TODO comments call out the connector list and the corpus stub.
- 2026-05-13 — T2.4 shipped: per-investigation token / USD / latency telemetry now lives in `eval_report.json -> per_investigation`. New stdlib-only module `scripts/eval_telemetry.py` (deterministic 4-chars/token estimator, illustrative 2025-era public rate card mirroring `services/agents/app/core/cost_telemetry.py`, mean/median/p50/p95/p99 across all 200 incidents and per-template). `scripts/run_evals.py` gains `--telemetry-only` / `--telemetry-model` / `--no-telemetry-records` flags so the substrate-walk numbers can run without the agent dependency stack. `scripts/render_eval_charts.py` extended with a hand-rolled SVG emitter (zero new deps) that writes four charts into `apps/docs/docs/benchmark-charts/`: `latency-p50-p95-p99.svg`, `tokens-distribution.svg`, `usd-distribution.svg`, `latency-by-template.svg`. `apps/docs/docs/benchmark.md` gains a clearly-labeled "Deterministic-substrate budget projection (T2.4)" section with the four SVGs inline plus a substrate budget table; the existing wet-eval tables stay as placeholders per workspace rule. Wet eval lives in T5.5; substrate budgets are an upper-bound CI gate, never quoted as live agent performance. New unit tests at `services/agents/tests/test_eval_telemetry.py` (18 cases: rate-card maths, token estimator, aggregate stats, severity scaling, SVG renderer round-trip including the no-records fallback) — all green.
- 2026-05-13 — Branch created, progress tracker initialised, wave-1 subagents dispatched.
- 2026-05-13 — T7.2 shipped: L0–L4 automation maturity white paper. Canonical
  docs concept page at `apps/docs/docs/concepts/automation-maturity.md`,
  full-length white paper (~4,400 words) at
  `apps/web/content/papers/l0-l4-automation-maturity.md`, rendered PDF at
  `apps/web/public/papers/l0-l4-automation-maturity.pdf`, render tool at
  `scripts/render_white_paper.py` (WeasyPrint + python-markdown). Sidebar
  wired and `concepts/capabilities.md` cross-linked.
- 2026-05-13 — T5.1 + T5.2 landed: benchmark.md gains north-star callout, latency/tokens/USD scaffold (T2.4-populates placeholders) + provenance footer; new benchmark-methodology.md (dataset, substrate-vs-wet, rate card, reproduce, limitations); `pnpm eval:public` entry point + `scripts/render_eval_charts.py` renderer; README footer points reproducers at the methodology page.
- 2026-05-13 — T1.3 shipped: graph schema v1.0 published (`schemas/graph-schema.yaml`, `apps/docs/docs/architecture/graph-schema.md`) with Mermaid ER diagram, 17 labels, 14 relationships, event-edge convention. CI drift gate at `.github/workflows/graph-schema-check.yml` runs `scripts/export_graph_schema.py --check` on PRs touching the schema or `services/ingest/internal/graph/**`.
- 2026-05-13 — T7.1 IDE extension scaffold landed at `services/mcp/cursor-extension/` (4 MCP-backed commands, typed JSON-RPC client, webview renderer, 19 passing smoke tests; marketplace publish deferred to follow-up).
- 2026-05-13 — T6.2 + T6.3 shipped: GTM marketing surface live without engineering involvement. New `/customers` index + `/customers/[slug]` MDX-driven case-study template (`apps/web/content/customers/example.mdx` template, `apps/web/src/lib/customers.ts` loader, `next-mdx-remote` + `gray-matter` wired into the web app). New `/sovereign` deployment-flexibility one-pager with deployment-mode matrix and any-cloud × any-region grid citing the air-gap overlay, Helm chart, and Terraform modules. Marketing nav (`LandingNav`) and footer (`Footer`) now surface the two new pages.
- 2026-05-13 — T2.5 shipped: public agent narrative consolidated to four named agents — Detect / Triage / Hunt / Respond. New facade at `services/agents/app/agents/__init__.py` (DetectAgent, TriageAgent, HuntAgent, RespondAgent + back-compat aliases AutoTriageAgent, PhishingAgent, IdentityAgent, CloudAgent, InsiderThreatAgent, ResponderAgent — sub-agents stay as internal modules but are framed as TriageAgent capabilities). 32 facade tests at `services/agents/tests/test_four_agent_facade.py` lock the contract. New `apps/docs/docs/architecture/agents.md` (added to sidebar) is the public source of truth, including a `Status: in flight` note for `DetectAgent.process` cross-service wiring into `services/fusion/`. Landing-page hero copy at `apps/web/src/components/onboarding/StartHero.tsx` is now "Detect. Triage. Hunt. Respond." with a four-agent strip; the matching Vitest test asserts only the four branded names appear and that sub-agent names are never promoted to the hero.
- 2026-05-13 — T3.1 shipped: SOC Insights dashboard live at `/dashboards/soc-insights` with seven rolling-window tiles (MTTA, MTTR, FP rate, alerts/day, cases/day, agent cost / investigation, analyst hours saved). New aggregator `GET /v1/insights/soc?window=24h|7d|30d` at `services/api/app/api/v1/endpoints/insights.py` returns a Pydantic-typed payload with current/previous-window values, percentage delta, and a 24-bucket sparkline per tile. "Analyst hours saved" heuristic is documented inline as `MANUAL_INVESTIGATION_MINUTES = 45` and surfaced in the response so the UI can render the assumption beside the tile. Realtime service (`services/realtime/src/index.ts`) gains an `insights` channel + 30-second `insights_updated` tick (`INSIGHTS_TICK_MS`); `case.updated` events also route through the insights channel so analysts see fresh tile values within a second of a case change. Web page (`apps/web/src/app/(app)/dashboards/soc-insights/page.tsx` + view/components under `apps/web/src/components/soc-insights/`) renders the tile grid with skeleton + error states, an inline-SVG sparkline (no new dep), and SWR-driven WebSocket revalidation. Sidebar nav surfaces the new dashboard. Tests: `services/api/tests/test_insights_endpoint.py` (12 cases — delta math, window allowlist, seven-tile shape, hours-saved heuristic, zero-state) + `apps/web/src/components/soc-insights/SOCInsightsView.test.tsx` (loading skeleton, tile labels rendered, error state, Sparkline math). Cost-table read path catches `SQLAlchemyError` and returns 0 so the dashboard renders cleanly until `aisoc_run_costs` deploys — labelled `# TODO(T2.4-followup)` in the code.
- 2026-05-13 — T3.4 shipped (scheduler scaffolded behind a feature flag): `/hunt` is the canonical natural-language hunt surface and `/investigate` 308-redirects there with query params preserved. New hero block on `/hunt` ("Hunt at the speed of thought" + three example pills covering geo / IAM / GitHub questions) calls `POST /v1/nl-query/translate` and runs the hunt within ~5s. Saved-hunts CRUD lives at `services/api/app/api/v1/endpoints/saved_hunts.py` (`POST/GET/DELETE /v1/saved-hunts`, `GET /v1/saved-hunts/{id}`, `POST /v1/saved-hunts/{id}/run`) backed by a new `SavedHunt` SQLAlchemy model + RLS-aware migration `services/api/migrations/040_saved_hunts.sql`. NL translator gains a 70-country name → ISO-3166 detector (`services/agents/app/nl_query/translator.py`, vendored copy synced) so "attacks from Iran" becomes `WHERE source.geo.country_iso_code == "IR"`. Hunt scheduler worker at `services/api/app/workers/hunt_scheduler.py` (asyncio.Task pattern matching `oauth_refresh`) sweeps `aisoc_saved_hunts`, fires due cron entries, and stamps `last_run_at` — *gated behind* `AISOC_HUNT_SCHEDULER_ENABLED=0` (default off) with the actual ES|QL runner stubbed `# TODO(T3.4-followup)` until the lake executor lands. UI: `HuntView` enhanced with hero, NL pills (auto-submit on click), saved-hunts sidebar with re-run + delete, raw saved-search list preserved alongside; `apps/web/src/lib/api.ts` exposes typed `savedHuntsApi` + `nlQueryApi`; shared types added at `packages/types/src/hunt.ts`. Tests: 38 cases at `services/api/tests/test_saved_hunts_endpoint.py` covering cron validation, CRUD wire shape, run re-translation/timestamp stamping, and a mocked scheduler `run_once` that asserts due hunts fire the executor + case-creation callback. OpenAPI yaml re-exported.
- 2026-05-13 — T4 wave-1 connectors shipped (T4.2 Tines, T4.3 Torq, T4.8 Falco, T4.10 PagerDuty + Opsgenie, T4.11 Confluence audit). Six new connector modules under `services/connectors/app/connectors/{tines,torq,falco,pagerduty,opsgenie,confluence_audit}.py`, registered in `_CONNECTOR_CLASSES` and surfaced through the marketplace + docs sidebar. Five push/pull SaaS audit-and-incident integrations plus one push-only K8s runtime sensor (Falco via falcosidekick → HTTP webhook); each ships a marketplace manifest in `plugins/<id>/plugin.yaml`, a setup walkthrough in `apps/docs/docs/connectors/<id>.md`, full pytest coverage (`services/connectors/tests/connectors/test_<id>.py` — 78 tests across the six modules, all green) and vendor-doc-sourced fixtures in `services/connectors/tests/fixtures/<id>/sample_event.json`. Wave-1 severity ladder collapses each vendor's native scheme into AiSOC's four-tier (`info | low | medium | high`) per the rules in the task spec; pagination strategies cover offset/limit (PagerDuty incidents, Confluence audit), opaque cursor (PagerDuty audit, Tines, Torq), and absolute-next-URL (Opsgenie). PagerDuty + Opsgenie are accounted as a single wave-1 "slot" since they're paired on-call vendors, so the wave still totals five shipped slots out of T4's longer roadmap.
