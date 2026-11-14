# AiSOC v8.0 — North-star Plan

> **Status**: Locked plan — implement as specified, do not edit.
> **Captured**: 2026-05-15
> **Hash**: `1dee8c63`
> **Tracking**: `AISOC_V8_PROGRESS.md` mirrors progress; this file is the source of truth.
> **Convention**: Mirrors workspace plan-file rules — `[ ]` → `[~]` (in flight) → `[x]` (shipped) lives in the progress mirror, never in this file.

---

## North-star outcomes (what v8.0 must ship)

1. **Sub-minute investigation, with the numbers in public.** p50 < 60s, p95 < 120s on the 200-incident eval set, with token + USD per investigation published in `apps/docs/docs/benchmark.md`.
2. **Knowledge graph built at ingest, not at query.** Every event materializes graph nodes + edges before fusion sees it; config-at-event-time captured as a versioned snapshot edge.
3. **A clean three-model story** — Semantic (Neo4j) / Behavioral (UEBA + LightGBM + Isolation Forest) / Knowledge (Qdrant RAG + LLM). LLM only ever sees structured summaries, never raw logs.
4. **Effective Permissions** across AWS / Azure / GCP / Okta / Google Workspace, with a Cytoscape graph view.
5. **Attack Chains** — one alert pulls every related alert across the stack into a single ranked timeline.
6. **NL hunting** as a hero surface — `/hunt`, saved hunts, scheduled hunts, example-query pills.
7. **40+ live connectors**, up from 26.
8. **Branded agent narrative** — 4 named agents that map to a customer's mental model (Detect / Triage / Hunt / Respond), with the existing sub-agents (phishing / identity / cloud / insider) framed as Triage capabilities.
9. **Hosted multi-tenant SaaS at app.aisoc.dev** (early-access waitlist) running the same code as self-hosted. Self-hosted stays first-class.

---

## Tracks

- **Track 1** — Graph-at-ingest architecture upgrade
- **Track 2** — Agent / reasoning latency + cost
- **Track 3** — UI: Effective Permissions, Attack Chains, NL Hunt, SOC Insights, Business Context
- **Track 4** — Connector wave (15 new)
- **Track 5** — Public benchmark + eval extensions
- **Track 6** — Hosted SaaS + GTM enablement surface
- **Track 7** — Narrative sharpening (OSS / sovereign / IDE-driven / public-eval / osquery)

Each task: `Priority` (P0 must / P1 important / P2 nice) · `Effort` (S < 1 wk / M 2-4 wk / L 1-2 mo) · `Depends on` (other T-IDs).

---

## Track 1 — Architecture: graph at ingest

**Goal:** end the "Neo4j is built after the fact" pattern. The security knowledge graph is written synchronously inside the ingest path, captures config-at-event-time, and has a published schema.

### T1.1 — Ingest-side graph writer  (P0, L, depends on: —)

Insert a graph-write step into the Kafka ingest path so every normalized event materializes / updates graph nodes + edges *before* it lands in fusion.

**New module:** `services/ingest/internal/graph/` (Go)
- `writer.go` — Neo4j Bolt driver, batched UNWIND upserts, pooled connection
- `schema.go` — entity + edge type enums, version stamping
- `extractor.go` — pulls entity references out of OCSF events (actor, target, resource, network endpoint, code repo, container image)

**Wiring:**
- Kafka consumer group `aisoc-graph-writer` reading `security.events`
- Idempotency: `(entity_type, natural_key, hash(properties))` UPSERT
- Publish `security.graph_updates` topic with `{entity_id, change_type, ts}` for downstream consumers

**Schema (versioned):**
- Node labels: `Identity, Permission, Role, Policy, Resource, Configuration, Endpoint, User, ServiceAccount, Repo, Container, Image, NetworkPath, SaaSApp, Alert, Case, Detection`
- Relationships: `:ASSUMED_BY, :HAS_PERMISSION, :GRANTS, :OWNS, :CONFIGURED_AS, :DEPLOYED_FROM, :ACCESSES, :PEER_OF, :TRIGGERED, :OCCURRED_ON, :MEMBER_OF, :DEPLOYS, :READS_FROM, :WRITES_TO`
- Every event-edge carries `{ts, source_event_id, snapshot_id}`

**Acceptance:**
- `services/ingest/internal/graph/writer_test.go` — given the 360-event synthetic corpus, all 14 source types yield ≥ 1 graph entity, deterministic counts, CI-gated
- `services/agents/tests/test_graph_freshness.py` — p95 < 2s from Kafka publish to graph readability via Cypher `MATCH`
- `eval_report.json` adds `graph_freshness_ms` field

### T1.2 — Config snapshots (config-at-event-time)  (P0, M, depends on: T1.1)

When an event lands referencing a resource, capture the resource's configuration *at that moment* as a versioned `Configuration` node connected via `:CONFIGURED_AS {ts}`.

**New module:** `services/ingest/internal/config_snapshot/`
- `snapshotter.go` — pulls config from connectors that expose `get_resource_config(resource_id, ts)`
- `cache.go` — Redis-backed TTL cache to avoid round-trips for hot resources

**Connector extension:** add optional method `get_resource_config(id, ts) -> dict` to `BaseConnector` (Python) and the Go connector interface. Default `NotImplemented`. Implement first for:
- AWS (CloudTrail trail config, IAM policy version)
- Azure (Resource Manager)
- GCP (Asset Inventory)
- Okta (group/policy versions)
- GitHub (repo settings + branch protection)

**Acceptance:** For an alert on AWS resource `i-12345`, the Cypher path `(:Alert)-[:OCCURRED_ON]->(:Resource)-[:CONFIGURED_AS {ts}]->(:Configuration)` returns the correct config at alert timestamp. Validated against fixtures in `services/ingest/test_data/aws_config_history.json`.

### T1.3 — Publish the graph schema  (P0, S, depends on: T1.1)

- `apps/docs/docs/architecture/graph-schema.md` — narrative + Mermaid ER diagram + every label / relationship explained
- `scripts/export_graph_schema.py` — connects to Neo4j, dumps current schema to YAML
- `schemas/graph-schema.yaml` — checked in, regenerated on schema migration

**Acceptance:** Doc renders on docs.aisoc.dev/architecture/graph-schema with full ER diagram. `scripts/export_graph_schema.py --check` fails CI if schema drifts without doc update.

### T1.4 — Real-time graph-update WebSocket channel  (P1, S, depends on: T1.1)

`services/realtime/` exists. Add a `/graph/updates` channel that fans out the `security.graph_updates` Kafka topic to subscribed clients with tenant filtering.

**Acceptance:** Console graph view subscribes; nodes light up < 1s after Kafka event publishes.

---

## Track 2 — Agent reasoning: latency + cost

**Goal:** investigation p50 < 60s, p95 < 120s on the eval set, with measured token + USD per investigation published. LLM contract enforced — agents only consume structured summaries.

### T2.1 — Pre-fetched context bundle  (P0, M, depends on: T1.1)

Before any sub-agent runs, build a `ContextBundle` Pydantic model:
- entity neighborhood (configurable depth, default 2)
- historical similar-case verdicts (last N from `aisoc_institutional_memory`)
- peer-entity behavior baselines (UEBA)
- threat-intel matches

**New:** `services/agents/app/context/bundle.py` (~150 LOC). Replaces the per-tool round-trip discovery pattern.

**Refactor:** sub-agents in `services/agents/app/agents/*.py` accept `ContextBundle` as a parameter; tools they call become enrichment of the bundle, not primary discovery.

**Acceptance:**
- `services/agents/tests/test_context_bundle.py` — for each of 200 eval incidents, bundle is fully populated in < 5s p95
- Token-per-investigation drops ≥ 30% vs baseline (measured in eval)

### T2.2 — LangGraph topology refactor: parallel sub-agents  (P0, M, depends on: T2.1)

Today's router is likely sequential. Move to parallel fan-out: `auto_triage_agent` classifies, then *concurrent* fan-out to relevant sub-agents (phishing AND identity if both signals present), join, then ResponderAgent.

**File:** `services/agents/app/investigator/graph.py` — change router edges to parallel; introduce a Join node. Keep sequential path under a feature flag until eval is green.

**Acceptance:**
- `services/agents/tests/test_latency.py` — investigation wall-clock p50 < 60s, p95 < 120s on the 200-incident set, warm Fly.io
- No regression in MITRE accuracy, completeness, or response-quality scores

### T2.3 — Structured-summaries-only LLM contract  (P0, M, depends on: T2.1)

Some agent prompts may today concatenate raw logs. Enforce: every LLM call receives only ContextBundle summary fields + numerical scores + RAG snippets. No raw OCSF JSON, ever.

**New:** `services/agents/app/llm/contract.py` — wraps every LLM call, validates message contents against `LLMInputContract` Pydantic model, fails closed on raw-log shape.

**Acceptance:** `services/agents/tests/test_llm_contract.py` — all 200 eval-incident runs pass the contract.

### T2.4 — Token + USD telemetry in eval  (P0, S, depends on: —)

Extend `scripts/run_evals.py` to emit `tokens_per_investigation` + `usd_per_investigation` aggregated from `aisoc_run_costs`. Add `scripts/render_eval_charts.py` → `docs/benchmark-charts/*.svg`.

**Acceptance:** `apps/docs/docs/benchmark.md` includes p50/p95/p99 latency, mean/median tokens, mean/median USD — per-template and aggregate.

### T2.5 — Brand the four agents  (P0, S, depends on: —)

Consolidate the public narrative around 4 named agents. Sub-agents (phishing / identity / cloud / insider) become *capabilities* of the Triage agent, not first-class names.

- `Detect` — fusion + entity-risk + native detections
- `Triage` — `auto_triage_agent` + the 4 sub-agents
- `Hunt` — Hunt-as-Code engine + NL hunt surface
- `Respond` — ResponderAgent + SOAR + ChatOps

**Where:** rename agent classes in `services/agents/app/agents/__init__.py` (alias old names for back-compat); update `apps/docs/docs/architecture/agents.md`; update landing-page hero copy.

**Acceptance:** Public docs reference exactly four agents. Internal sub-agent code paths unchanged.

---

## Track 3 — UI

**Reframe:** AiSOC already ships ~25 console pages, Cytoscape graphs, Monaco editor, React Flow playbooks, the 684-LOC Investigation Timeline, Responder PWA, ⌘J Copilot dock, ⌘K palette. The real UI work in v8.0 is five named features + polish.

### T3.1 — SOC Insights dashboard  (P1, M, depends on: T2.4)

New page: `apps/web/src/app/(console)/dashboards/soc-insights/page.tsx`.

Tiles: MTTA, MTTR, FP rate, alerts/day, cases/day, agent-cost-per-investigation, analyst hours saved (heuristic: auto-closed cases × avg manual investigation time).

**API:** `services/api/app/api/v1/endpoints/insights.py` — aggregates from cases + Investigation Ledger + `aisoc_run_costs`.

**Acceptance:** Renders < 1s on tryaisoc.com with seeded data; tiles refresh via WebSocket every 30s.

### T3.2 — Effective Permissions  (P0, L, depends on: T1.1)

**Backend:** `services/api/app/services/effective_permissions/` with provider modules:
- `aws.py` — IAM policy resolution (identity-based + resource-based + SCP)
- `azure.py` — RBAC role assignments + scope inheritance
- `gcp.py` — IAM policy resolution + organizational policies
- `okta.py` — group → role mapping
- `gws.py` — Google Workspace admin role mapping

Each takes a principal ID and returns the set of effective actions across resources with policy-chain provenance.

**Caching:** materialize into Neo4j as `(:Identity)-[:EFFECTIVE_PERMISSION {actions, last_resolved}]->(:Resource)`.

**UI:** `apps/web/src/app/(console)/identity/permissions/page.tsx` — Cytoscape "Identity → Role → Policy → Action → Resource"; collapsible by provider; "show only changes since last week" filter.

**Acceptance:**
- For fixture AWS account in `services/api/tests/fixtures/aws_iam_complex.json`, output matches AWS IAM Policy Simulator on 50 sample principal/resource pairs
- UI loads for a 1k-principal tenant in < 3s

### T3.3 — Attack Chains  (P0, L, depends on: T1.1)

**Backend:** `services/fusion/app/services/attack_chain.py` — given an alert, walks the graph within a configurable window (default 24h), pulls all alerts sharing ≥ 1 entity, ranks by graph distance + temporal proximity + risk overlap, returns a single ranked timeline.

**Storage:** new table `attack_chains` via migration `services/api/migrations/0NN_attack_chains.sql`.

**UI:** `apps/web/src/app/(console)/cases/[id]/attack-chain/page.tsx` — single timeline + side-by-side entity graph; "pivot to source" buttons that route back to the original detection / connector event.

**Acceptance:** For seeded `INC-RT-001` (LockBit 3.0) on tryaisoc.com, Attack Chain stitches: initial phishing → credential harvest → cloud auth anomaly → S3 enumeration → exfil. All 5 alerts in correct temporal order.

### T3.4 — `/hunt` — natural language hunt surface  (P0, S-M, depends on: —)

Rebrand `/investigate` to `/hunt`. Add saved-hunt persistence + scheduled-hunt cron from the same UI. Example-query pill row on first load:
- "Did we get any new attacks from Iran?"
- "Show me everyone who touched our prod IAM role in the last 7 days"
- "Any GitHub auth from a new device this week?"

**Files:**
- Rename `apps/web/src/app/(console)/investigate/page.tsx` → `apps/web/src/app/(console)/hunt/page.tsx`. Add redirect.
- New `services/api/app/api/v1/endpoints/hunts.py` for saved + scheduled hunts.
- Reuse existing NL → Sigma/KQL/SPL/ES|QL translator chain.

**Landing:** dedicated hero block ("Hunt at the speed of thought"), 90-second demo video, blog post.

**Acceptance:** Each of the 3 example queries returns results in < 5s on seeded tryaisoc.com. Saved hunts persist across reload. Scheduled hunts fire on cron and create cases on hit.

### T3.5 — Business Context Rules  (P1, M, depends on: —)

A layer between detection and the triage agent where customers encode their own context: "if alert.target.tag == 'prod' and alert.time.is_business_hours: severity = critical; route_to = tier2".

**Engine:** `services/api/app/services/business_context/` — YAML or visual rule definitions; evaluated post-fusion, pre-triage-agent.

**UI:** `apps/web/src/app/(console)/settings/business-context/page.tsx` — Monaco YAML editor with rule-builder side-panel; live preview against last 100 alerts.

**Acceptance:** A test rule mutating severity is reflected within 1s of save; dry-run preview shows 50 sample alerts with before/after.

### T3.6 — Slack / Teams approval Block-Kit cards  (P1, M, depends on: —)

Upgrade `services/slack-bot/` from slash-command-only to interactive Block Kit cards. Add Teams Adaptive Cards. Email fallback via Mailgun.

**Behaviour:** approver sees full case context, Approve / Deny / Need-Info buttons, configurable timeout, safe-default fallback action, full audit trail.

**Acceptance:** Approve/Deny buttons trigger HMAC-verified callback; timeout → safe-default action; full audit trail captured.

### T3.7 — NL → playbook generator  (P1, M, depends on: T3.4)

Add NL-authored playbook drafting on top of the existing React Flow editor.

**Files:**
- `apps/web/src/app/(console)/playbooks/new/page.tsx?nl=true` — prompt input → LLM emits DAG draft → opens in React Flow editor
- `services/agents/app/playbook/nl_drafter.py` — prompt template + LLM call + JSON Schema validation against `playbook.schema.json`

**Acceptance:** Prompt "When a high-severity exfil alert fires on a prod S3 bucket, isolate the IAM role, snapshot the bucket policy, and page on-call" emits a valid DAG with isolate-role + snapshot-policy + page nodes wired in correct order.

### T3.8 — Design system v2 + Storybook  (P1, M, depends on: —)

- Add shadcn/ui formally if not already wired
- Tighten dark theme tokens
- Build `apps/web/.storybook/` with 30+ component stories so screenshots can be programmatically generated for marketing
- WCAG AA is already shipped per ROADMAP v7.0 — keep it green

**Acceptance:** Storybook builds; 30+ stories; visual-regression snapshots committed.

---

## Track 4 — Connector wave (15 new)

**Goal:** cross 40 live connectors; ship the 15 below in 8 weeks. All in `services/connectors/app/connectors/<id>/` with companion `plugins/<id>/plugin.yaml`.

| # | Connector | Effort | Why this slot |
|---|---|---|---|
| 1 | Cloudflare WAF + Zero Trust | M | CDN + ZTNA increasingly the perimeter |
| 2 | Tines | S | SOAR fallback target |
| 3 | Torq | S | SOAR coverage parity |
| 4 | Sublime Security | M | Email-security AI narrative |
| 5 | Abnormal Security | M | Same |
| 6 | Lacework (extend) | S | Add policy-violations stream |
| 7 | Sysdig | M | K8s runtime |
| 8 | Falco | S | OSS K8s runtime |
| 9 | HashiCorp Vault audit | M | Identity-graph extension to secrets |
| 10 | PagerDuty / Opsgenie | S | On-call loop closure |
| 11 | Atlassian Confluence audit | S | SaaS breadth |
| 12 | Box / Dropbox audit | M | DLP narrative |
| 13 | Datadog logs + APM | M | Observability spine |
| 14 | Snowflake audit | M | Warehouse parity |
| 15 | OCI (Oracle Cloud) | M | Sovereign cloud play |

**Cross-cutting:**
- `scripts/generate_connector_docs.py` — auto-generate `apps/docs/docs/connectors/<id>.md` from each connector's `schema()`
- Test scaffold per connector: `services/connectors/tests/connectors/test_<id>.py` covering schema valid, normalize round-trip, fixture-driven `fetch_alerts`
- Marketplace card includes a "schema-drift alerts in last 30 days" badge from the existing sentinel

**Acceptance:** 15 connectors land + green CI + auto-generated docs + visible in `/marketplace`.

---

## Track 5 — Public benchmark + eval extensions

**Goal:** make AiSOC's eval the published reference. Everything reproducible from `make eval-public`.

### T5.1 — Speed + token + cost publication  (P0, S, depends on: T2.4)

Publish `apps/docs/docs/benchmark.md`: p50/p95/p99 latency per template, tokens per investigation (mean/median + by-category), USD per investigation at current rate card.

### T5.2 — Methodology page  (P0, S, depends on: T5.1)

Open-source methodology + rate card in `apps/docs/docs/benchmark-methodology.md`. Invite reproductions in the README footer.

### T5.3 — Public-dataset fidelity benchmark  (P1, M, depends on: —)

Run AiSOC against:
- AIT-LDS (Austrian Institute of Technology log dataset)
- CICIDS2018
- MITRE Engenuity ATT&CK Evaluations rounds where data is public

**Files:**
- `services/agents/tests/test_public_datasets.py`
- `services/agents/tests/datasets/{ait_lds,cicids2018,mitre_engenuity}.py`

**Acceptance:** Benchmark page shows AiSOC scores on each dataset with date stamp + commit SHA.

### T5.4 — Public scoreboard page  (P1, M, depends on: T5.1)

Page at `tryaisoc.com/benchmark` that pulls latest CI's `eval_report.json` and renders score vs previous release. Open a GitHub issue template for anyone to PR a comparable published metric.

### T5.5 — "Wet eval" weekly CI job  (P1, S, depends on: T2.4)

Today the eval runs against deterministic substrate (README discloses this). Add a separate weekly CI job that actually calls the LLM tier on the 200-incident set and posts the run's tokens + USD + latency to the benchmark page.

**File:** `.github/workflows/wet-eval-weekly.yml`. Budget-gated; failure non-blocking on PRs.

---

## Track 6 — Hosted SaaS + GTM enablement surface

### T6.1 — `app.aisoc.dev` multi-tenant managed instance  (P0, L, depends on: T1.1, T2.2, T3.2, T3.3)

Same code as self-hosted, deployed on Fly.io with regional read replicas. Sign-up gated by an early-access waitlist.

**Files:**
- `apps/web/src/app/(marketing)/early-access/page.tsx` — waitlist form
- `services/api/app/api/v1/endpoints/waitlist.py` — captures applications, sends Slack alert to GTM channel
- `infra/fly/managed/` — Helm-compose hybrid deploy config for the managed environment

**Acceptance:** Waitlist captures applications; managed instance boots from `main` on every release tag.

### T6.2 — Reference-customer page templates  (P0, S, depends on: —)

Template page so GTM can publish case studies without engineering involvement.

**File:** `apps/web/src/app/(marketing)/customers/[slug]/page.tsx` — MDX-driven, with structured frontmatter: `{logo, industry, challenge, result_numbers[], quote, quote_role, quote_company}`.

**Acceptance:** Template renders for a placeholder case study; new case study = new MDX file in `apps/web/content/customers/`.

### T6.3 — Sovereign + air-gap one-pager  (P1, S, depends on: —)

A landing page surfacing AiSOC's deployment flexibility: air-gap mode, Ollama sidecar, on-prem, Helm, Terraform, any cloud, any country.

**File:** `apps/web/src/app/(marketing)/sovereign/page.tsx` with a country / cloud / deployment-mode matrix.

### T6.4 — `pnpm aisoc:demo` polishing  (P1, S, depends on: —)

The one-command demo seeder exists. Polish it: deterministic 4 cases (phishing / cloud takeover / insider exfil / ransomware), 90-second screencast in `apps/web/public/demo.mp4`, README badge linking to a Fly.io-hosted demo with read-only credentials.

**Acceptance:** New user runs `pnpm aisoc:demo`, gets to a populated dashboard with 4 cases in < 4 min on a warm laptop.

---

## Track 7 — Narrative + IDE-driven SOC

### T7.1 — Cursor extension  (P0, M, depends on: —)

Ship a Cursor extension wrapping `@aisoc/mcp` so analysts can run triage, replay decisions, and explain steps from inside Cursor.

**New repo (or path):** `aisoc-cursor-extension/` or `services/mcp/cursor-extension/`.

**Capabilities exposed via the extension:**
- "Run triage on case X" → calls `aisoc_run_investigation`
- "Replay step 3 of investigation Y" → calls `aisoc_replay_decision`
- "Explain why the agent did this" → calls `aisoc_explain_step`
- "Find detections covering this technique" → calls `aisoc_query_detections`

**Acceptance:** Published to Cursor extension marketplace; demo video on tryaisoc.com showing a full triage flow without leaving Cursor.

### T7.2 — L0–L4 automation maturity white paper  (P1, S, depends on: —)

The maturity model is shipped in v6.0. Write it up as a white paper under the AiSOC brand, host as a PDF at `apps/web/public/papers/l0-l4-automation-maturity.pdf`. Submit to MITRE D3FEND community channels.

### T7.3 — Three blog posts to anchor the narrative  (P1, S, depends on: T5.1, T7.1)

- "How AiSOC investigates incidents in under a minute, with the numbers" — references T2 + T5 outputs
- "The SOC has an IDE now" — references T7.1 Cursor extension
- "AiSOC owns the endpoint truth layer" — osctrl + FleetDM + `aisoc-direct` + custom virtual tables + 16 osquery rules

Authored as MDX in `apps/web/content/blog/`.

---

## Sequencing — 12 weeks

### Week 0 — pre-kick-off
- Eng lead walks team through this plan
- PM opens GitHub issues for every T-ID with this doc linked
- GTM kicks off reference-customer recruitment (long lead) and academic / lab reproductions (long lead)

### Weeks 1–3 — parallel kickoff
| Track | Tasks |
|---|---|
| T1 | T1.1 graph writer (start). T1.3 schema publication (finish wk 2). |
| T2 | T2.4 token + USD telemetry (wk 1). T2.5 four-agent rebrand (wk 1). T2.1 ContextBundle (start wk 2). |
| T3 | T3.4 `/hunt` rebrand (finish wk 2). T3.1 SOC Insights (start). |
| T4 | First 5 connectors: Tines, Torq, Falco, PagerDuty, Confluence. |
| T5 | T5.1 + T5.2 published (wk 3). |
| T7 | T7.1 Cursor extension kickoff. |

**Wk 3 milestone:** Ingest-side graph writer in beta on a dev tenant. Public benchmark page live. `/hunt` rebrand shipped. 5 new connectors landed. Four-agent naming live in docs.

### Weeks 4–6 — heavy build
| Track | Tasks |
|---|---|
| T1 | T1.1 finishes. T1.2 config snapshots. T1.4 graph-update WebSocket. |
| T2 | T2.1 ships. T2.2 parallel topology refactor. T2.3 LLM contract. |
| T3 | T3.5 Business Context Rules. T3.6 Slack Block Kit. |
| T4 | 5 more connectors: Sublime, Abnormal, Sysdig, Vault, Box. |
| T5 | T5.3 public-dataset benchmark. |
| T7 | T7.3 blog 1 published. |

**Wk 6 milestone:** Investigation p50 < 60s on the eval. Effective-permissions resolver in dev. Attack Chains backend in dev. 10 new connectors total. First reference customer logo committed.

### Weeks 7–9 — UI completion + customer evidence
| Track | Tasks |
|---|---|
| T3 | T3.2 Effective Permissions UI ships. T3.3 Attack Chains UI ships. T3.7 NL → playbook. T3.8 design system v2 + Storybook. |
| T4 | Connectors 11–15: Datadog, Snowflake, OCI, Dropbox, Cloudflare. |
| T5 | T5.4 public scoreboard + T5.5 wet eval CI. |
| T6 | T6.1 `app.aisoc.dev` waitlist live. T6.2 customer page template + first 2 case studies. |
| T7 | T7.2 maturity model white paper. T7.3 blogs 2 + 3. |

**Wk 9 milestone:** Effective Permissions + Attack Chains live on tryaisoc.com. 15+ new connectors total (≥ 40 live). 2 customer reference pages public. Cursor extension shipped.

### Weeks 10–12 — polish + v8.0 launch
- v8.0 release bundling everything in T1–T3
- T6.4 demo seeder + 90s screencast cut
- Launch sequence: HN post, Twitter thread, blog promotion, customer-quoted case studies
- Final reference-customer logos go live
- Cursor-extension demo video featured on landing

**Wk 12 milestone:** v8.0 shipped. Effective Permissions + Attack Chains + NL Hunt + SOC Insights + 15 new connectors + 5 customer reference pages + Cursor extension + public sub-minute benchmark — all live.

---

## Appendix — task index

```
[ ] T1.1  Ingest-side graph writer                       (P0, L)
[ ] T1.2  Config snapshots                                (P0, M)  → T1.1
[ ] T1.3  Publish graph schema                            (P0, S)  → T1.1
[ ] T1.4  Real-time graph-update WebSocket                (P1, S)  → T1.1
[ ] T2.1  Pre-fetched context bundle                      (P0, M)  → T1.1
[ ] T2.2  LangGraph parallel topology                     (P0, M)  → T2.1
[ ] T2.3  LLM-input contract                              (P0, M)  → T2.1
[ ] T2.4  Token + USD eval telemetry                      (P0, S)
[ ] T2.5  Four-agent brand consolidation                  (P0, S)
[ ] T3.1  SOC Insights dashboard                          (P1, M)  → T2.4
[ ] T3.2  Effective Permissions                           (P0, L)  → T1.1
[ ] T3.3  Attack Chains                                   (P0, L)  → T1.1
[ ] T3.4  /hunt NL surface                                (P0, S-M)
[ ] T3.5  Business Context Rules                          (P1, M)
[ ] T3.6  Slack/Teams Block Kit approvals                 (P1, M)
[ ] T3.7  NL → playbook generator                         (P1, M)  → T3.4
[ ] T3.8  Design system v2 + Storybook                    (P1, M)
[ ] T4.x  15-connector wave                               (P1, L total)
[ ] T5.1  Speed + token + USD published                   (P0, S)  → T2.4
[ ] T5.2  Methodology page                                (P0, S)  → T5.1
[ ] T5.3  Public-dataset fidelity benchmark               (P1, M)
[ ] T5.4  Public scoreboard page                          (P1, M)  → T5.1
[ ] T5.5  Wet-eval weekly CI job                          (P1, S)  → T2.4
[ ] T6.1  app.aisoc.dev managed waitlist                  (P0, L)  → T1.1, T2.2, T3.2, T3.3
[ ] T6.2  Reference-customer page template                (P0, S)
[ ] T6.3  Sovereign + air-gap landing page                (P1, S)
[ ] T6.4  Demo seeder + screencast polish                 (P1, S)
[ ] T7.1  Cursor extension                                (P0, M)
[ ] T7.2  L0–L4 white paper                               (P1, S)
[ ] T7.3  Three anchor blog posts                         (P1, S)  → T5.1, T7.1
```
