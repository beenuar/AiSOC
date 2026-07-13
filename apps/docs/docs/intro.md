---
sidebar_position: 1
---

# Introduction

AiSOC is an open-source AI Security Operations Center maintained by
the AiSOC community. The agent itself is MIT-licensed, self-hostable, and
auditable: every LLM prompt, tool call, evidence citation, and decision is
recorded in a replayable Investigation Ledger, and the substrate is gated by a
public, reproducible eval harness on every PR targeting `main` / `develop`.

:::tip What's new (last 48 hours)

The console is now a workbench, not a list of pages. Seven PRs in the
**v1.5 wave** added a global [time-window selector](./console/funnel-kpis),
tenant switcher + role badge in the topbar, a five-tier severity ladder
with **`critical`** restored end-to-end, the [Investigation Rail](./console/investigation-rail)
on `/alerts` (PR-4), a server-anchored
[Investigation Queue workbench](./console/queue) (PR-5), a
[Rule Tuning workbench](./console/rule-tuning) (PR-6),
[operations funnel + pipeline-health KPIs](./console/funnel-kpis) (PR-7),
and a [zero-prerequisite installer](./installation) (PR-8) that bootstraps
Docker, Node, pnpm, and Python from a clean machine.

Underneath, **v8.0 wave-1** landed the [graph-at-ingest entity store](./architecture/graph-schema)
(Neo4j, 17 node labels / 14 edge types, written inline with Kafka
consumption), the four-agent rebrand (`DetectAgent`, `TriageAgent`,
`HuntAgent`, `RespondAgent` — see the [funnel KPIs](./console/funnel-kpis)
page for the funnel stages they own), a natural-language `/hunt` surface
that translates plain English into ES|QL / SPL / KQL, the
[L0–L4 automation maturity model](./concepts/automation-maturity), and a
[public weekly benchmark scoreboard](./benchmark-scoreboard) refreshed by
CI.

A simultaneous security wave fixed **12 critical/high CVE-class issues**:
the rule-engine `eval()` RCE is gone, tenant isolation on `/hunts` and
`/cases` is now query-layer enforced, CORS refuses to start with
`AISOC_CORS_ORIGINS=*` in production, playbook outbound traffic goes
through an [SSRF guard](./operations/security), plugin OCI installs verify
signed manifests and pin image digests, audit logs are hash-chained with
sanitized `actor_ip`, and Python CodeQL alerts on `main` are zero — see
the [security operations page](./operations/security#static-analysis-codeql)
for the full list.

:::

## Capabilities

- **Click-and-connect cloud connectors** — pick from a **78-connector** catalog spanning EDR, SIEM, cloud, IAM, SaaS, VCS, network, ITSM, vuln, and email-security sources (CrowdStrike, SentinelOne, Cortex XDR, Splunk, Microsoft Sentinel, AWS Security Hub, Defender XDR, GCP Cloud Audit, GCP SCC, M365, Entra ID, Azure Activity, Google Workspace, Okta, Duo Security, Cloudflare, Tailscale, GitHub, Wiz, Snyk, Zscaler, Proofpoint, ServiceNow, Jira, 1Password, **Wazuh Indexer**, **auditd `file_tail`**, and 25 more — see [Architecture](./architecture)). Fill a schema-driven form, click `Test connection` for a live auth round-trip, and `Save & enable`. Secrets are encrypted at the application layer with a Fernet [`CredentialVault`](./operations/credentials) before they hit Postgres; an in-process APScheduler polls each enabled instance and pushes normalized OCSF events through to the ingest spine. Setup walkthroughs: [docs/connectors](./connectors).
- **Investigation Ledger** — every prompt, response, evidence citation, and tool call the agent emits is logged step-by-step and replayable on each case.
- **Public eval harness** — alert reduction (a real measurement on a fixed noisy stream) plus MITRE-tactic, investigation-completeness, and response-quality substrate self-consistency gates. Reproducible with one command and run in CI on every PR. The [eval harness page](./benchmark) documents what each suite does and does not measure.
- **Ambient Copilot** — context-aware next-action suggestions on every alert, case, rule, and playbook page; one click runs the right agent tool with the right payload.
- **Responder PWA** — installable mobile route at `/responder/*` with passkey-only login, on-call rotation, approvals queue, VAPID Web Push, and offline shell.
- **LangGraph multi-agent investigation** — orchestrator, recon, forensic, responder, and report-writer agents grounded in MITRE ATT&CK with Qdrant RAG memory. Includes domain-specific agents for phishing triage, identity threat analysis, cloud misconfiguration detection, and insider threat scoring.
- **Autonomous alert triage** — LLM-based auto-triage agent classifies alerts as true positive, false positive, or benign with confidence scoring. High-confidence false positives are auto-closed; uncertain alerts escalate to human analysts.
- **Conversational investigation chat** — multi-turn NL interface for querying alerts, cases, and threat intel with quick actions and a persistent investigation context panel.
- **MITRE ATT&CK coverage advisor** — identifies detection gaps across tactics, recommends new rules, and enables one-click detection generation for uncovered techniques.
- **Shift handoff dashboard** — SOC shift management with handoff item tracking, shift summary KPIs (alerts triaged, cases opened, escalations), and report generation.
- **EASM (External Attack Surface Management)** — continuous asset discovery, exposed service detection, certificate monitoring with expiry alerts, and risk scoring.
- **MSSP executive dashboard** — cross-tenant view with aggregated KPIs (MTTD, MTTR, SLA compliance, ARR) and per-tenant risk scoring for managed security providers.
- **Alert noise tuning** — closed-loop dashboard driven by analyst TP/FP verdicts, with auto-tune toggles per rule and monthly noise trend visualization.
- **Team analytics & gamification** — analyst leaderboard with sortable performance metrics, badges (MITRE Master, Speed Demon, Zero FP, Precision Strike), and team highlights feed.
- **STIX/TAXII publishing** — bidirectional threat intel sharing with STIX 2.1 bundle creation and TAXII collection management. Optional [STIX → MISP push](./integrations/misp-push) republishes high-confidence indicators and bundles to a MISP server with `dry-run` / `health` endpoints for fail-closed staging rollouts.
- **Automated compliance evidence** — continuous collection from connected sources across SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA frameworks.
- **AI-generated incident reports** — one-click PDF/MD export of case investigation summaries directly from the case detail view.
- **Real-time fusion** — Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest).
- **Attack graph** — Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions.
- **UEBA** — per-user Welford online baseline, Z-score anomaly scoring, and Kafka-integrated anomaly publishing.
- **Honeytokens** — HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting.
- **Purple Team** — Atomic Red Team YAML parser + Caldera executor, ATT&CK coverage heatmap, tabletop sessions.
- **Detection engineering** — 800+ native Sigma-shaped rules plus ~6,000 imported from SigmaHQ, Splunk Security Content, Chronicle, and MITRE CAR (each tagged with provenance), running over OpenSearch + ClickHouse, YARA, KQL / EQL, community catalog with one-click install. Includes 27 cloud-native rules covering M365, Azure, and GCP.
- **Detection-as-Code (DAC)** — propose, review, eval-gate, and promote detection rules via `/api/v1/detection-proposals`. Every proposal carries an eval result; candidates that regress MITRE accuracy are blocked from promotion.
- **Detection confidence** — each fused alert carries a `high / medium / low` confidence label and an ordered evidence chain. The label is derived from weighted factors, not manually assigned.
- **Detection drift monitoring** — scheduled ATT&CK coverage snapshots enable "delta vs. last week" tracking on the MITRE heatmap.
- **Hunt-as-Code** — YAML hunt definitions in `hunts/` with hypothesis, indicator matching (equals/in/regex/gte/lte/exists/contains_any/iendswith), and APScheduler-driven continuous execution. Results flow to Postgres via the Hunt API.
- **Risk-Based Alerting (RBA)** — alerts contribute time-decayed risk points to entities (user, host, IP, domain). When an entity's score crosses a configurable threshold, AiSOC promotes it to an incident with contributing alerts attached.
- **Federated search** — translate a single query into SPL, KQL, and ES|QL and fan out to connected SIEMs. Results are merged and deduplicated. A new natural-language `/hunt` surface accepts plain English and emits a deterministic template (the `HuntAgent` never writes raw queries), with saved hunts that deep-link into the [Investigation Rail](./console/investigation-rail).
- **Live Actions dispatcher** — push real response actions to connected EDR / IAM / network surfaces (isolate host, disable account, block IP, revoke session) with HMAC-signed idempotency keys and human-approval gates on destructive actions. ([Live Actions](./concepts/live-actions))
- **Slack ChatOps bot** — dedicated `aisoc` slash commands (`/aisoc triage`, `/aisoc approve`, `/aisoc status`, `/aisoc summary`) with interactive approval buttons and HMAC-signed callbacks. Human-in-the-loop triage without opening the console. (`services/slack-bot/`)
- **ChatOps verification** — Slack/Teams interactive prompts with HMAC-signed callback choices (acknowledge / deny / escalate) for human-in-the-loop response actions.
- **AI executive digest PDF** — branded A4 PDF with KPI tiles, alert-volume chart, top-rule table, and remediation summary, auto-emailed Monday 06:00 UTC via APScheduler. (`services/api/app/services/digest_pdf.py`)
- **Threat actor attribution engine** — per-alert actor attribution with MITRE Group mapping, confidence scoring, Diamond Model labeling, and campaign clustering. (`services/threatintel/app/actors/attribution.py`)
- **Air-gap / local-LLM mode** — run AiSOC with zero outbound HTTP using Ollama, LiteLLM, or vLLM via a single env-var toggle and a Docker Compose overlay. ([Air-gapped mode](./operations/air-gapped))
- **BYOK — Bring Your Own LLM key** — per-tenant LLM credential management (API key, base URL, model) stored encrypted in `CredentialVault`; configurable from the Settings UI. ([Credentials](./operations/credentials))
- **Saved views & drag-drop dashboard widgets** — analysts save custom alert filter presets and rearrange dashboard widgets; persisted per-user in Postgres.
- **Playbook engine** — 50+ community SOAR playbooks with explicit decision trees and human-approval gates on destructive actions.
- **Threat intelligence** — TAXII 2.1, MISP, OTX, CISA KEV with triple storage (search, vector, graph).
- **Governance** — SAML 2.0 + OIDC SSO, multi-tenant RLS, granular RBAC, immutable audit log.
- **Compliance dashboards** — SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD / MTTR / MTTC SLA tracking.
- **Public benchmark scoreboard** — live KPI bar (alert-to-incident ratio, MTTD, MTTR, FPR), per-suite eval results, and community submission leaderboard at `/benchmark`.
- **AI-vs-AI adversary eval** — deterministic attacker-LLM mutator generates adversarial incidents to test detection resilience under synonym swap, leetspeak, zero-width injection, and fragmentation attacks.
- **Marketplace** — 15 first-party plugins, 50+ playbooks, 6,900+ detections (filtered by tier: stable / beta / imported / community), surfaced in-app via [`marketplace/index.json`](https://github.com/beenuar/AiSOC/tree/main/marketplace).
- **SDKs** — Python, TypeScript, and Go SDKs for client and plugin development; Ed25519-signed publishing.
- **Model Context Protocol** — `@aisoc/mcp` exposes 13 tools to Claude, Cursor, Continue, and Cody so analysts can replay agent decisions and run governed warm-tier SELECTs from inside their IDE ([MCP integration](./integrations/mcp)).

## Architecture Overview

```
Sources (EDR, SIEM, Cloud, Identity, Network)
        │
        ▼
Connectors → Ingest (Go·OCSF) → Kafka spine
                                      │
              ┌───────────────────────┼────────────────────────┐
              ▼                       ▼                        ▼
         Fusion (ML)            UEBA (baseline)          Rules (Sigma·YARA)
              │                       │                        │
              └───────────────────────┼────────────────────────┘
                                      │
                         Storage Tier (Postgres·CH·OS·Qdrant·Neo4j·Redis)
                                      │
                         Core API (FastAPI) ◄──── Web Console (Next.js 14)
```

See the full [Architecture](./architecture) page for the detailed service map and data flow.

## Quick Links

### Get started

- [One-click install](./installation) — zero-prerequisite bootstrap for Linux, macOS, and Windows
- [Quick Start](./quickstart) — `pnpm aisoc:demo`, under 5 minutes to a live investigation. The **Path C — founder-style CLI** flow (`docker compose -f infra/compose/docker-compose.dev.yml up -d` → `aisoc db upgrade` → `aisoc serve` → `aisoc submit examples/alerts/lateral-movement.json`) goes from fresh clone to a live alert at `http://localhost:3000/alerts` in under 90 seconds, with no Kafka / Fusion required for the first alert.
- [Architecture](./architecture) — service map and data flow
- [Glossary](./glossary) — security and AiSOC-specific terminology in one place
- [FAQ](./operations/faq) — common questions about scope, deployment, data, and licensing

### Console workbenches (v1.5)

- [Investigation Rail](./console/investigation-rail) — `/alerts` two-pane workbench (PR-4)
- [Investigation Queue](./console/queue) — `/queue` workbench with atomic claim semantics (PR-5)
- [Rule Tuning](./console/rule-tuning) — `/detection/tuning` workbench (PR-6)
- [Funnel KPIs & pipeline health](./console/funnel-kpis) — operations funnel + pipeline health (PR-7)

### Core concepts

- [Detections](./concepts/detections)
- [Playbooks](./concepts/playbooks) — anatomy, triggers, conditions, approvals
- [Cases](./concepts/cases) — including the Investigation Ledger
- [Live Actions](./concepts/live-actions) — push real response actions to connected surfaces with approvals
- [Automation maturity (L0–L4)](./concepts/automation-maturity) — how AiSOC climbs from human-driven to fully autonomous closure
- [Capabilities](./concepts/capabilities) — full feature inventory by tier

### Connect & extend

- [Connectors](./connectors) — click-and-connect catalog with 52 cloud / SaaS / SIEM / EDR / IAM / VCS / network / ITSM / vuln / email-security sources, including [Wazuh Indexer](./connectors/wazuh) and [auditd `file_tail`](./connectors/auditd)
- [MCP Integration](./integrations/mcp) — connect Claude / Cursor / Continue / Cody
- [Plugin SDK (Python)](./plugins/python-sdk)
- [Plugin SDK (Go)](./plugins/go-sdk)

### APIs

- [REST API](./api/rest) — OpenAPI 3.1 spec
- [GraphQL API](./api/graphql) — schema and queries
- [WebSocket API](./api/websocket) — real-time events

### Operate

- [Deployment: Docker](./deployment/docker)
- [Deployment: Kubernetes](./deployment/kubernetes)
- [Deployment: Environment Variables](./deployment/env-vars)
- [Security model](./operations/security) — RBAC, MFA/SSO, audit logs, multi-tenant isolation
- [Credentials](./operations/credentials) — `CredentialVault` threat model and key rotation
- [Upgrades & versioning](./operations/upgrades) — release cadence, deprecation policy, in-place upgrades
- [Troubleshooting](./operations/troubleshooting) — common errors, log locations, recovery

### Quality & community

- [Public eval harness](./benchmark) — alert reduction plus MITRE / completeness / response-quality gates
- [Public weekly benchmark scoreboard](./benchmark-scoreboard) — community submission leaderboard refreshed weekly by CI
- [Contributing](./contributing/dev-setup) — local dev setup
- [Contribution guidelines](./contributing/guidelines) — branching, PR template, testing, plan files
