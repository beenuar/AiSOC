---
sidebar_position: 4
---

# Architecture

## High-Level Data Flow

```
External Sources
  (EDR · SIEM · Cloud · Identity · Network · SaaS · Threat Intel)
        │                                ▲
        │                                │
        │                       osquery-tls + osquery-extensions
        │                          (endpoint telemetry, host live-query)
        ▼ connectors (50 vendors, registry-based)
   Kafka spine  ◄── Honeytokens (deception events)
        │
   ┌────┼─────────────────────┬────────────────────┐
   ▼    ▼                     ▼                    ▼
Fusion  UEBA                Detections        Threat Intel
(ML +  (Welford,           (Sigma·YARA·       (TAXII · MISP ·
 RBA)   Z-score)            KQL·EQL · DAC)     OTX · KEV)
   │    │                     │                    │
   └────┴─────────────────────┴────────────────────┘
                      │
              PostgreSQL · ClickHouse · OpenSearch
              Qdrant (vectors) · Neo4j (graph) · Redis
                      │
               FastAPI Core API (port 8000)
                      │
   ┌─────────┬────────┼────────┬─────────────┬─────────────┐
   ▼         ▼        ▼        ▼             ▼             ▼
Next.js   Agents  Realtime   MCP        Slack-bot      Actions
(3000)    (8001)  (8086,    (TS,       (ChatOps,       (8002,
React +          WS+Push)  stdio)    HMAC-signed)   SOAR exec)
PWA          │
             ▼
       Investigation Ledger
     (every prompt/tool/step,
      replayable per case)
```

Key structural pieces include the **Investigation Ledger** (every
agent prompt, response, evidence citation, and tool call is logged step-by-
step against a case and replayable in the UI), the **Ambient Copilot**
(context-aware next-action surface across alerts, cases, rules, and
playbooks), the **Responder PWA** (passkey-only mobile route at
`/responder/*` with VAPID Web Push), the **public eval harness** (one
real measurement plus three substrate self-consistency gates, run in CI),
the **MCP server** (`@aisoc/mcp`, exposes 13 tools to Claude / Cursor /
Continue / Cody — including the warm-tier `aisoc_lake_query` /
`aisoc_lake_schema` pair, gated by the `lake:query` permission), and the
**click-and-connect connector platform** (next section).

Additional capabilities introduced in 2026 H2:

- **Detection-as-Code (DAC)** — propose → review → eval-gate → promote lifecycle for detection rules, with eval results gating promotion.
- **Detection confidence** — each fused alert carries a derived confidence label (`high / medium / low`) with an ordered evidence chain.
- **Detection drift monitoring** — scheduled ATT&CK coverage snapshots with delta tracking.
- **Hunt-as-Code** — YAML hunt definitions in `hunts/` with hypothesis-driven indicator matching and APScheduler-driven continuous execution.
- **Risk-Based Alerting (RBA)** — time-decayed entity risk scoring that promotes high-risk entities to incidents.
- **Federated search** — translate a single query into SPL, KQL, and ES|QL and fan out to connected SIEMs.
- **ChatOps verification** — HMAC-signed Slack/Teams interactive prompts for human-in-the-loop response actions.
- **AI-vs-AI adversary eval** — deterministic attacker-LLM mutator for testing detection resilience.

### v1.5 — market-driven additions (2026-05-07)

The v1.5 release ships from a review of G2, Gartner Peer Insights, and customer feedback on AI SOC / SIEM / SOAR platforms. It adds five new agents, eight new console pages, four new API surfaces, and ten new connectors:

- **Autonomous alert triage agents** — `services/agents/app/agents/auto_triage_agent.py` plus four sibling agents (phishing, identity, cloud, insider-threat) classify each alert as `true_positive` / `false_positive` / `benign` with a confidence score. Low-confidence noise auto-closes; the rest is escalated. Surfaced via `/api/v1/agents/triage`.
- **Conversational investigation chat** — multi-turn copilot at `/investigate` that anchors on a case and reads its evidence, ledger, and entity graph for grounded follow-up Q&A. Component: `apps/web/src/components/copilot/InvestigationChat.tsx`.
- **MITRE ATT&CK coverage advisor** — `/coverage-advisor` ranks technique gaps by adversary prevalence and recommends rules to close them.
- **Shift handoff dashboard** — `/shifts` shows outgoing/incoming analysts the active cases, in-flight investigations, and queued approvals on one screen. Endpoints in `services/api/app/api/v1/endpoints/shifts.py`.
- **EASM (External Attack Surface Management)** — `/easm` discovers assets, exposed services, and certificate-expiry risks for everything the org points at the public internet.
- **MSSP executive dashboard** — `/mssp` rolls up KPIs, cross-tenant alert volumes, and per-customer SLA posture into a multi-tenant pane.
- **Investigation Rail on `/alerts`** — two-pane alert queue: selecting a row opens a right-hand rail with **deterministic correlation narrative** (fusion-time, no LLM on read), **related entities** with pivot links, a **mini-timeline** (case + audit, six events), and **recommended actions**. `GET /api/v1/alerts/{id}` returns a structured envelope; legacy rows lazy back-fill narrative on first read. See [Investigation Rail](./console/investigation-rail).
- **Alert noise-tuning dashboard** — `/noise-tuning` (and `/detection/tuning` where deployed) surfaces per-rule false-positive rate, suppression candidates, and one-click tuning.
- **Team analytics & gamification** — `/analytics/team` ships analyst leaderboard, MTTR per analyst, dispositions accuracy, and shift workload balance.
- **STIX 2.1 / TAXII 2.1 publishing** — `services/api/app/api/v1/endpoints/stix_taxii.py` pushes the tenant's IOCs and threat-actor profiles to upstream / community feeds.
- **Automated compliance evidence** — `services/api/app/api/v1/endpoints/compliance.py` collects point-in-time evidence for SOC 2 / ISO 27001 / NIST CSF / PCI-DSS / HIPAA / DORA.
- **AI-generated incident reports** — one-click "Export Report" on every case generates a PDF incident report from the Investigation Ledger.
- **Air-gap deployment configuration** — `services/api/app/api/v1/endpoints/deployment.py` exposes air-gap mode toggles for tenants that disallow external feeds.
- **Connector catalog growth** — SentinelOne, Cortex XDR / XSIAM, Wiz, Snyk, Zscaler, Proofpoint, ServiceNow, Jira, 1Password, Duo Security, Carbon Black, Chronicle, Cisco Umbrella, CrowdStrike, Datadog Cloud SIEM, Elastic, Mimecast, Okta, Rapid7 InsightIDR, Salesforce, Microsoft Sentinel, Splunk, Sumo Logic, Tenable, Trellix Helix, Trend Vision One, and more. **The catalog is now 77 connectors** across EDR, SIEM, cloud, identity, SaaS, network, and email categories. See [Connectors](./connectors/).

## Connector polling and credential vault

```
Browser (Add connector wizard)
    │
    │ POST /api/v1/connectors  { type, auth_config, connector_config }
    ▼
services/api  ─── CredentialVault.encrypt() ───▶ vault:v1:<base64>
    │
    │ INSERT INTO connectors(auth_config_encrypted, ...)
    ▼
PostgreSQL  ◄────────────────────────────────────────────────────┐
    │                                                            │
    │ every 30s reload                                            │
    ▼                                                             │
services/connectors                                               │
   ConnectorScheduler (APScheduler, in-process)                   │
       │                                                          │
       │  per-instance job @ poll_interval_seconds (default 300s) │
       ▼                                                          │
   _poll_one(instance)                                            │
       │                                                          │
       │ 1. CredentialVault.decrypt() ── reads same key as API ──┘
       │ 2. construct connector class from registry
       │ 3. await connector.fetch_alerts(since_seconds=300)
       │ 4. [connector.normalize(e) for e in raw_events]
       │ 5. await ingest_client.push_events(tenant_id, normalized)
       │ 6. record_poll_success(events_added, elapsed_ms)
       ▼
services/ingest  POST /v1/ingest/batch  X-Tenant-ID: <uuid>
       │
       ▼
   Kafka spine ──▶ Fusion · UEBA · Detections (existing pipeline)
```

### Founder-flow direct-write submit (v7.3.1+)

For the fresh-clone demo and any flow where Kafka / Fusion / `services/ingest`
is not required for the first alert, `services/api` exposes a dedicated
direct-write endpoint:

```
POST /api/v1/alerts/submit   (X-Tenant-ID: <uuid>)
    │
    │ payload: { "events": [<OCSF event>, ...], "rule_id": "demo.lateral-movement" }
    ▼
services/api
    │ 1. parse OCSF events (no Kafka, no services/ingest)
    │ 2. _synthesise_alert_from_events()  ── derives entities, MITRE tags, severity
    │ 3. INSERT INTO alerts(...)          ── single row, idempotent
    │ 4. return { id, status: "new" }
    ▼
PostgreSQL  ──▶  /alerts console (lights up immediately)
```

This is the path used by the `aisoc submit` CLI command and the
[`examples/alerts/lateral-movement.json`](https://github.com/beenuar/AiSOC/tree/main/examples/alerts/lateral-movement.json)
canonical payload. The classic Kafka-fed pipeline above is still the
**production** path; the direct-write endpoint exists so a fresh clone of
the repo, an `aisoc serve` process, and a single `aisoc submit` call are
enough to see an alert on `/alerts` — no broker, no schedulers, no
connectors required.

The `services/api` service holds the **encrypt** authority for the vault
and is the only writer to `connectors.auth_config_encrypted`.
`services/connectors` ships a vendored read-path `decrypt_dict()` that
pairs to the same `AISOC_CREDENTIAL_KEY` so the scheduler can decrypt
per-poll without owning the write path. Key rotation is supported via
`MultiFernet` and the `AISOC_CREDENTIAL_KEY_ROTATION_FROM` env var; the
[Operations: Credentials](./operations/credentials) page documents the
full rotation procedure, threat model, and hosted-OAuth roadmap.

The wizard's `Test connection` button skips the vault entirely — it
forwards the raw form values to a stateless `POST /connectors/{id}/test`
endpoint on the connectors microservice, which constructs the connector
in memory and calls `test_connection()`. Bad credentials never touch the
database.

## Monorepo Layout

```
AiSOC/
├── apps/
│   ├── web/                # Next.js 14 React frontend (incl. Responder PWA)
│   └── docs/               # This Docusaurus site
├── services/
│   ├── api/                  # FastAPI gateway              (port 8000)
│   ├── agents/               # LangGraph investigator       (port 8001)
│   ├── realtime/             # Node/TS WebSocket + Web Push (port 8086)
│   ├── ingest/               # Go OCSF normaliser           (port 8081)
│   ├── enrichment/           # Go enrichment fan-out        (port 8080)
│   ├── fusion/               # Fusion + ML scoring          (port 8003)
│   ├── actions/              # Action executor              (port 8002)
│   ├── threatintel/          # TAXII / MISP / OTX / KEV     (port 8005)
│   ├── ueba/                 # User behavior analytics      (port 8007)
│   ├── honeytokens/          # Deception platform           (port 8008)
│   ├── purple-team/          # Adversary emulation          (port 8006)
│   ├── connectors/           # Connector polling + credential vault (50 vendors)
│   ├── demo-producer/        # Synthetic event generator for demos
│   ├── mcp/                  # Model Context Protocol server (TypeScript)
│   ├── osquery-tls/          # osquery TLS server: enrol hosts, ship results
│   ├── osquery-extensions/   # Custom osquery tables/decorators
│   └── slack-bot/            # ChatOps surface (HMAC-signed approvals)
├── packages/
│   ├── plugin-sdk-py/      # Python plugin SDK
│   ├── plugin-sdk-go/      # Go plugin SDK
│   ├── sdk-py/             # Python client SDK
│   ├── sdk-ts/             # TypeScript client SDK
│   └── sdk-go/             # Go models / client helpers
├── infra/
│   ├── helm/aisoc/         # Helm chart (Kubernetes, HA-ready)
│   ├── terraform/          # Terraform modules
│   ├── coolify/            # One-click deploy on Coolify
│   ├── fly/                # Fly.io demo deployments
│   ├── railway/            # Railway templates
│   └── render/             # render.yaml blueprint
├── detections/             # 200+ Sigma/YARA/KQL detection rules (YAML)
├── hunts/                  # Hunt-as-Code YAML definitions (hypothesis + indicators)
├── playbooks/              # 50+ SOAR playbooks (YAML)
├── plugins/                # 15 first-party plugins (Go + Python)
├── marketplace/            # Marketplace index (index.json)
├── docs/                   # OpenAPI spec (openapi.yaml)
├── docker-compose.yml      # Full development stack
├── infra/compose/          # docker-compose.{demo,dev,airgap}.yml overlays
└── scripts/                # Utilities (seed, eval harness, build, validate)
```

## Service Responsibilities

| Service | Port | Language | Responsibility |
|---------|------|----------|----------------|
| `api` | 8000 | Python (FastAPI) | REST gateway, auth, RBAC, RLS, audit log, **Investigation Ledger**, **alert detail envelope** (Investigation Rail: narrative, entities, mini-timeline, actions), Ambient Copilot, marketplace, approvals, on-call, passkeys, push subscriptions, **Detection Proposals** (DAC lifecycle), **Federated Search** fan-out, SLA tracking, **Shifts** handoff, **STIX/TAXII** publishing, **Compliance evidence** collection, **Deployment / air-gap** configuration |
| `agents` | 8001 | Python (LangGraph) | Orchestrator + recon + forensic + responder + report-writer agents, **autonomous triage agent** + phishing / identity / cloud / insider-threat sub-agents, **conversational investigation chat**, playbook engine, ledger writes, **Hunt-as-Code** engine + scheduler |
| `realtime` | 8086 | TypeScript (Node.js) | WebSocket streaming of agent steps; **VAPID Web Push** delivery for the Responder PWA |
| `ingest` | 8081 | Go | OCSF normalisation, Bloom-filter dedup, Kafka publish |
| `enrichment` | 8080 | Go | Enrichment fan-out (IP, domain, hash, email, user) |
| `fusion` | 8003 | Python | ML scoring (LightGBM + Isolation Forest), correlation, **deterministic correlation narratives** on fused alerts, **alert confidence scoring**, **entity risk / RBA** |
| `actions` | 8002 | Python | Plugin action executor, blast-radius gating, **ChatOps verification** (HMAC-signed Slack/Teams prompts) |
| `threatintel` | 8005 | Python | TAXII 2.1 / MISP / OTX / KEV ingestion + triple storage |
| `ueba` | 8007 | Python | Welford baseline, Z-score scoring, anomaly stream |
| `honeytokens` | 8008 | Python | Token lifecycle, HMAC signing, webhook dispatch |
| `purple-team` | 8006 | Python | ART YAML parser, Caldera executor, ATT&CK heatmap, **detection drift snapshots** |
| `connectors` | — | Python | Connector polling (APScheduler), credential vault (`CredentialVault`), registry-based discovery — **50 vendors shipped** across EDR / SIEM / cloud / IAM / SaaS / network / email |
| `demo-producer` | — | Python | Synthetic event generator for demos and evaluation |
| `mcp` | n/a | TypeScript | Model Context Protocol stdio server, 13 tools for IDE-side agents (Claude / Cursor / Continue / Cody) — discovery, deep-dive, action/replay, and the warm-tier lake query pair |
| `osquery-tls` | 8443 | Go | TLS server implementing osquery's enrol/config/distributed/log endpoints; ships normalised host events into `ingest` |
| `osquery-extensions` | — | Go | Out-of-band osquery extensions registering custom virtual tables and decorators consumed by `osquery-tls` |
| `slack-bot` | — | Python | ChatOps surface: posts approval prompts, exposes `/aisoc` slash command, verifies inbound interactions with HMAC-signed Slack request signatures |
| `web` | 3000 | TypeScript (Next.js) | React console + Responder PWA route group, **`/alerts` Investigation Rail**, **benchmark scoreboard**, conversational investigation chat |

## Storage Tier

| Store | Role |
|-------|------|
| PostgreSQL | Operational data, RLS-enforced multi-tenancy, audit log, **investigation ledger** |
| ClickHouse | Time-series analytics, compliance metrics |
| OpenSearch | Full-text search across alerts, logs, cases |
| Qdrant | Semantic vector search for RAG copilot + agent memory |
| Neo4j | Attack graph, entity relationships, blast-radius queries |
| Redis | Cache, rate-limiting, session store, push subscription cache |
| Kafka | Async event backbone |

## Investigation Ledger

Every agent action (LLM prompt, LLM response, tool call, evidence
citation, decision branch) is appended to the `investigation_ledger`
table, scoped to a case and stamped with the agent identity, model,
prompt hash, and timestamp. The Case workspace renders this as a
scrubbable timeline so analysts can replay the agent's reasoning.

The schema is defined in
[`services/api/migrations/008_investigation_ledger.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/008_investigation_ledger.sql).
The agent-side writer lives in
[`services/agents/app/investigator/ledger.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/app/investigator/ledger.py),
and the UI consumer is
[`apps/web/src/components/cases/InvestigationLedger.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/cases/InvestigationLedger.tsx).

### Prompt sanitization layer

Investigator agents (`recon`, `forensic`, `responder`, `report_writer`) consume
attacker-influenced strings — enrichment payloads, dark-web excerpts, vendor
descriptions, raw alert fields — and hand them to an LLM. Every one of those
agents now routes its context through
[`services/agents/app/investigator/prompt_sanitizer.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/app/investigator/prompt_sanitizer.py),
which strips known role / chat delimiters, redacts common jailbreak phrasings,
caps field length, bounds list size and recursion depth, and wraps the result
in explicit `<UNTRUSTED_DATA>` tags. The agents still validate the LLM's
response against a Pydantic schema before persisting it. See the
[LLM prompt safety section in the security guide](./operations/security#llm-prompt-safety)
for the threat model and defence-in-depth layers.

## Investigation Rail and correlation narrative

The alert queue (`/alerts`) pairs the sortable table with an **Investigation Rail**
([`InvestigationRail.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/alerts/InvestigationRail.tsx))
fed by `GET /api/v1/alerts/{id}`. The response envelope is assembled in
[`services/api/app/services/alert_rail.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/alert_rail.py)
(narrative text, entity buckets, merged mini-timeline, recommended actions).

**Narrative** — At fusion time, `services/fusion` runs the same deterministic
builder as the API vendored copy ([`narrative.py`](https://github.com/beenuar/AiSOC/blob/main/services/fusion/app/services/narrative.py))
so promoted alerts persist a short explanation of *which* signals correlated
and *why*. Reads do not call an LLM. Alerts created before this shipped get a
lazy projection on first detail fetch via
[`narrative_projection.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/narrative_projection.py),
then the text is cached on the row (see migration `041_alert_correlation_narrative.sql`).

**Sync** — When the narrative builder changes, run `scripts/sync_vendored_narrative.py`
so `services/api/app/_vendor/narrative.py` stays aligned with fusion.

Operator-facing detail: [Investigation Rail](./console/investigation-rail).

## Responder PWA

The Responder PWA is mounted under the Next.js route group
`apps/web/src/app/(responder)/`. It is **passkey-only** (no passwords),
shows the on-call rotation, lists pending approvals, supports VAPID
Web Push for high-severity alerts, and ships an offline shell.

The schema is defined in
[`009_responder_pwa.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/009_responder_pwa.sql).
The push pipeline lives in
[`services/realtime/src/push.ts`](https://github.com/beenuar/AiSOC/blob/main/services/realtime/src/push.ts).

## Enterprise Security Controls

- **Multi-tenancy** — PostgreSQL Row-Level Security on every table; `tenant_id` is derived from the JWT and cannot be spoofed.
- **RBAC** — `require_permission` FastAPI dependency; custom roles with fine-grained action permissions per resource type.
- **SAML 2.0 / OIDC** — Pluggable SSO with JIT user provisioning and group-to-role mapping.
- **WebAuthn / Passkeys** — Required for the Responder PWA; password-less by default.
- **Immutable Audit Log** — Postgres trigger + `SECURITY DEFINER` function prevents UPDATE/DELETE on `audit_log`.
- **Replayable agent decisions** — The Investigation Ledger is append-only and tenant-scoped.
- **OpenTelemetry** — All services emit traces, metrics, and structured logs to a configurable OTLP endpoint.
- **Backup & Restore** — `scripts/backup.sh` / `restore.sh` with AES-256-GCM encryption and SHA-256 manifest.
- **High-Availability Helm** — Multi-replica deployments, HPA, PDB, anti-affinity, and readiness probes.

## Plugin Extension Points

Plugins extend AiSOC at three key points:

- **Enrichers** — Add context to indicators (IP, domain, hash, email)
- **Actions** — Execute response steps (block IP, disable user, create ticket)
- **Connectors** — Ingest events from external sources (SIEM, EDR, cloud)
- **Widgets** — Render plugin-supplied React panels in the case workspace

See [Plugin Overview](./plugins/overview) for the full plugin lifecycle.
