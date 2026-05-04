---
sidebar_position: 3
---

# Architecture

## High-Level Data Flow

```
External Sources
  (EDR · SIEM · Cloud · Identity · Network · Threat Intel)
        │
        ▼ connectors
   Kafka spine  ◄── Honeytokens (deception events)
        │
   ┌────┼──────────────────────────────────┐
   ▼    ▼                                  ▼
Fusion  UEBA                           Detections
(ML)  (baseline)                  (Sigma·YARA·KQL·EQL)
   │    │                                  │
   └────┴──────────────────────────────────┘
                      │
              PostgreSQL · ClickHouse · OpenSearch
              Qdrant (vectors) · Neo4j (graph) · Redis
                      │
               FastAPI Core API (port 8000)
                      │
            ┌─────────┼──────────┬─────────────┐
            ▼         ▼          ▼             ▼
         Next.js   Agents   Realtime         MCP
        (port 3000) (8001)  (8086, WS+Push)  (TS, stdio)
                       │
                Investigation Ledger
              (every prompt/tool/step,
               replayable per case)
```

The new structural pieces in v5.2 are the **Investigation Ledger** (every
agent prompt, response, evidence citation, and tool call is logged step-by-
step against a case and replayable in the UI), the **Ambient Copilot**
(context-aware next-action surface across alerts, cases, rules, and
playbooks), the **Responder PWA** (passkey-only mobile route at
`/responder/*` with VAPID Web Push), the **public eval harness** (one
real measurement plus three substrate self-consistency gates, run in CI),
and the **MCP server** (`@aisoc/mcp`, exposes 11 tools to Claude / Cursor /
Continue / Cody).

## Monorepo Layout

```
AiSOC/
├── apps/
│   ├── web/                # Next.js 14 React frontend (incl. Responder PWA)
│   └── docs/               # This Docusaurus site
├── services/
│   ├── api/                # FastAPI gateway              (port 8000)
│   ├── agents/             # LangGraph investigator       (port 8001)
│   ├── realtime/           # Node/TS WebSocket + Web Push (port 8086)
│   ├── ingest/             # Go OCSF normaliser           (port 8081)
│   ├── enrichment/         # Go enrichment fan-out        (port 8080)
│   ├── fusion/             # Fusion + ML scoring          (port 8003)
│   ├── actions/            # Action executor              (port 8002)
│   ├── threatintel/        # TAXII / MISP / OTX / KEV     (port 8005)
│   ├── ueba/               # User behavior analytics      (port 8007)
│   ├── honeytokens/        # Deception platform           (port 8008)
│   ├── purple-team/        # Adversary emulation          (port 8006)
│   └── mcp/                # Model Context Protocol server (TypeScript)
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
├── playbooks/              # 50+ SOAR playbooks (YAML)
├── plugins/                # 15 first-party plugins (Go + Python)
├── marketplace/            # Marketplace index (index.json)
├── docs/                   # OpenAPI spec (openapi.yaml)
├── docker-compose.yml      # Full development stack
├── docker-compose.demo.yml # Slim profile for `pnpm aisoc:demo`
└── scripts/                # Utilities (seed, eval harness, build, validate)
```

## Service Responsibilities

| Service | Port | Language | Responsibility |
|---------|------|----------|----------------|
| `api` | 8000 | Python (FastAPI) | REST gateway, auth, RBAC, RLS, audit log, **Investigation Ledger**, Ambient Copilot, marketplace, approvals, on-call, passkeys, push subscriptions |
| `agents` | 8001 | Python (LangGraph) | Orchestrator + recon + forensic + responder + report-writer agents, playbook engine, ledger writes |
| `realtime` | 8086 | TypeScript (Node.js) | WebSocket streaming of agent steps; **VAPID Web Push** delivery for the Responder PWA |
| `ingest` | 8081 | Go | OCSF normalisation, Bloom-filter dedup, Kafka publish |
| `enrichment` | 8080 | Go | Enrichment fan-out (IP, domain, hash, email, user) |
| `fusion` | 8003 | Python | ML scoring (LightGBM + Isolation Forest), correlation |
| `actions` | 8002 | Python | Plugin action executor, blast-radius gating |
| `threatintel` | 8005 | Python | TAXII 2.1 / MISP / OTX / KEV ingestion + triple storage |
| `ueba` | 8007 | Python | Welford baseline, Z-score scoring, anomaly stream |
| `honeytokens` | 8008 | Python | Token lifecycle, HMAC signing, webhook dispatch |
| `purple-team` | 8006 | Python | ART YAML parser, Caldera executor, ATT&CK heatmap |
| `mcp` | n/a | TypeScript | Model Context Protocol stdio server, 11 tools for IDE-side agents |
| `web` | 3000 | TypeScript (Next.js) | React console + Responder PWA route group |

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
- **Widgets** *(v5.2)* — Render plugin-supplied React panels in the case workspace

See [Plugin Overview](./plugins/overview) for the full plugin lifecycle.
