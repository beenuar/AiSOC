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
                 ┌────┴────┐
                 ▼         ▼
            Next.js      Agents
           (port 3000)  LangGraph
                        (port 8001)
```

## Monorepo Layout

```
aisoc/
├── apps/
│   ├── web/               # Next.js 14 React frontend
│   └── docs/              # This Docusaurus site
├── services/
│   ├── api/               # FastAPI gateway        (port 8000)
│   ├── agents/            # LangGraph investigator (port 8001)
│   ├── realtime/          # WebSocket server       (port 8002)
│   ├── ingest/            # Go OCSF normaliser     (port 8003)
│   ├── honeytokens/       # Deception platform     (port 8004)
│   ├── ueba/              # User behavior analytics(port 8005)
│   └── purple-team/       # Adversary emulation    (port 8006)
├── packages/
│   ├── plugin-sdk-py/     # Python plugin SDK
│   ├── plugin-sdk-go/     # Go plugin SDK
│   ├── sdk-py/            # Python client SDK
│   ├── sdk-ts/            # TypeScript client SDK
│   └── sdk-go/            # Go models
├── infra/
│   ├── helm/aisoc/        # Helm chart (Kubernetes)
│   └── terraform/         # Terraform modules
├── playbooks/             # Starter playbook templates (JSON)
├── detections/            # Detection rules (YAML)
├── marketplace/           # Community marketplace index
├── docs/                  # OpenAPI spec (openapi.yaml)
└── scripts/               # Utilities (backup, seed, runbook gen)
```

## Service Responsibilities

| Service | Port | Language | Responsibility |
|---------|------|----------|----------------|
| `api` | 8000 | Python | REST gateway, auth, RBAC, routing |
| `agents` | 8001 | Python | LangGraph AI investigator, playbook engine |
| `realtime` | 8002 | Python | WebSocket streaming, live agent steps |
| `ingest` | 8003 | Go | OCSF normalisation, Bloom dedup, Kafka publish |
| `honeytokens` | 8004 | Python | Token lifecycle, HMAC signing, webhook dispatch |
| `ueba` | 8005 | Python | Welford baseline, Z-score scoring, anomaly stream |
| `purple-team` | 8006 | Python | ART YAML parser, Caldera executor, ATT&CK heatmap |
| `web` | 3000 | TypeScript | React/Next.js console |

## Storage Tier

| Store | Role |
|-------|------|
| PostgreSQL | Operational data, RLS-enforced multi-tenancy, audit log |
| ClickHouse | Time-series analytics, compliance metrics |
| OpenSearch | Full-text search across alerts, logs, cases |
| Qdrant | Semantic vector search for RAG copilot |
| Neo4j | Attack graph, entity relationships |
| Redis | Cache, rate-limiting, session store |
| Kafka | Async event backbone |

## Enterprise Security Controls

- **Multi-tenancy** — PostgreSQL Row-Level Security on every table; `tenant_id` is derived from the JWT and cannot be spoofed.
- **RBAC** — `require_permission` FastAPI dependency; custom roles with fine-grained action permissions per resource type.
- **SAML 2.0 / OIDC** — Pluggable SSO with JIT user provisioning and group-to-role mapping.
- **Immutable Audit Log** — Postgres trigger + `SECURITY DEFINER` function prevents UPDATE/DELETE on `audit_log`.
- **OpenTelemetry** — All services emit traces, metrics, and structured logs to a configurable OTLP endpoint.
- **Backup & Restore** — `scripts/backup.sh` / `restore.sh` with AES-256-GCM encryption and SHA-256 manifest.
- **High-Availability Helm** — Multi-replica deployments, HPA, PDB, anti-affinity, and readiness probes.

## Plugin Extension Points

Plugins extend AiSOC at three key points:

- **Enrichers** — Add context to indicators (IP, domain, hash, email)
- **Actions** — Execute response steps (block IP, disable user, create ticket)
- **Connectors** — Ingest events from external sources (SIEM, EDR, cloud)

See [Plugin Overview](./plugins/overview) for the full plugin lifecycle.
