# AiSOC — AI-Powered Security Operations Center

<div align="center">

![AiSOC Logo](https://img.shields.io/badge/AiSOC-AI%20Security%20Operations-blue?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Built by Cyble](https://img.shields.io/badge/Built%20by-Cyble-orange?style=for-the-badge)](https://cyble.com)

**Enterprise-grade, open-source AI Security Operations Center**

[Features](#features) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Documentation](#documentation) · [Contributing](#contributing)

</div>

---

## Overview

AiSOC is a production-ready, enterprise-grade AI Security Operations Center built for modern threat detection, investigation, and response. It combines real-time streaming data ingestion, AI-powered threat analysis using autonomous agents, and hyperautomation workflows to give security teams unprecedented visibility and response capabilities.

Built and open-sourced by **Cyble** under the MIT License.

## Features

### 🤖 AI-Powered Investigation
- **Autonomous AI Agents** — LangGraph-based multi-agent system for investigation, threat hunting, and remediation
- **Natural Language Search** — Query your security data in plain English
- **Explainable AI** — Every AI decision comes with full reasoning chains

### ⚡ Real-Time Detection
- **Stream Processing** — Kafka-based event streaming with sub-second latency
- **Alert Fusion** — Intelligent deduplication and correlation reduces alert noise by 80%+
- **MITRE ATT&CK Mapping** — Automatic technique and tactic classification

### 🔗 Deep Integrations (Phase 1)
- CrowdStrike Falcon
- Splunk Enterprise / Cloud
- AWS Security Hub
- Okta Identity
- Microsoft Sentinel

### 🧠 Knowledge Graph (Neo4j)
- **Entity Graph** — Hosts, Users, Alerts, IOCs, Techniques, Cases connected as a property graph
- **Attack Path Reconstruction** — `/v1/graph/attack-path/{case_id}` returns the full kill-chain
- **Blast Radius Analysis** — Multi-hop traversal feeds the action executor's gating logic
- **MITRE Coverage** — Automatic mapping of telemetry to ATT&CK technique nodes

### 🎯 Detection Engineering
- **Sigma Rule Execution** — `pySigma` runner with OpenSearch/ClickHouse backends
- **YARA Scanning** — `yara-python` runner for file/memory artifact analysis
- **Multi-language Support** — KQL, EQL, Lucene, Regex query types
- **On-demand Hunts** — `POST /v1/rules/hunt` for ad-hoc threat hunting

### 🌐 Threat Intelligence Platform
- **TAXII 2.1 Feed Poller** — Ingests STIX 2.1 bundles from MITRE, Mandiant, ISAC feeds
- **MISP Integration** — Pulls events and IOCs from any MISP instance
- **AlienVault OTX** — Subscribed pulse consumption
- **CISA KEV Catalog** — Auto-correlates known-exploited CVEs against asset telemetry
- **Bloom-filter Dedup** — Redis-backed; handles 10M+ IOCs with ~0.1% false-positive rate
- **Triple Storage** — OpenSearch (search), Qdrant (semantic RAG), Neo4j (actor↔TTP graph)

### 🤖 ML-Augmented Fusion
- **Isolation Forest** — Unsupervised anomaly score per alert (auto-trained at 50+ samples)
- **LightGBM Ranker** — Priority score trained on analyst feedback (LambdaRank objective)
- **Feedback Loop** — `POST /ml/feedback` continuously improves the ranker
- **Heuristic Fallback** — Always-on scoring even before models are trained

### 🛰️ Vulnerability Correlation
- **Shodan Enrichment** — Open ports, banners, ASN, CVEs per public IP (Go enrichment service)
- **CISA KEV Cross-correlation** — Emits `VULNERABILITY_MATCH` Kafka events for KEV-listed CVEs
- **Asset Context** — Links exposure data to Host nodes in the knowledge graph

### 📊 SOC Console
- **Real-time Dashboard** — Live metrics, trend charts, and threat feeds
- **Alert Management** — Triage, investigate, and respond from a single pane
- **Case Management** — Full incident lifecycle management
- **Threat Intelligence** — IOC lookup, threat feed correlation
- **Threat Hunting** — KQL, Sigma, and YARA query execution
- **Attack Graph View** — Visual kill-chain reconstruction from Neo4j

### 🛡️ Enterprise Ready
- **Multi-tenant** — Complete tenant isolation with RBAC
- **Audit Logging** — Full compliance trail for SOC2, ISO 27001
- **Zero-trust** — JWT + API key auth with per-tenant scoping
- **High Availability** — Kubernetes-native with horizontal autoscaling

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AiSOC Platform                             │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     Web Frontend (Next.js 14)                │  │
│  │    Dashboard · Alerts · Cases · Threat Intel · Hunt · AI     │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                             │                                        │
│  ┌──────────────┐  ┌───────▼────────┐  ┌──────────────────────┐  │
│  │  Real-time   │  │   Core API     │  │   AI Agent           │  │
│  │  Service     │  │   (FastAPI)    │  │   Orchestrator       │  │
│  │  (Node.js)   │  │   REST/GraphQL │  │   (LangGraph)        │  │
│  │  WebSocket   │  └───────┬────────┘  └──────────────────────┘  │
│  └──────────────┘          │                                        │
│                    ┌───────▼────────────────┐                       │
│                    │      Apache Kafka       │                       │
│                    │   (Event Streaming)     │                       │
│                    └───────┬────────────────┘                       │
│                            │                                         │
│  ┌───────────┬─────────────┼──────────────────┬──────────────┐     │
│  │           │             │                  │              │     │
│  ▼           ▼             ▼                  ▼              ▼     │
│  Ingest    Enrich      Alert Fusion        Actions       Connectors │
│  Worker   (Go/Redis)   (Python)           (Python)      (Python)   │
│  (Go)                                                               │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    Data Layer                                │  │
│  │  PostgreSQL · ClickHouse · OpenSearch · Qdrant · Redis       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Service Map

| Service | Language | Port | Description |
|---------|----------|------|-------------|
| `api` | Python/FastAPI | 8000 | Core REST API — alerts, cases, tenants, RBAC, graph, rules |
| `ingest` | Go | 9090 | High-throughput event ingestion, OCSF normalization, Shodan + CVE correlation |
| `enrichment` | Go | 8080 | IOC enrichment via VirusTotal, AbuseIPDB, GreyNoise, Shodan |
| `fusion` | Python | 8003 | Alert dedup, correlation, ML anomaly + priority scoring |
| `agents` | Python/LangGraph | 8001 | AI investigation agents with full MITRE ATT&CK + Qdrant RAG |
| `actions` | Python | 8002 | SOAR action execution with blast-radius gating |
| `threatintel` | Python | 8005 | TAXII 2.1 / MISP / OTX / CISA KEV feed poller and IOC store |
| `realtime` | Node.js | 4000 | WebSocket/SSE real-time event delivery |
| `web` | Next.js 14 | 3000 | SOC console frontend |

### Data Layer

| Store | Purpose |
|-------|---------|
| **PostgreSQL** | App config, tenants, users, cases, detection rules, RLS-isolated |
| **ClickHouse** | High-cardinality event analytics, alert metrics, IOC enrichment cache |
| **OpenSearch** | Full-text IOC, actor, and threat report search; Sigma backend |
| **Qdrant** | Vector RAG for AI agents, semantic IOC and ATT&CK technique search |
| **Neo4j** | Knowledge graph: entity relationships, attack paths, blast radius |
| **Redis** | Cache, pub/sub, IOC bloom filter, enrichment TTL cache |
| **Kafka** | Event streaming bus (raw events, fused alerts, vulnerability matches) |

---

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose v2
- Node.js 20+ and pnpm 8+
- Go 1.21+ (for local development)
- Python 3.11+ (for local development)

### 1. Clone and Configure

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
cp .env.example .env  # if .env.example is missing, see Configuration below
```

Edit `.env` with your configuration:

```env
# Required for AI agents (use Anthropic OR OpenAI)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# Optional: threat intelligence enrichment
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...
SHODAN_API_KEY=...

# Optional: TAXII 2.1 feeds (comma-separated URL,collection,user,pass tuples)
TAXII_FEEDS=https://cti-taxii.mitre.org/taxii/,enterprise-attack,,
```

### 2. Start the Stack

```bash
# Start core infrastructure + all services
docker compose up -d

# Wait for services to be ready (~60s for first start)
docker compose ps

# View logs from a specific service
docker compose logs -f api
docker compose logs -f fusion
docker compose logs -f agents
```

### 3. Access the Console

| Surface | URL | Notes |
|---------|-----|-------|
| Web Console | http://localhost:3000 | Next.js frontend |
| API Swagger | http://localhost:8000/docs | Interactive API explorer |
| Agents API | http://localhost:8001/docs | LangGraph agent runner |
| Actions API | http://localhost:8002/docs | SOAR playbooks |
| Fusion API | http://localhost:8003/docs | ML status + feedback endpoints |
| Threat Intel | http://localhost:8005/docs | IOC search + feed status |
| Enrichment | http://localhost:8080/health | Shodan + KEV CVE correlation |
| Ingest | http://localhost:8081/health | Go ingest worker |
| Realtime WS | ws://localhost:8086/ws | Live alert stream |
| Neo4j Browser | http://localhost:7474 | `neo4j` / `neo4j_dev_secret` |
| OpenSearch | http://localhost:9200 | Full-text search |
| Qdrant | http://localhost:6333 | Vector DB (RAG) |
| ClickHouse | http://localhost:8123 | Analytics warehouse |
| Grafana | http://localhost:3001 | `admin` / `admin` (monitoring profile) |
| Jaeger | http://localhost:16686 | Distributed traces (monitoring profile) |

Default API credentials: `admin@aisoc.local` / `changeme`

### 4. Run with Connectors

```bash
# Start with connectors profile
docker compose --profile connectors up -d

# Start with monitoring
docker compose --profile monitoring up -d
```

---

## Development

### Monorepo Structure

```
aisoc/
├── apps/
│   └── web/              # Next.js 14 SOC console
├── services/
│   ├── api/              # Python FastAPI — core REST API + Neo4j graph + rule engine
│   ├── ingest/           # Go — event ingestion, OCSF, Shodan + CVE correlation
│   ├── enrichment/       # Go — IOC enrichment
│   ├── fusion/           # Python — alert dedup, correlation, ML scoring
│   ├── agents/           # Python LangGraph — AI agents w/ full ATT&CK + Qdrant RAG
│   ├── actions/          # Python — SOAR action execution
│   ├── threatintel/      # Python — TAXII/MISP/OTX/KEV feed poller
│   └── realtime/         # Node.js — WebSocket/SSE
├── integrations/         # Connector implementations (CrowdStrike, Splunk, AWS, Okta, Sentinel, ...)
├── packages/
│   ├── types/            # Shared TypeScript types
│   ├── ui/               # Shared React components
│   └── ocsf/             # OCSF schema normalization
├── infra/
│   ├── terraform/        # AWS infrastructure (VPC, EKS, RDS)
│   └── helm/             # Kubernetes Helm chart
├── docs/
│   ├── architecture/     # System design, data flows
│   ├── api/              # API reference
│   └── runbooks/         # Operations guides
└── docker-compose.yml
```

### Frontend Development

```bash
cd apps/web
pnpm install
pnpm dev
```

### Backend Development

```bash
# Start infrastructure only
docker compose up -d postgres redis kafka clickhouse opensearch qdrant neo4j

# Run core API
cd services/api
poetry install
poetry run uvicorn app.main:app --reload --port 8000

# Run fusion worker (with ML scoring)
cd services/fusion
poetry install
poetry run uvicorn app.main:app --reload --port 8003

# Run ingest worker
cd services/ingest
go run main.go

# Run threat intel feed poller
cd services/threatintel
poetry install
poetry run uvicorn app.main:app --reload --port 8005
```

### Running Tests

```bash
# Frontend
cd apps/web && pnpm test

# Core API
cd services/api && poetry run pytest

# Go services
cd services/ingest && go test ./...
```

---

## Deployment

### Kubernetes (Recommended)

```bash
# Add Bitnami repo for dependencies
helm repo add bitnami https://charts.bitnami.com/bitnami

# Install AiSOC
helm install aisoc ./infra/helm/aisoc \
  --namespace aisoc \
  --create-namespace \
  --values ./infra/helm/aisoc/values.yaml \
  --set global.environment=production
```

### Terraform (AWS)

```bash
cd infra/terraform
terraform init
terraform plan -var="environment=prod"
terraform apply
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `KAFKA_BOOTSTRAP_SERVERS` | Yes | Kafka broker addresses |
| `OPENAI_API_KEY` | Yes | OpenAI API key for AI agents |
| `SECRET_KEY` | Yes | JWT signing secret |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal enrichment |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB enrichment |
| `GREYNOISE_API_KEY` | No | GreyNoise enrichment |

---

## API Documentation

Once running, API docs are available at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- OpenAPI JSON: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

For detailed API references, system design, and runbooks see:
- [API Reference](docs/api/API_REFERENCE.md)
- [System Design](docs/architecture/SYSTEM_DESIGN.md)
- [Local Development Runbook](docs/runbooks/LOCAL_DEVELOPMENT.md)

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Good First Issues

- Adding new connector integrations
- Improving MITRE ATT&CK coverage
- Frontend UI enhancements
- Documentation improvements
- Test coverage

---

## Security

Please report security vulnerabilities to `security@cyble.com`. Do not open public GitHub issues for security vulnerabilities.

---

## License

Copyright © 2024 Cyble. Released under the [MIT License](LICENSE).

---

<div align="center">
Built with ❤️ by the <a href="https://cyble.com">Cyble</a> team
</div>
