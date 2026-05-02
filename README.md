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

### 📊 SOC Console
- **Real-time Dashboard** — Live metrics, trend charts, and threat feeds
- **Alert Management** — Triage, investigate, and respond from a single pane
- **Case Management** — Full incident lifecycle management
- **Threat Intelligence** — IOC lookup, threat feed correlation
- **Threat Hunting** — KQL, Sigma, and YARA query execution

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
| `core-api` | Python/FastAPI | 8000 | REST API — alerts, cases, tenants, RBAC |
| `ingest` | Go | 9090 | High-throughput event ingestion + OCSF normalization |
| `enrichment` | Go | 8080 | IOC enrichment via VirusTotal, AbuseIPDB, GreyNoise |
| `alert-fusion` | Python | — | Alert deduplication, correlation, incident grouping |
| `agents` | Python/LangGraph | 8001 | AI investigation, threat hunting, remediation agents |
| `actions` | Python | 8002 | SOAR action execution with blast-radius gating |
| `realtime` | Node.js | 4000 | WebSocket/SSE real-time event delivery |
| `web` | Next.js 14 | 3000 | SOC console frontend |

---

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose v2
- Node.js 20+ and pnpm 8+
- Go 1.21+ (for local development)
- Python 3.11+ (for local development)

### 1. Clone and Configure

```bash
git clone https://github.com/cyble/aisoc.git
cd aisoc
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Required for AI agents
OPENAI_API_KEY=sk-...

# Optional: threat intelligence enrichment
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...
```

### 2. Start the Stack

```bash
# Start core infrastructure + all services
docker compose up -d

# Wait for services to be ready
docker compose ps

# View logs
docker compose logs -f core-api
```

### 3. Access the Console

Open [http://localhost:3000](http://localhost:3000) in your browser.

Default credentials: `admin@aisoc.local` / `changeme`

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
│   ├── core-api/         # Python FastAPI — core REST API
│   ├── ingest/           # Go — high-throughput event ingestion
│   ├── enrichment/       # Go — IOC enrichment
│   ├── alert-fusion/     # Python — alert dedup + correlation
│   ├── agents/           # Python LangGraph — AI agents
│   ├── actions/          # Python — SOAR action execution
│   └── realtime/         # Node.js — WebSocket/SSE
├── connectors/
│   ├── crowdstrike/      # CrowdStrike Falcon connector
│   ├── splunk/           # Splunk Enterprise/Cloud connector
│   ├── aws/              # AWS Security Hub connector
│   ├── okta/             # Okta Identity connector
│   └── sentinel/         # Microsoft Sentinel connector
├── packages/
│   ├── types/            # Shared TypeScript types
│   ├── ui/               # Shared React components
│   └── ocsf/             # OCSF schema normalization
├── infra/
│   ├── terraform/        # AWS infrastructure (VPC, EKS, RDS)
│   └── helm/             # Kubernetes Helm chart
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
docker compose up -d postgres redis kafka clickhouse opensearch qdrant

# Run core API
cd services/core-api
poetry install
poetry run uvicorn app.main:app --reload --port 8000

# Run ingest worker
cd services/ingest
go run cmd/worker/main.go
```

### Running Tests

```bash
# Frontend
cd apps/web && pnpm test

# Core API
cd services/core-api && poetry run pytest

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
