---
sidebar_position: 1
---

# Introduction

**AiSOC** (v5.1.0) is an open-source, production-ready AI Security Operations Center
built by [Cyble](https://cyble.com) and the community. It combines AI-powered
investigation, automated playbook execution, enterprise governance, and an extensible
plugin ecosystem to help security teams detect threats faster and respond smarter.

## Key Features

- ⚡ **Real-time fusion** — Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest)
- 🧠 **AI Copilot** — LangGraph multi-agent reasoning grounded in MITRE ATT&CK with persistent Qdrant RAG memory
- 🕸️ **Attack graph** — Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions
- 👤 **UEBA** — Per-user Welford online baseline, Z-score anomaly scoring, and Kafka-integrated anomaly publishing
- 🍯 **Honeytokens** — HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting
- 🟣 **Purple Team** — Atomic Red Team YAML parser + Caldera executor, ATT&CK coverage heatmap, and tabletop sessions
- 🎯 **Detection engineering** — Sigma over OpenSearch + ClickHouse, YARA, KQL/EQL, community catalog with one-click install
- 🌐 **Threat intelligence** — TAXII 2.1, MISP, OTX, CISA KEV with triple storage (search · vector · graph)
- 🛡️ **Enterprise governance** — SAML 2.0 + OIDC SSO, multi-tenant RLS, granular RBAC, immutable audit log
- 📊 **Compliance dashboards** — SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD/MTTR/MTTC SLA tracking
- 🔌 **Plugin ecosystem** — Python and TypeScript SDKs, Ed25519-signed publishing, community marketplace

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

- [Quick Start](./quickstart) — up and running in 5 minutes
- [Architecture](./architecture) — service map and data flow
- [API Reference (REST)](./api/rest) — OpenAPI 3.1 spec
- [API Reference (GraphQL)](./api/graphql) — schema and queries
- [API Reference (WebSocket)](./api/websocket) — real-time events
- [Plugin SDK (Python)](./plugins/python-sdk)
- [Plugin SDK (Go)](./plugins/go-sdk)
- [Concepts: Detections](./concepts/detections)
- [Concepts: Playbooks](./concepts/playbooks)
- [Concepts: Cases](./concepts/cases)
- [Deployment: Docker](./deployment/docker)
- [Deployment: Kubernetes](./deployment/kubernetes)
- [Deployment: Environment Variables](./deployment/env-vars)
