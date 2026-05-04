---
sidebar_position: 1
---

# Introduction

**AiSOC** (v5.2.0) is an open-source, production-ready AI Security Operations Center
maintained by the AiSOC community. It is the **only AI SOC where the agent itself is
open-source, auditable, and self-hostable** — every LLM prompt, tool call, and
decision the agent makes is recorded in a replayable Investigation Ledger, and the
substrate is gated by a public, reproducible eval harness on every commit.

## Key Features

- 📒 **Investigation Ledger** — every prompt, response, evidence citation, and tool call the agent emits is logged step-by-step and replayable on each case (the structural moat over closed-source AI SOC vendors)
- 📊 **Public eval harness** — alert reduction (a real measurement on a fixed noisy stream) plus MITRE-tactic, investigation-completeness, and response-quality substrate self-consistency gates are reproducible with one command and run in CI on every PR. We are upfront about which is which ([eval harness page](./benchmark)).
- 🤖 **Ambient Copilot** — context-aware next-action suggestions on every alert, case, rule, and playbook page; one click runs the right agent tool with the right payload
- 📱 **Responder PWA** — installable mobile route at `/responder/*` with passkey-only login, on-call rotation, approvals queue, VAPID Web Push, and offline shell
- 🧠 **LangGraph multi-agent investigation** — orchestrator + recon + forensic + responder + report-writer agents, grounded in MITRE ATT&CK with persistent Qdrant RAG memory
- ⚡ **Real-time fusion** — Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest)
- 🕸️ **Attack graph** — Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions
- 👤 **UEBA** — Per-user Welford online baseline, Z-score anomaly scoring, and Kafka-integrated anomaly publishing
- 🍯 **Honeytokens** — HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting
- 🟣 **Purple Team** — Atomic Red Team YAML parser + Caldera executor, ATT&CK coverage heatmap, and tabletop sessions
- 🎯 **Detection engineering** — 200+ Sigma rules over OpenSearch + ClickHouse, YARA, KQL/EQL, community catalog with one-click install
- 📜 **Playbook engine** — 50+ community SOAR playbooks with explicit decision trees and human-approval gates on destructive actions
- 🌐 **Threat intelligence** — TAXII 2.1, MISP, OTX, CISA KEV with triple storage (search · vector · graph)
- 🛡️ **Enterprise governance** — SAML 2.0 + OIDC SSO, multi-tenant RLS, granular RBAC, immutable audit log
- 📊 **Compliance dashboards** — SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD/MTTR/MTTC SLA tracking
- 🧩 **Marketplace** — 15 first-party plugins + 50+ playbooks + 200+ detections, surfaced in-app via [`marketplace/index.json`](https://github.com/beenuar/AiSOC/tree/main/marketplace)
- 🔌 **SDKs** — Python, TypeScript, and Go SDKs for both client and plugin development; Ed25519-signed publishing
- 🤝 **Model Context Protocol (MCP)** — `@aisoc/mcp` exposes 11 tools to Claude / Cursor / Continue / Cody so analysts can replay agent decisions from inside their IDE ([MCP integration](./integrations/mcp))

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

- [Quick Start](./quickstart) — `pnpm aisoc:demo`, under 5 minutes to a live investigation
- [Public eval harness](./benchmark) — alert reduction (real measurement) plus MITRE / completeness / response-quality substrate self-consistency gates
- [MCP Integration](./integrations/mcp) — connect Claude / Cursor / Continue / Cody
- [Architecture](./architecture) — service map and data flow
- [API Reference (REST)](./api/rest) — OpenAPI 3.1 spec
- [API Reference (GraphQL)](./api/graphql) — schema and queries
- [API Reference (WebSocket)](./api/websocket) — real-time events
- [Plugin SDK (Python)](./plugins/python-sdk)
- [Plugin SDK (Go)](./plugins/go-sdk)
- [Concepts: Detections](./concepts/detections)
- [Concepts: Playbooks](./concepts/playbooks)
- [Concepts: Cases](./concepts/cases) — including the Investigation Ledger
- [Deployment: Docker](./deployment/docker)
- [Deployment: Kubernetes](./deployment/kubernetes)
- [Deployment: Environment Variables](./deployment/env-vars)
