---
sidebar_position: 1
---

# Introduction

AiSOC (v5.2.0) is an open-source AI Security Operations Center maintained by
the AiSOC community. The agent itself is MIT-licensed, self-hostable, and
auditable: every LLM prompt, tool call, evidence citation, and decision is
recorded in a replayable Investigation Ledger, and the substrate is gated by a
public, reproducible eval harness on every PR targeting `main` / `develop`.

## Capabilities

- **Click-and-connect cloud connectors** — pick from a 14-connector catalog (Microsoft Entra, Azure Activity, Defender XDR, GCP Cloud Audit, GCP SCC, Microsoft 365 audit, Google Workspace, Cloudflare, GitHub, plus the original CrowdStrike / Splunk / AWS Security Hub / Okta / Microsoft Sentinel set), fill a schema-driven form, click `Test connection` for a live auth round-trip, and `Save & enable`. Secrets are encrypted at the application layer with a Fernet [`CredentialVault`](./operations/credentials) before they hit Postgres; an in-process APScheduler polls each enabled instance and pushes normalized OCSF events through to the ingest spine. Setup walkthroughs: [docs/connectors](./connectors).
- **Investigation Ledger** — every prompt, response, evidence citation, and tool call the agent emits is logged step-by-step and replayable on each case.
- **Public eval harness** — alert reduction (a real measurement on a fixed noisy stream) plus MITRE-tactic, investigation-completeness, and response-quality substrate self-consistency gates. Reproducible with one command and run in CI on every PR. The [eval harness page](./benchmark) documents what each suite does and does not measure.
- **Ambient Copilot** — context-aware next-action suggestions on every alert, case, rule, and playbook page; one click runs the right agent tool with the right payload.
- **Responder PWA** — installable mobile route at `/responder/*` with passkey-only login, on-call rotation, approvals queue, VAPID Web Push, and offline shell.
- **LangGraph multi-agent investigation** — orchestrator, recon, forensic, responder, and report-writer agents grounded in MITRE ATT&CK with Qdrant RAG memory.
- **Real-time fusion** — Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest).
- **Attack graph** — Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions.
- **UEBA** — per-user Welford online baseline, Z-score anomaly scoring, and Kafka-integrated anomaly publishing.
- **Honeytokens** — HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting.
- **Purple Team** — Atomic Red Team YAML parser + Caldera executor, ATT&CK coverage heatmap, tabletop sessions.
- **Detection engineering** — 800 native Sigma-shaped rules plus ~6,000 imported from SigmaHQ, Splunk Security Content, Chronicle, and MITRE CAR (each tagged with provenance), running over OpenSearch + ClickHouse, YARA, KQL / EQL, community catalog with one-click install.
- **Playbook engine** — 50+ community SOAR playbooks with explicit decision trees and human-approval gates on destructive actions.
- **Threat intelligence** — TAXII 2.1, MISP, OTX, CISA KEV with triple storage (search, vector, graph).
- **Governance** — SAML 2.0 + OIDC SSO, multi-tenant RLS, granular RBAC, immutable audit log.
- **Compliance dashboards** — SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD / MTTR / MTTC SLA tracking.
- **Marketplace** — 15 first-party plugins, 50+ playbooks, 6,900+ detections (filtered by tier: stable / beta / imported / community), surfaced in-app via [`marketplace/index.json`](https://github.com/beenuar/AiSOC/tree/main/marketplace).
- **SDKs** — Python, TypeScript, and Go SDKs for client and plugin development; Ed25519-signed publishing.
- **Model Context Protocol** — `@aisoc/mcp` exposes 11 tools to Claude, Cursor, Continue, and Cody so analysts can replay agent decisions from inside their IDE ([MCP integration](./integrations/mcp)).

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
- [Connectors](./connectors) — click-and-connect catalog with 14 cloud / SaaS / SIEM / EDR / VCS sources
- [Operations: Credentials](./operations/credentials) — `CredentialVault` threat model, key rotation, hosted-OAuth roadmap
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
