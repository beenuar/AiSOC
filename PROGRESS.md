# AiSOC Build Progress

Last updated: 2026-05-01

## ✅ ALL TASKS COMPLETE — v2 Enterprise Platform shipped

| Phase | Description | Status |
|-------|-------------|--------|
| v1 — Initial monorepo | Core services, frontend, infra, docs | ✅ COMPLETED |
| v2 — Enterprise upgrade | Knowledge graph, rule engine, ML fusion, threat intel | ✅ COMPLETED |

### v1 — Initial monorepo

| ID | Task | Status |
|----|------|--------|
| setup-workspace | Initialize monorepo structure with pnpm + Turborepo | ✅ COMPLETED |
| build-ingest | Build Go ingest workers with OCSF normalization + ATT&CK mapping | ✅ COMPLETED |
| build-core-api | Build FastAPI Core API: tenants, RBAC, alerts, cases, reporting | ✅ COMPLETED |
| build-enrichment | Build Go IOC enrichment microservice with Redis cache | ✅ COMPLETED |
| build-alert-fusion | Build Alert Fusion Service (Python) for dedup + merge | ✅ COMPLETED |
| build-agents | Build LangGraph AI Agent Orchestrator with all domain agents | ✅ COMPLETED |
| build-actions | Build Action Execution Service with blast-radius gate + rollback | ✅ COMPLETED |
| build-realtime | Build Node.js/Bun real-time service (WebSocket/SSE) | ✅ COMPLETED |
| build-connectors | Build 5 Phase 1 connectors: CrowdStrike, Splunk, AWS, Okta, Sentinel | ✅ COMPLETED |
| build-packages | Build shared packages: OCSF lib, TypeScript types, React UI components | ✅ COMPLETED |
| build-frontend | Build Next.js 14 frontend: SOC console, case mgmt, attack graph, NL search | ✅ COMPLETED |
| build-infra | Build Terraform infrastructure + Helm charts + Docker configs | ✅ COMPLETED |
| build-docs | Create README, architecture docs, API docs, migration guides | ✅ COMPLETED |
| setup-github | Create GitHub repository and push initial commit | ✅ COMPLETED |
| github-push | Push complete codebase to GitHub | ✅ COMPLETED |

### v2 — Enterprise platform upgrade

| ID | Task | Status |
|----|------|--------|
| infra-fixes | Reconcile docker-compose ports/profiles for fusion, threatintel, connectors | ✅ COMPLETED |
| neo4j-graph | Add Neo4j to compose; implement `graph_service` (attack path, blast radius, neighbors, MITRE coverage) | ✅ COMPLETED |
| rule-engine | Multi-language detection rule engine: Sigma (pySigma), YARA, KQL, Lucene, Regex with `/v1/rules` API | ✅ COMPLETED |
| attck-corpus | Full MITRE ATT&CK STIX 2.1 corpus loader (Go + Python), in-process index, optional Qdrant embedding | ✅ COMPLETED |
| threatintel-svc | New `services/threatintel`: TAXII 2.1 + MISP + OTX + CISA KEV pollers, Bloom dedup, OpenSearch+Qdrant+Neo4j sinks | ✅ COMPLETED |
| ingest-shodan-cve | Shodan enrichment + CISA KEV cross-correlation in Go ingest, emits `vulnerability.matches` | ✅ COMPLETED |
| ml-fusion | Isolation Forest anomaly + LightGBM LambdaRank priority scoring with analyst feedback loop | ✅ COMPLETED |
| docs-update | Refreshed README, new SYSTEM_DESIGN.md, API_REFERENCE.md, LOCAL_DEVELOPMENT.md runbook | ✅ COMPLETED |

## GitHub Repository

**https://github.com/beenuar/AiSOC**

## Services

### Backend services

| Service | Language | Port | Notes |
|---------|----------|------|-------|
| `services/api` | Python/FastAPI | 8000 | REST + WebSocket, RBAC, cases, Neo4j graph, rule engine |
| `services/ingest` | Go 1.21 | 9090 | OCSF normalize, ATT&CK tag, Shodan + KEV correlation |
| `services/enrichment` | Go 1.21 | 8080 | IOC enrichment, Redis-cached |
| `services/fusion` | Python 3.11 | 8003 | Dedup + correlation + ML scoring (anomaly + ranker) |
| `services/agents` | Python 3.11 | 8001 | LangGraph multi-agent investigations w/ full ATT&CK + Qdrant RAG |
| `services/actions` | Python 3.11 | 8002 | SOAR action executor with blast-radius gate |
| `services/threatintel` | Python 3.11 | 8005 | TAXII / MISP / OTX / KEV poller + IOC store |
| `services/realtime` | Node.js 20 | 4000 | WebSocket/SSE fan-out |
| `apps/web` | Next.js 14 | 3000 | SOC console |

### Connectors (Phase 1)

* CrowdStrike Falcon
* Splunk Enterprise/Cloud
* AWS Security Hub
* Okta Identity
* Microsoft Sentinel

### Shared packages

* `packages/types` — TypeScript type definitions
* `packages/ui` — React UI component library
* `packages/ocsf` — OCSF schema normalization

### Data layer

| Store | Purpose |
|-------|---------|
| PostgreSQL | App config, RBAC, cases, detection rules (RLS-isolated) |
| ClickHouse | Event analytics, alert metrics |
| OpenSearch | IOC, actor, threat-report search; Sigma backend |
| Qdrant | Vector RAG for agents + threat intel |
| Neo4j | Knowledge graph: entities, attack paths, blast radius |
| Redis | Cache, pub/sub, IOC bloom filter |
| Kafka | Event streaming bus |

### Infrastructure

* `infra/terraform` — AWS (VPC, EKS, RDS, ElastiCache, MSK)
* `infra/helm/aisoc` — Kubernetes Helm chart
* `docker-compose.yml` — Full local stack

### Documentation

* `README.md` — Project overview, quick start, architecture diagram
* `docs/architecture/SYSTEM_DESIGN.md` — Service topology, knowledge graph, ML fusion, threat intel pipeline
* `docs/api/API_REFERENCE.md` — REST endpoints (graph, rules, IOC search, ML)
* `docs/runbooks/LOCAL_DEVELOPMENT.md` — Step-by-step local launch + smoke test
* `CONTRIBUTING.md` — Contribution guidelines
* `LICENSE` — MIT
* `.env.example` — Environment variable reference
