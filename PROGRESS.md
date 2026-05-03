# AiSOC Build Progress

Last updated: 2026-05-03

## ✅ ALL TASKS COMPLETE — v4.1 + v5.0 + v5.1 shipped

> v4.1 "Community Ecosystem", v5.0 "Enterprise Ready", and v5.1 "Detection Depth" are
> all implemented. See ROADMAP.md for per-item status. Use `pnpm aisoc:lab` to spin
> up the full demo stack.

| Phase | Description | Status |
|-------|-------------|--------|
| v1 — Initial monorepo | Core services, frontend, infra, docs | ✅ COMPLETED |
| v2 — Enterprise upgrade | Knowledge graph, rule engine, ML fusion, threat intel | ✅ COMPLETED |
| v4.0 — Autonomous SOC | Multi-agent investigator, Visual SOAR Studio, Plugin Platform, OpenTelemetry | ✅ COMPLETED |
| v4.1 — Community Ecosystem | Plugin publishing, marketplace v2, detection catalog, playbook submissions, aisoc-cli | ✅ COMPLETED |
| v5.0 — Enterprise Ready | SAML/OIDC, multi-tenant RLS, RBAC, audit log, compliance dashboards, SLA, HA Helm, backup, runbooks | ✅ COMPLETED |
| v5.1 — Detection Depth | UEBA service, honeytokens service, purple-team service (ART + Caldera + ATT&CK heatmap + tabletop) | ✅ COMPLETED |

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

### v4 — Autonomous SOC

| ID | Task | Status |
|----|------|--------|
| investigator | LangGraph multi-agent orchestrator (Recon, Forensic, Responder, ReportWriter) | ✅ COMPLETED |
| case-workspace | Case Workspace UI — Investigation & Report tabs with streaming progress | ✅ COMPLETED |
| eval-harness | Eval harness: 20 synthetic incidents, ≥80% MITRE-tactic accuracy CI gate | ✅ COMPLETED |
| soar-studio | React Flow visual playbook editor + DAG engine (retries, conditions, on_failure) | ✅ COMPLETED |
| playbook-schema | `playbook.schema.json` JSON Schema 2020-12 for portability and CI linting | ✅ COMPLETED |
| detection-as-code | `detections/` directory with Sigma + AiSOC YAML; GitHub Action deploy-on-merge | ✅ COMPLETED |
| playbook-templates | 12 starter playbook templates | ✅ COMPLETED |
| marketplace | Community playbook + plugin marketplace static index | ✅ COMPLETED |
| plugin-sdk | Plugin SDK in Python (`packages/plugin-sdk-py/`) and Go (`packages/plugin-sdk-go/`) | ✅ COMPLETED |
| plugin-yaml | `plugin.yaml` manifest spec (connector \| enricher \| responder \| detection \| widget) | ✅ COMPLETED |
| plugin-oci | Plugin loader with OCI image support (`oras pull`) | ✅ COMPLETED |
| ref-plugins | 4 reference plugins: Okta connector, YARA enricher, Slack quarantine, MTTR widget | ✅ COMPLETED |
| openapi | Public REST API v1, OpenAPI 3.1 at `docs/openapi.yaml` | ✅ COMPLETED |
| graphql | GraphQL gateway (Strawberry) at `/graphql` | ✅ COMPLETED |
| api-tokens | Scoped API tokens (`/api/v1/api-keys`) | ✅ COMPLETED |
| client-sdks | Auto-generated TypeScript, Python, Go client SDKs | ✅ COMPLETED |
| docs-site | Docusaurus docs site at `apps/docs/`, deployed to GitHub Pages | ✅ COMPLETED |
| otel | OpenTelemetry traces across agents → api → realtime (OTLP/Jaeger) | ✅ COMPLETED |
| demo-lab | `pnpm aisoc:lab` one-command full-stack demo + Conti ransomware scenario | ✅ COMPLETED |
| migration | MIGRATION.md for v3 → v4 upgrade path | ✅ COMPLETED |

### v4.1 — Community Ecosystem

| ID | Task | Status |
|----|------|--------|
| cli | `aisoc-cli` scaffold/validate/publish commands for plugins and detections | ✅ COMPLETED |
| plugin-publish | Plugin publish flow: `community_plugins` table, POST `/api/v1/plugins/publish`, Ed25519 signature verification | ✅ COMPLETED |
| marketplace-v2 | MarketplaceView.tsx with ratings, install counts, verified badges, category filter, sort | ✅ COMPLETED |
| detection-catalog | Detection catalog: paginated Sigma browse API + UI page with install action | ✅ COMPLETED |
| playbook-community | Playbook community submissions: `community_playbooks` table + submit/curate API + Community tab | ✅ COMPLETED |

### v5.0 — Enterprise Ready

| ID | Task | Status |
|----|------|--------|
| saml-oidc | SAML 2.0 + OIDC auth in `services/api/app/auth/` with JWT issuance | ✅ COMPLETED |
| rls | Multi-tenant RLS: `tenant_id` migration, Postgres RLS policies, SQLAlchemy middleware | ✅ COMPLETED |
| rbac | Granular RBAC: roles/permissions/user_roles tables + `require_permission()` + admin UI | ✅ COMPLETED |
| audit-log | Immutable audit log: append-only `audit_log` table + FastAPI middleware + UI | ✅ COMPLETED |
| soc2 | SOC 2 evidence dashboard: auto-collect evidence API + compliance page + PDF export | ✅ COMPLETED |
| frameworks | ISO 27001 + NIST CSF + PCI-DSS/HIPAA/DORA: mapping YAMLs + `/api/v1/compliance/{framework}` + heatmap UI | ✅ COMPLETED |
| sla | MTTD/MTTR/MTTC SLA tracking: `tenant_sla_config` table + metrics API + dashboard widget | ✅ COMPLETED |
| helm-ha | Helm chart HPA, PDB, Ingress, per-service deployment templates | ✅ COMPLETED |
| backup-cli | `scripts/backup.sh` and `scripts/restore.sh` for Postgres + ClickHouse + plugins | ✅ COMPLETED |
| ops-docs | `docs/operations/multi-region.md` + `scripts/generate_runbook.py` from OTel traces | ✅ COMPLETED |

### v5.1 — Detection Depth

| ID | Task | Status |
|----|------|--------|
| ueba | `services/ueba/` — baseline computation (Welford), anomaly scoring (z-score), peer-group analysis, Kafka integration | ✅ COMPLETED |
| honeytokens | `services/honeytokens/` — token generator, HMAC-signed webhook alerting, lifecycle management UI | ✅ COMPLETED |
| purple-team | `services/purple-team/` — Atomic Red Team loader, Caldera client, ATT&CK coverage heatmap, tabletop simulator UI | ✅ COMPLETED |

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
| `services/ueba` | Python 3.11 | 8004 | Behavioral baseline, anomaly scoring, peer-group analysis, Kafka |
| `services/honeytokens` | Python 3.11 | 8005 | Token generation, first-touch alerting, lifecycle management |
| `services/purple-team` | Python 3.11 | 8006 | Atomic Red Team, Caldera integration, ATT&CK coverage, tabletop |
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
