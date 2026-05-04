# AiSOC Build Progress

Last updated: 2026-05-04

## Status: v4.1, v5.0, v5.1, and v5.2 shipped

v4.1, v5.0, v5.1, and v5.2 are all implemented. See ROADMAP.md and
CHANGELOG.md for per-item status. Use `pnpm aisoc:demo` for the demo stack,
or `pnpm aisoc:lab` for the full lab stack.

| Phase | Description | Status |
|-------|-------------|--------|
| v1 — Initial monorepo | Core services, frontend, infra, docs | Completed |
| v2 — Enterprise upgrade | Knowledge graph, rule engine, ML fusion, threat intel | Completed |
| v4.0 | Multi-agent investigator, visual SOAR studio, plugin platform, OpenTelemetry | Completed |
| v4.1 | Plugin publishing, marketplace v2, detection catalog, playbook submissions, aisoc-cli | Completed |
| v5.0 | SAML/OIDC, multi-tenant RLS, RBAC, audit log, compliance dashboards, SLA, HA Helm, backup, runbooks | Completed |
| v5.1 | UEBA service, honeytokens service, purple-team service (ART + Caldera + ATT&CK heatmap + tabletop) | Completed |
| v5.2 | Investigation Ledger, 200-incident public eval harness, Responder PWA + passkeys, Ambient Copilot, MCP server, demo stack | Completed |

### v1 — Initial monorepo

| ID | Task | Status |
|----|------|--------|
| setup-workspace | Initialize monorepo structure with pnpm + Turborepo | Completed |
| build-ingest | Build Go ingest workers with OCSF normalization + ATT&CK mapping | Completed |
| build-core-api | Build FastAPI Core API: tenants, RBAC, alerts, cases, reporting | Completed |
| build-enrichment | Build Go IOC enrichment microservice with Redis cache | Completed |
| build-alert-fusion | Build Alert Fusion Service (Python) for dedup + merge | Completed |
| build-agents | Build LangGraph AI Agent Orchestrator with all domain agents | Completed |
| build-actions | Build Action Execution Service with blast-radius gate + rollback | Completed |
| build-realtime | Build Node.js/Bun real-time service (WebSocket/SSE) | Completed |
| build-connectors | Build 5 Phase 1 connectors: CrowdStrike, Splunk, AWS, Okta, Sentinel | Completed |
| build-packages | Build shared packages: OCSF lib, TypeScript types, React UI components | Completed |
| build-frontend | Build Next.js 14 frontend: SOC console, case mgmt, attack graph, NL search | Completed |
| build-infra | Build Terraform infrastructure + Helm charts + Docker configs | Completed |
| build-docs | Create README, architecture docs, API docs, migration guides | Completed |
| setup-github | Create GitHub repository and push initial commit | Completed |
| github-push | Push complete codebase to GitHub | Completed |

### v2 — Enterprise platform upgrade

| ID | Task | Status |
|----|------|--------|
| infra-fixes | Reconcile docker-compose ports/profiles for fusion, threatintel, connectors | Completed |
| neo4j-graph | Add Neo4j to compose; implement `graph_service` (attack path, blast radius, neighbors, MITRE coverage) | Completed |
| rule-engine | Multi-language detection rule engine: Sigma (pySigma), YARA, KQL, Lucene, Regex with `/v1/rules` API | Completed |
| attck-corpus | Full MITRE ATT&CK STIX 2.1 corpus loader (Go + Python), in-process index, optional Qdrant embedding | Completed |
| threatintel-svc | New `services/threatintel`: TAXII 2.1 + MISP + OTX + CISA KEV pollers, Bloom dedup, OpenSearch+Qdrant+Neo4j sinks | Completed |
| ingest-shodan-cve | Shodan enrichment + CISA KEV cross-correlation in Go ingest, emits `vulnerability.matches` | Completed |
| ml-fusion | Isolation Forest anomaly + LightGBM LambdaRank priority scoring with analyst feedback loop | Completed |
| docs-update | Refreshed README, new SYSTEM_DESIGN.md, API_REFERENCE.md, LOCAL_DEVELOPMENT.md runbook | Completed |

### v4

| ID | Task | Status |
|----|------|--------|
| investigator | LangGraph multi-agent orchestrator (Recon, Forensic, Responder, ReportWriter) | Completed |
| case-workspace | Case Workspace UI — Investigation & Report tabs with streaming progress | Completed |
| eval-harness | Eval harness: 20 synthetic incidents, ≥80% MITRE-tactic accuracy CI gate | Completed |
| soar-studio | React Flow visual playbook editor + DAG engine (retries, conditions, on_failure) | Completed |
| playbook-schema | `playbook.schema.json` JSON Schema 2020-12 for portability and CI linting | Completed |
| detection-as-code | `detections/` directory with Sigma + AiSOC YAML; GitHub Action deploy-on-merge | Completed |
| playbook-templates | 12 starter playbook templates | Completed |
| marketplace | Community playbook + plugin marketplace static index | Completed |
| plugin-sdk | Plugin SDK in Python (`packages/plugin-sdk-py/`) and Go (`packages/plugin-sdk-go/`) | Completed |
| plugin-yaml | `plugin.yaml` manifest spec (connector \| enricher \| responder \| detection \| widget) | Completed |
| plugin-oci | Plugin loader with OCI image support (`oras pull`) | Completed |
| ref-plugins | 4 reference plugins: Okta connector, YARA enricher, Slack quarantine, MTTR widget | Completed |
| openapi | Public REST API v1, OpenAPI 3.1 at `docs/openapi.yaml` | Completed |
| graphql | GraphQL gateway (Strawberry) at `/graphql` | Completed |
| api-tokens | Scoped API tokens (`/api/v1/api-keys`) | Completed |
| client-sdks | Auto-generated TypeScript, Python, Go client SDKs | Completed |
| docs-site | Docusaurus docs site at `apps/docs/`, deployed to GitHub Pages | Completed |
| otel | OpenTelemetry traces across agents → api → realtime (OTLP/Jaeger) | Completed |
| demo-lab | `pnpm aisoc:lab` one-command full-stack demo + Conti ransomware scenario | Completed |
| migration | MIGRATION.md for v3 → v4 upgrade path | Completed |

### v4.1

| ID | Task | Status |
|----|------|--------|
| cli | `aisoc-cli` scaffold/validate/publish commands for plugins and detections | Completed |
| plugin-publish | Plugin publish flow: `community_plugins` table, POST `/api/v1/plugins/publish`, Ed25519 signature verification | Completed |
| marketplace-v2 | MarketplaceView.tsx with ratings, install counts, verified badges, category filter, sort | Completed |
| detection-catalog | Detection catalog: paginated Sigma browse API + UI page with install action | Completed |
| playbook-community | Playbook community submissions: `community_playbooks` table + submit/curate API + Community tab | Completed |

### v5.0

| ID | Task | Status |
|----|------|--------|
| saml-oidc | SAML 2.0 + OIDC auth in `services/api/app/auth/` with JWT issuance | Completed |
| rls | Multi-tenant RLS: `tenant_id` migration, Postgres RLS policies, SQLAlchemy middleware | Completed |
| rbac | Granular RBAC: roles/permissions/user_roles tables + `require_permission()` + admin UI | Completed |
| audit-log | Immutable audit log: append-only `audit_log` table + FastAPI middleware + UI | Completed |
| soc2 | SOC 2 evidence dashboard: auto-collect evidence API + compliance page + PDF export | Completed |
| frameworks | ISO 27001 + NIST CSF + PCI-DSS/HIPAA/DORA: mapping YAMLs + `/api/v1/compliance/{framework}` + heatmap UI | Completed |
| sla | MTTD/MTTR/MTTC SLA tracking: `tenant_sla_config` table + metrics API + dashboard widget | Completed |
| helm-ha | Helm chart HPA, PDB, Ingress, per-service deployment templates | Completed |
| backup-cli | `scripts/backup.sh` and `scripts/restore.sh` for Postgres + ClickHouse + plugins | Completed |
| ops-docs | `docs/operations/multi-region.md` + `scripts/generate_runbook.py` from OTel traces | Completed |

### v5.1

| ID | Task | Status |
|----|------|--------|
| ueba | `services/ueba/` — baseline computation (Welford), anomaly scoring (z-score), peer-group analysis, Kafka integration | Completed |
| honeytokens | `services/honeytokens/` — token generator, HMAC-signed webhook alerting, lifecycle management UI | Completed |
| purple-team | `services/purple-team/` — Atomic Red Team loader, Caldera client, ATT&CK coverage heatmap, tabletop simulator UI | Completed |

### v5.2

| ID | Task | Status |
|----|------|--------|
| investigation-ledger | Append-only ledger of every prompt, tool call, evidence shard, and rationale (`investigation_step` table + `services/agents/app/investigator/ledger.py` + UI) | Completed |
| ledger-api | `GET /api/v1/investigations/*` for listing, retrieving, and replaying ledger entries by case | Completed |
| eval-harness-v2 | 200-incident synthetic dataset covering all 14 MITRE tactics + 4 eval gates: alert reduction (real measurement) plus MITRE-tactic / completeness / response-quality substrate self-consistency gates | Completed |
| benchmark-page | Public eval harness page at `/benchmark` (docs + web) with published numbers, full method, comparison to other AI SOC offerings, and explicit "what each suite measures" framing | Completed |
| ci-eval-gates | `scripts/run_evals.py --ci` wired into `.github/workflows/ci.yml` so every commit is gated on substrate self-consistency + alert-reduction thresholds | Completed |
| responder-pwa | Installable PWA (`apps/web/src/app/(responder)/`) with service worker, offline shell, manifest, icons | Completed |
| passkeys | WebAuthn passkey registration + login for Responder surface (FIDO2 platform authenticators only) | Completed |
| oncall | On-call schedule + handoff (`oncall.py` + Responder home page + alert page badge) | Completed |
| approvals | Long-lived approval requests for blast-radius-gated SOAR actions, approvable from PWA with passkey | Completed |
| web-push | VAPID-signed Web Push notifications wired into `services/realtime` + per-device subscriptions following on-call rotation | Completed |
| ambient-copilot | Contextual actions on alert / case / rule / playbook surfaces, grounded in the Investigation Ledger | Completed |
| mcp-server | `services/mcp/` — Model Context Protocol server exposing 11 AiSOC tools to Claude Desktop, Cursor, Cody, Continue | Completed |
| streamlined-demo | `pnpm aisoc:demo` + `docker-compose.demo.yml` + prebuilt GHCR images for the demo profile | Completed |
| content-pack | First-party content: 10 detections, 12 playbooks, 15 plugins indexed into `marketplace/index.json` | Completed |

## GitHub repository

https://github.com/beenuar/AiSOC

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
| `services/realtime` | Node.js 20 | 4000 | WebSocket/SSE fan-out + VAPID Web Push |
| `services/mcp` | Node.js 20 | stdio | Model Context Protocol server, 11 AiSOC tools for Claude / Cursor / Cody / Continue |
| `apps/web` | Next.js 14 | 3000 | SOC console + Responder PWA + `/benchmark` page |

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
* `docker-compose.yml` — Full local lab stack (`pnpm aisoc:lab`)
* `docker-compose.demo.yml` — Streamlined demo stack with prebuilt GHCR images (`pnpm aisoc:demo`)
* `.github/workflows/release.yml` + `publish-images.yml` — Build and publish per-service images to `ghcr.io/beenuar/aisoc-*`

### Documentation

* `README.md` — Project overview, quick start, architecture diagram
* `CHANGELOG.md` — Per-release feature log; v5.2.0 covers Phase 1–4C
* `ROADMAP.md` — Per-item phase status across v1 → v5.2
* `MIGRATION.md` — Upgrade guide between major versions
* `SECURITY.md` — Vulnerability disclosure policy
* `apps/docs/` — Docusaurus site (intro, quickstart, architecture, concepts, plugins, deployment, contributing, benchmark, integrations/mcp)
* `docs/openapi.yaml` — Generated OpenAPI 3.0 spec, source of truth for client SDKs
* `docs/architecture/SYSTEM_DESIGN.md` — Service topology, knowledge graph, ML fusion, threat intel pipeline
* `docs/runbooks/LOCAL_DEVELOPMENT.md` — Step-by-step local launch + smoke test
* `CONTRIBUTING.md` — Contribution guidelines incl. eval harness + content authoring
* `LICENSE` — MIT
* `.env.example` — Environment variable reference
