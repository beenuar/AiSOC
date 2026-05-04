# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`/detection` route 500 error** — moved `SAMPLE_SIGMA` / `SAMPLE_KQL` / `SAMPLE_EQL` constant declarations above their use in `DEMO_RULES` to resolve a Temporal Dead Zone reference error in `apps/web/src/components/detections/DetectionsView.tsx` (`0ef4a65`).
- **TopBar title mismatch on most routes** — expanded the `routeLabels` map in `apps/web/src/components/layout/TopBar.tsx` to cover all 19 sidebar destinations and added a URL-segment fallback so non-mapped routes no longer render `Alerts` (`4ca84bb`).
- **Sidebar footer showed `v0.1.0`** — bumped `apps/web/package.json` to `5.1.0` and read the version dynamically in `apps/web/src/components/layout/Sidebar.tsx` so the footer always tracks the package version (`f4d9189`).
- **Docs homepage underselling v5.1.0** — refreshed the Docusaurus tagline in `apps/docs/docusaurus.config.ts` and expanded the feature list in `apps/docs/src/pages/index.tsx` to cover UEBA, Honeytokens, Purple Team, and the v5.0 governance surface (`2e1873d`).

---

## [5.1.0] — 2026-05-03

### Added — v5.1 "Detection Depth"

- **UEBA service** (`services/ueba`) — User & Entity Behavior Analytics
  - Welford online algorithm for incremental baseline computation
  - Z-score anomaly scoring with configurable sensitivity
  - Peer-group analysis (same role / department / location clustering)
  - Kafka consumer (`security.events`) → producer (`security.anomalies`) integration with `fusion` service
  - Alembic migrations, Dockerfile, Helm deployment template
- **Honeytokens service** (`services/honeytokens`) — deceptive credential & file traps
  - HMAC-SHA256 signed token generator (URL, file, AWS key, email flavors)
  - Webhook handler for first-touch alerting (HTTP signed callbacks)
  - Token lifecycle management: active / triggered / expired states
  - React UI: create tokens, view trigger log, copy lure URLs
  - Alembic migrations, Dockerfile, Helm deployment template
- **Purple Team service** (`services/purple-team`) — adversary emulation & tabletop
  - Atomic Red Team YAML parser (any `atomics/` directory)
  - Caldera REST integration for remote execution
  - ATT&CK coverage heatmap (tactic × technique matrix)
  - Test execution tracking with detection reporting (true positive / false negative)
  - Tabletop exercise session manager with finding capture
  - React UI: Coverage tab, Executions tab, Tabletop tab
  - Alembic migrations, Dockerfile, Helm deployment template

---

## [5.0.0] — 2026-05-03

### Added — v5.0 "Enterprise Ready"

- **SAML 2.0 + OIDC authentication** (`services/api/app/auth/`)
  - IdP-initiated and SP-initiated SAML 2.0 flows (python3-saml)
  - OIDC authorization-code + PKCE flow with `authlib`
  - JWT issuance on successful SSO login
- **Multi-tenant Row-Level Security** (Postgres RLS)
  - `tenant_id` column on all data tables
  - RLS policies enforced at the database level
  - SQLAlchemy `set_tenant()` middleware in FastAPI deps
- **Granular RBAC** (`services/api/app/api/v1/endpoints/rbac.py`)
  - `roles`, `role_permissions`, `user_roles` tables
  - `require_permission("resource:action")` FastAPI dependency
  - Admin UI at `/settings/rbac`
- **Immutable Audit Log**
  - Append-only `audit_log` table with a before-UPDATE trigger
  - FastAPI middleware auto-logs every mutating request
  - `GET /api/v1/audit` paginated endpoint with tenant filter
  - Audit log viewer UI at `/audit`
- **Compliance dashboards**
  - SOC 2 evidence auto-collection + PDF export (`/compliance/soc2`)
  - ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA framework heatmaps
  - `GET /api/v1/compliance/{framework}` endpoint with control mapping
- **SLA tracking** — MTTD / MTTR / MTTC
  - `tenant_sla_config` + `alert_sla_events` tables
  - `GET /api/v1/sla/metrics` + `GET /api/v1/sla/breaches`
  - SLA dashboard widget at `/sla`
- **HA Helm chart** — HPA, PDB, Ingress per service
- **Backup & restore scripts** (`scripts/backup.sh`, `scripts/restore.sh`) for Postgres + ClickHouse + plugins → S3/R2
- **Operational runbook generator** (`scripts/generate_runbook.py`) from live OTel trace data
- **Multi-region deployment guide** (`docs/operations/multi-region.md`)
- **OpenTelemetry instrumentation** across API, UEBA, Honeytokens, and Purple Team services

---

## [4.1.0] — 2026-05-03

### Added — v4.1 "Community Ecosystem"

- **AiSOC CLI** (`packages/aisoc-cli`) — `scaffold`, `validate`, `publish` commands for plugins and detections
  - `aisoc scaffold plugin <name>` — generate plugin skeleton
  - `aisoc validate detection <file>` — Sigma/YAML schema validation
  - `aisoc publish plugin <path>` — submit to community registry with Ed25519 signing
- **Plugin publishing flow**
  - `community_plugins` table with signature, author, review state
  - `POST /api/v1/plugins/publish` — signed submission
  - `POST /api/v1/plugins/{id}/approve` / `reject` — curator review endpoints
  - Ed25519 signature verification on every submission
- **Marketplace v2** — ratings, install counts, verified badges, category filter, sort options
  - `plugin_ratings` table + `POST /api/v1/plugins/{id}/rate`
  - `GET /api/v1/marketplace?category=&sort=` with pagination
- **Detection catalog** (`/detection/catalog`) — paginated Sigma rule browser
  - Install-to-tenant action from catalog
  - `GET /api/v1/detections/catalog` endpoint
- **Playbook community submissions**
  - `community_playbooks` table + submit / curate API
  - Community tab in PlaybooksView UI
- **Docusaurus documentation site** (`apps/docs`) — full API, architecture, deployment, plugin SDK, quickstart

---

## [3.0.0] — 2026-05-02

### Added
- **Threat Intelligence Enrichment (13 providers)**
  - Open-source/freemium: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan.io, IPinfo
  - Commercial: Cyble Vision, Recorded Future, Mandiant, Crowdstrike Intel, Anomali, IBM X-Force, Flashpoint, Intel 471, DomainTools, RiskIQ
  - New enrichment types: `DarkWebContext`, `VulnerabilityRef`, `BrandRisk`
  - Concurrent fan-out enrichment engine in Go
- **Go module path migration** — all services updated from `github.com/cyble/aisoc` to `github.com/beenuar/aisoc`
- **SECURITY.md** — vulnerability disclosure policy and security contacts
- `services/enrichment/README.md` — full enrichment service documentation

### Changed
- All GitHub repository references updated to `https://github.com/beenuar/AiSOC`
- Helm chart container images updated from `ghcr.io/cyble/aisoc-*` to `ghcr.io/beenuar/aisoc-*`
- `.env.example` expanded with API keys for all commercial TI providers

---

## [2.0.0] — 2026-05-01

### Added
- **Knowledge Graph** — Neo4j-backed entity relationship visualization (`services/api/app/services/graph_service.py`)
- **ML Fusion Engine** — multi-model alert scoring and deduplication (`services/fusion/app/services/`)
- **Rule Engine** — YAML-based detection rules with MITRE ATT&CK mapping (`services/api/app/services/rule_engine.py`)
- **Attack Graph** viz with D3.js force layout (`apps/web/src/components/graph/`)
- **MITRE ATT&CK Heatmap** on dashboard
- **AI Copilot dock** — streaming LLM assistant integrated into case and alert views
- **Threat Hunt page** — query builder with saved hunts and timeline scrubbing
- **Case Workspace** — full case lifecycle: evidence, timeline, collaborators, MITRE tagging
- **Detection Rule Builder** — visual rule editor with backtesting
- **Settings page** — RBAC, notifications, API key management, threat intel feed config
- **Live Dashboard** — WebSocket-powered real-time alert/event feed
- **Command Palette** (cmd-K) — fuzzy search for navigation and actions
- **Marketing Landing Page** — hero, feature highlights, open-source section, footer
- **Design Token System** — Tailwind + CSS vars, Framer Motion animations, responsive layouts
- **Demo Producer** — synthetic event generator for local development
- `scripts/seed_demo.py` — database seeding for demos

### Changed
- Web app migrated to Next.js App Router
- All API routes versioned under `/api/v1`

---

## [1.0.0] — 2026-04-30

### Added
- Initial release of AiSOC — AI Security Operations Center
- FastAPI backend (`services/api`) with alert ingestion, case management, detection rules
- Next.js 14 frontend (`apps/web`) with dashboard, alerts, cases, connectors, threat-intel pages
- Real-time service (`services/realtime`) using WebSockets
- Ingest service (`services/ingest`) in Go for high-throughput event ingestion
- Enrichment service (`services/enrichment`) in Go
- Docker Compose stack for local development
- Helm chart for Kubernetes deployment (`infra/helm/aisoc/`)
- MIT License

[Unreleased]: https://github.com/beenuar/AiSOC/compare/v5.1.0...HEAD
[5.1.0]: https://github.com/beenuar/AiSOC/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/beenuar/AiSOC/compare/v4.1.0...v5.0.0
[4.1.0]: https://github.com/beenuar/AiSOC/compare/v3.0.0...v4.1.0
[3.0.0]: https://github.com/beenuar/AiSOC/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/beenuar/AiSOC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/beenuar/AiSOC/releases/tag/v1.0.0
