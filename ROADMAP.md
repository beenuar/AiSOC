# AiSOC Roadmap

This document captures the planned direction for AiSOC across major versions. All v4 deliverables and items deferred beyond v4 are listed here.

## v4.0 — Shipped

### AI multi-agent investigator
- [x] Orchestrator (LangGraph state machine) in `services/agents/app/investigator/`
- [x] ReconAgent, ForensicAgent, ResponderAgent (dry-run with analyst approval)
- [x] ReportWriterAgent — streaming markdown + branded PDF
- [x] Investigation & Report tabs in Case Workspace UI
- [x] Eval harness: 20 synthetic incidents, ≥80% MITRE-tactic accuracy CI gate

### Visual SOAR studio
- [x] React Flow playbook editor with full node palette (Trigger, Condition, Action, Loop, Parallel, Human Approval, Wait, Notify)
- [x] DAG playbook engine with retries, idempotency, blast-radius checks
- [x] `playbook.schema.json` (JSON Schema 2020-12) for portability and CI linting
- [x] Detection-as-Code: `detections/` directory with Sigma + AiSOC YAML, GitHub Action deploy-on-merge
- [x] 12 starter playbook templates
- [x] Community playbook marketplace (static index v4.0; publishing flow v4.1)

### Plugin platform, public API, SDKs, docs
- [x] Plugin SDK in Python (`packages/plugin-sdk-py/`) and Go (`packages/plugin-sdk-go/`)
- [x] `plugin.yaml` manifest spec (connector | enricher | responder | detection | widget)
- [x] Plugin loader with OCI image support (`oras pull`) in api/actions/enrichment/connectors
- [x] Public REST API v1 at `/api/v1`, OpenAPI 3.1 at `docs/openapi.yaml`
- [x] GraphQL gateway (Strawberry) proxying REST
- [x] Scoped API tokens (`cases:read`, `playbooks:run`, `plugins:install`)
- [x] Auto-generated client SDKs: `@aisoc/sdk` (TypeScript), `aisoc-sdk` (Python/PyPI), `github.com/beenuar/aisoc/sdk-go`
- [x] Docusaurus docs site at `docs/site/`, deployed to GitHub Pages
- [x] Demo Lab: `pnpm aisoc:lab` one-command full-stack + Conti-style ransomware scenario
- [x] 4 reference plugins: Okta connector, YARA enricher, Slack quarantine responder, MTTR sparkline widget

### Cross-cutting
- [x] OpenTelemetry traces: agents → actions → api → realtime (Jaeger/Tempo)
- [x] API token scopes (foundation for SSO)
- [x] MIGRATION.md for v3 → v4 upgrade path

---

## v4.1 — Shipped

- [x] Plugin publishing flow (signed community submissions, Ed25519 verification, review endpoints)
- [x] Plugin marketplace UI v2 (ratings, install counts, verified badges, category filter, sort)
- [x] Detection catalog: browse and install community Sigma rules via UI
- [x] Playbook community submissions and curation
- [x] `aisoc-cli` — developer CLI for scaffold, validate, publish plugins and detections

---

## v5.0 — Shipped

### Identity & Access
- [x] SAML 2.0 + OIDC authentication (Okta, Azure AD, Google Workspace)
- [x] Multi-tenant row-level security (Postgres RLS + SQLAlchemy middleware)
- [x] Granular RBAC with data-class and tenant scopes (`require_permission()` dependency)
- [x] Full analyst audit log (append-only `audit_log` table + middleware + UI)

### Compliance
- [x] SOC 2 Type II evidence collection dashboard + PDF export
- [x] ISO 27001 control mapping
- [x] NIST CSF / NIST 800-53 control coverage heatmap
- [x] PCI-DSS, HIPAA, DORA module
- [x] MTTD / MTTR / MTTC SLA tracking per tenant

### High Availability & Operations
- [x] HA Helm chart with PodDisruptionBudgets and HorizontalPodAutoscalers
- [x] Backup / restore CLI (`scripts/backup.sh`, `scripts/restore.sh`)
- [x] Multi-region active-active topology guide (`docs/operations/multi-region.md`)
- [x] Operator runbook generation from OTel traces (`scripts/generate_runbook.py`)

---

## v5.1 — Shipped

### UEBA
- [x] Per-user, per-host, per-service behavioral baselines (Welford's algorithm)
- [x] Anomaly risk scores feeding the fusion engine (z-score composite scoring)
- [x] Peer-group analysis and deviation scoring
- [x] Kafka integration: consumes `security.events`, publishes `ueba.anomalies`

### Deception / Honeytokens
- [x] Token generation (AWS keys, URLs, DNS, file, DB credentials, custom types)
- [x] First-touch alerting via HMAC-SHA256-signed webhooks
- [x] Honeytoken lifecycle management UI (create, revoke, delete, trigger history)

### Purple-Team / Continuous Validation
- [x] Atomic Red Team YAML loader and test sync API
- [x] Caldera adversary emulation REST client integration
- [x] ATT&CK coverage heatmap by tactic/technique with detection tracking
- [x] Tabletop incident simulator with findings management UI

---

## v6.0 — Shipped (2026-05-06)

### Wave 3 — Operational Maturity

- [x] MSSP / parent-tenant console — onboard child tenants, delegate cross-tenant actions, view rollup metrics
- [x] Asset inventory + vuln-to-alert correlation — asset CRUD, vulnerability findings, blast-radius context
- [x] Insider threat module — user risk profiles, behavioural indicators, peer-group deviation scoring
- [x] L0–L4 auto-remediation maturity tiers — per-tenant autonomy gate with audit log and per-action whitelist

### Wave 4 — Advanced Capabilities

- [x] Internal threat intelligence — IOC harvesting, threat actor profiles, STIX/TAXII feed subscriptions
- [x] Cloud security posture management (CSPM/KSPM) — posture findings, drift tracking, suppress/resolve workflows
- [x] Identity-centric correlation graph — identity node/edge graph, alert-to-identity linking, attack-path queries
- [x] Auto-generated board reports — report templates, scheduled PDF/HTML artefacts, email/webhook delivery

### Platform

- [x] Dashboard metrics API — aggregated KPI endpoint powering frontend dashboard tiles
- [x] Tailscale connector — audit log and policy-change events with cursor-based pagination
- [x] AWS GuardDuty credential-exfiltration Sigma detection rule

---

## v7.0 — Planned

- Mobile responder console (React Native) — triage and acknowledge from phone
- WCAG AA full accessibility pass
- Light theme + brand-configurable white-label mode
- Saved views and custom dashboard widgets per analyst
- AI-generated weekly executive digest (auto-emailed PDF)
- Slack / Teams native bot for alert triage without opening the UI
- Plugin publishing marketplace v3 (commercial plugins, revenue sharing)

---

## Ideas Backlog (unscheduled)

- NL→query: "show me failed logins from new ASNs last 24h" → ES|QL / KQL
- AI-generated threat intelligence briefings from public feeds
- Automated IOC sharing to community MISP instances
- Embedded red-team scoring (ATT&CK coverage %) visible on dashboard
- "Explain this alert" button using LLM with enrichment context
- Incident cost estimator (breach impact calculator)
- SLA breach predictor (ML model on historical MTTR data)
