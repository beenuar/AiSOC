# AiSOC Roadmap

This document captures the planned direction for AiSOC across major versions. All v4 deliverables and items deferred beyond v4 are listed here.

## v4.0 — "Autonomous SOC" ✅ Shipped

### Pillar 1: AI Multi-Agent Investigator
- [x] Orchestrator (LangGraph state machine) in `services/agents/app/investigator/`
- [x] ReconAgent, ForensicAgent, ResponderAgent (dry-run with analyst approval)
- [x] ReportWriterAgent — streaming markdown + branded PDF
- [x] Investigation & Report tabs in Case Workspace UI
- [x] Eval harness: 20 synthetic incidents, ≥80% MITRE-tactic accuracy CI gate

### Pillar 2: Visual SOAR Studio
- [x] React Flow playbook editor with full node palette (Trigger, Condition, Action, Loop, Parallel, Human Approval, Wait, Notify)
- [x] DAG playbook engine with retries, idempotency, blast-radius checks
- [x] `playbook.schema.json` (JSON Schema 2020-12) for portability and CI linting
- [x] Detection-as-Code: `detections/` directory with Sigma + AiSOC YAML, GitHub Action deploy-on-merge
- [x] 12 starter playbook templates
- [x] Community playbook marketplace (static index v4.0; publishing flow v4.1)

### Pillar 3: Plugin Platform + Public API + SDKs + Docs
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

## v4.1 — "Community Ecosystem" ✅ Shipped

- [x] Plugin publishing flow (signed community submissions, Ed25519 verification, review endpoints)
- [x] Plugin marketplace UI v2 (ratings, install counts, verified badges, category filter, sort)
- [x] Detection catalog: browse and install community Sigma rules via UI
- [x] Playbook community submissions and curation
- [x] `aisoc-cli` — developer CLI for scaffold, validate, publish plugins and detections

---

## v5.0 — "Enterprise Ready" ✅ Shipped

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

## v5.1 — "Detection Depth" ✅ Shipped

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

## v6.0 — "Full-Spectrum Visibility"

### Investigation & Forensics Depth
- Super-timeline view (Plaso-style, all event sources on one scrubbable axis)
- Process tree and lateral movement graph (extending `graph_service.py`)
- PCAP viewer and network session reconstruction
- Memory and disk artifact viewer (Volatility / Velociraptor integration)
- Evidence vault — signed, hashed, chain-of-custody for every artifact

### Data Source Breadth
- **Identity:** Okta, Azure AD/Entra, Google Workspace, Duo (full production connectors)
- **Cloud:** AWS CloudTrail/GuardDuty, Azure Defender, GCP Security Command Center, Kubernetes audit + Falco
- **EDR:** CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Wazuh
- **Email:** Gmail/Workspace, Microsoft 365, Mimecast, Proofpoint — phishing triage agent
- **Network:** Zeek, Suricata/NFSen, NDR (Arkime/Stenographer)
- **STIX/TAXII server** (both consume and serve IOCs)
- **MISP** and **OpenCTI** federation

### Attack Surface & Vulnerability
- ASM / CTEM module — external attack surface discovery feeding TI
- CVE + EPSS + KEV joined to asset inventory for vuln↔alert correlation
- ITDR (Identity Threat Detection & Response) module
- CSPM / CNAPP lite — cloud misconfiguration with runtime correlation

---

## v7.0 — "Operator Experience"

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
