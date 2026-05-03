# AiSOC Roadmap

This document captures the planned direction for AiSOC across major versions. All v4 deliverables and items deferred beyond v4 are listed here.

## v4.0 — "Autonomous SOC" (Current)

### Pillar 1: AI Multi-Agent Investigator
- [ ] Orchestrator (LangGraph state machine) in `services/agents/app/investigator/`
- [ ] ReconAgent, ForensicAgent, ResponderAgent (dry-run with analyst approval)
- [ ] ReportWriterAgent — streaming markdown + branded PDF
- [ ] Investigation & Report tabs in Case Workspace UI
- [ ] Eval harness: 20 synthetic incidents, ≥80% MITRE-tactic accuracy CI gate

### Pillar 2: Visual SOAR Studio
- [ ] React Flow playbook editor with full node palette (Trigger, Condition, Action, Loop, Parallel, Human Approval, Wait, Notify)
- [ ] DAG playbook engine with retries, idempotency, blast-radius checks
- [ ] `playbook.schema.json` (JSON Schema 2020-12) for portability and CI linting
- [ ] Detection-as-Code: `detections/` directory with Sigma + AiSOC YAML, GitHub Action deploy-on-merge
- [ ] 12 starter playbook templates
- [ ] Community playbook marketplace (static index v4.0; publishing flow v4.1)

### Pillar 3: Plugin Platform + Public API + SDKs + Docs
- [ ] Plugin SDK in Python (`packages/plugin-sdk-py/`) and Go (`packages/plugin-sdk-go/`)
- [ ] `plugin.yaml` manifest spec (connector | enricher | responder | detection | widget)
- [ ] Plugin loader with OCI image support (`oras pull`) in api/actions/enrichment/connectors
- [ ] Public REST API v1 at `/api/v1`, OpenAPI 3.1 at `docs/openapi.yaml`
- [ ] GraphQL gateway (Strawberry) proxying REST
- [ ] Scoped API tokens (`cases:read`, `playbooks:run`, `plugins:install`)
- [ ] Auto-generated client SDKs: `@aisoc/sdk` (TypeScript), `aisoc-sdk` (Python/PyPI), `github.com/beenuar/aisoc-go`
- [ ] Docusaurus docs site at `docs/site/`, deployed to GitHub Pages
- [ ] Demo Lab: `pnpm aisoc:lab` one-command full-stack + Conti-style ransomware scenario
- [ ] 4 reference plugins: Okta connector, YARA enricher, Slack quarantine responder, MTTR sparkline widget

### Cross-cutting
- [ ] OpenTelemetry traces: agents → actions → api → realtime (Jaeger/Tempo)
- [ ] API token scopes (foundation for SSO)
- [ ] MIGRATION.md for v3 → v4 upgrade path

---

## v4.1 — "Community Ecosystem"

- Plugin publishing flow (signed community submissions, review process)
- Plugin marketplace UI v2 (ratings, install counts, verified badges)
- Detection catalog: browse and install community Sigma rules via UI
- Playbook community submissions and curation
- `aisoc-cli` — developer CLI for scaffold, validate, publish plugins and detections

---

## v5.0 — "Enterprise Ready"

### Identity & Access
- SAML 2.0 + OIDC authentication (Okta, Azure AD, Google Workspace)
- Multi-tenant row-level security
- Granular RBAC with data-class and tenant scopes
- Full analyst audit log (every action immutably recorded)

### Compliance
- SOC 2 Type II evidence collection dashboard
- ISO 27001 control mapping
- NIST CSF / NIST 800-53 control coverage heatmap
- PCI-DSS, HIPAA, DORA module
- MTTD / MTTR / MTTC SLA tracking per tenant

### High Availability & Operations
- HA Helm chart with PodDisruptionBudgets and HorizontalPodAutoscalers
- Backup / restore CLI
- Multi-region active-active topology guide
- Operator runbook generation from OTel traces

---

## v5.1 — "Detection Depth"

### UEBA
- Per-user, per-host, per-service behavioral baselines
- Anomaly risk scores feeding the fusion engine
- Peer-group analysis

### Deception / Honeytokens
- Fake credential documents, fake S3 buckets, fake API keys
- Alert on first touch, enriched with attacker fingerprint
- Honeytoken lifecycle management UI

### Purple-Team / Continuous Validation
- Atomic Red Team integration for automated adversary simulation
- Caldera agent integration
- Detection coverage score vs. MITRE ATT&CK matrix
- Tabletop incident simulator for analyst training

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
