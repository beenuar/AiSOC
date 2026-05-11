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

## v6.1 — Shipped (2026-05-07) — v1.5 market-driven feature expansion

A review of G2, Gartner Peer Insights, and customer feedback on AI SOC / SIEM /
SOAR platforms drove this release.

### New autonomous agents (`services/agents/app/agents/`)

- [x] Master autonomous triage agent (`auto_triage_agent.py`) — classifies each
      alert as `true_positive` / `false_positive` / `benign` with confidence
- [x] Phishing triage sub-agent (`phishing_agent.py`)
- [x] Identity reasoning sub-agent (`identity_agent.py`)
- [x] Cloud reasoning sub-agent (`cloud_agent.py`)
- [x] Insider-threat reasoning sub-agent (`insider_threat_agent.py`)
- [x] All five exposed via `POST /api/v1/agents/triage`

### New console pages (`apps/web/src/components/`)

- [x] `/investigate` — conversational, multi-turn investigation copilot
- [x] `/coverage-advisor` — MITRE ATT&CK gap ranking by adversary prevalence
- [x] `/shifts` — analyst shift-handoff dashboard
- [x] `/easm` — External Attack Surface Management
- [x] `/mssp` — MSSP executive dashboard
- [x] `/noise-tuning` — per-rule false-positive rate and one-click tuning
- [x] `/analytics/team` — analyst leaderboard, MTTR per analyst, dispositions accuracy

### New API surfaces (`services/api/app/api/v1/endpoints/`)

- [x] `shifts.py` — shift-handoff CRUD
- [x] `stix_taxii.py` — STIX 2.1 / TAXII 2.1 publishing
- [x] `compliance.py` — automated compliance evidence (SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA)
- [x] `deployment.py` — deployment / air-gap toggles

### New connectors (16 → 26)

- [x] SentinelOne (`sentinelone.py`)
- [x] Cortex XDR (`cortex_xdr.py`)
- [x] Wiz (`wiz.py`)
- [x] Snyk (`snyk.py`)
- [x] Zscaler (`zscaler.py`)
- [x] Proofpoint (`proofpoint.py`)
- [x] ServiceNow (`servicenow.py`)
- [x] Jira (`jira.py`)
- [x] 1Password (`1password.py`)
- [x] Duo Security (`duo_security.py`)

### Other

- [x] AI-generated incident reports — one-click "Export Report" generates PDF from the Investigation Ledger
- [x] Air-gap deployment configuration — per-tenant toggles disable external feeds

---

## v7.0 — Shipped ✅ (2026-05-10)

All items below were shipped as part of the v1.0 buyer-value plan.
Implemented and reviewed by Beenu Arora <beenu@cyble.com>.

- [x] WCAG AA full accessibility pass (axe-core CI gate — `apps/web/src/test/a11y.test.tsx`)
- [x] Light theme persisted in user profile (`ThemeProvider.tsx` + `PATCH /api/v1/users/me/preferences`)
- [x] Saved views and custom drag-drop dashboard widgets per analyst (`saved_views.py` + `DashboardView.tsx`)
- [x] AI-generated weekly executive digest — auto-emailed PDF (`digest_pdf.py` + `weekly_digest_task.py`)
- [x] Slack native bot for alert triage without opening the UI (`services/slack-bot/` — 61 tests)
- [x] Threat actor attribution engine v0 (`services/threatintel/app/actors/attribution.py`)
- [x] Air-gap / Ollama local-LLM mode (`docker-compose.airgap.yml` + `apps/docs/docs/operations/air-gapped.md`)
- [x] BYOK per-tenant LLM credentials UI + API (`llm_credentials.py` + `SettingsView.tsx`)
- [x] MSSP console — per-child-tenant KPI aggregation, SLA posture, parent_tenant_id hierarchy
- [x] Team analytics view — analyst MTTR, leaderboard, shift workload (`TeamAnalyticsView.tsx`)
- [x] Case auto-summary + PDF export (`case_summary.py` + `case_summary_html.py`)
- [x] Investigation timeline (replayable) (`InvestigationTimeline.tsx`)
- [x] Playbook gallery with 12 curated packs + GitHub PR integration for detection proposals
- [ ] Mobile responder console (React Native) — triage and acknowledge from phone _(deferred to v8.0)_
- [ ] Plugin publishing marketplace v3 (commercial plugins, revenue sharing) _(deferred to v8.0)_

---

## v7.0.x — Endpoint telemetry wave + hardening (2026-05-10)

Six-PR feature wave that closes [#44](https://github.com/beenuar/AiSOC/issues/44)
("osctrl connector for fleet-wide osquery telemetry") and significantly extends
osquery coverage end to end. All six PRs were implemented sequentially as part of
the v7.0 release window and then patched through 7.0.1 → 7.0.3.

### Endpoint telemetry — osquery feature wave (PR1–PR6)

- [x] **PR1 — osctrl + FleetDM connectors** (`services/connectors/app/connectors/osctrl.py`,
      `fleetdm.py`). Schema-driven setup, live `Test connection` round-trip, secrets
      encrypted via `CredentialVault`, polling on per-instance schedule, plus marketplace
      manifests at `plugins/osctrl/plugin.yaml` and `plugins/fleetdm/plugin.yaml`.
- [x] **PR2 — Native osquery detection schema migration** — 16 osquery rules
      (`detections/endpoint/osquery-*.yaml`, IDs `det-endpoint-281..296`) migrated from
      `_quarantine/` to the native schema, with positive/negative test fixtures
      (`detections/fixtures/osquery_*.json`) gated by the Detection Validation workflow.
- [x] **PR3 — Live-query playbook step** (`services/actions/app/clients/osctrl_client.py`,
      `fleetdm_client.py`, `osquery_allowlist.py`, `services/agents/app/playbook/steps/osquery_live_query.py`).
      Allowlisted distributed queries pushed to single hosts or fleet-wide via
      osctrl/FleetDM with HMAC-signed ChatOps approval.
- [x] **PR4 — `aisoc-osquery-tls` FastAPI service + `aisoc-direct` agent connector**
      (`services/osquery-tls/`, `services/connectors/app/connectors/aisoc_direct.py`).
      First-party self-hosted osquery TLS plugin, FleetDM-compatible config/log endpoints,
      direct-from-agent ingest path that bypasses third-party SaaS.
- [x] **PR5 — Osquery packs + FIM endpoint + FIM dashboard**
      (`services/osquery-tls/app/api/v1/endpoints/fim.py`, `apps/web/src/components/dashboard/FimDashboard.tsx`).
      Bundled IR / OSquery-ATT&CK / FIM packs; ingests `file_events` and synthesises
      alerts on writes to `/etc/passwd`, `/etc/shadow`, sshd configs, sudoers, Windows
      registry hives. FIM-specific detection IDs `det-endpoint-297..300`.
- [x] **PR6 — AiSOC osquery extensions** (`services/osquery-extensions/tables/*.go`).
      5 custom Go-based virtual tables: `aisoc_browser_extensions`, `aisoc_kernel_modules`,
      `aisoc_attck_persistence`, `aisoc_pending_actions`, `aisoc_alert_cache` — ship
      richer endpoint visibility plus a bidirectional response channel.

### Patch releases

#### v7.0.1 — Web app hardening (CodeQL + Turbopack)

- [x] **42 CodeQL code-scanning alerts cleared** (`py/unused-global-variable`,
      `py/cyclic-import`, `py/empty-except`, `py/log-injection`,
      `py/clear-text-logging-sensitive-data`, `py/incomplete-url-substring-sanitization`,
      `py/stack-trace-exposure`, `py/call/wrong-arguments`, `py/unused-import`,
      `js/unused-local-variable`).
- [x] **`apps/web/next.config.js`** — Removed deprecated `eslint.ignoreDuringBuilds`
      key Next.js 16 no longer accepts; added `turbopack.root` for workspace package
      resolution.
- [x] **`apps/web/src/app/layout.tsx`** — Added `suppressHydrationWarning` to `<html>`
      so the render-blocking `themeBootstrapScript` can write `data-theme` /
      `data-theme-preference` / `style.colorScheme` without React reporting an
      attribute mismatch.

#### v7.0.2 — Version alignment + landing-page footer + docs

- [x] **`apps/web/package.json`** bumped to `7.0.2`; sidebar shows `v7.0.2` dynamically.
- [x] **`apps/web/src/components/landing/Footer.tsx`** — Replaced hard-coded `v6.1.0`
      with a dynamic import of `package.json`.
- [x] **`README.md`** — Added `osquery-tls` (port 8090) and `osquery-extensions` to the
      services / Swagger / directory-tree / dev-surface tables.

#### v7.0.3 — Structural hydration fix + font preload

- [x] **`apps/web/src/components/layout/AppShell.tsx`** — Wrapped `<DemoBanner />` in
      a new `<ClientOnly>` boundary so the banner (which reads
      `NEXT_PUBLIC_DEMO_MODE`) is never server-rendered. Eliminates React
      hydration error #418 caused by stale env-var inlining producing a structural
      tree mismatch (server saw `<button>` from `Sidebar`, client expected `<div>`
      from `DemoBanner`).
- [x] **`apps/web/src/app/layout.tsx`** — Added `preload: false` to the
      `JetBrains_Mono` `next/font/google` config; eliminates "preloaded but not
      used within a few seconds" Chrome warnings without any visible FOUT.

---

## v7.1.0 — Shipped ✅ (2026-05-10) — Cloud Security Coverage Wave

Six new connectors, three documentation backfills, and a new ingest template
closing the biggest cloud-security gap in the connector catalogue. Every Tier-1
cloud workload protection platform now has a first-class AiSOC integration,
AWS gets three native data sources, and Kubernetes audit logs land via a
dual-mode connector that works on both managed and air-gapped clusters.

### Track A — Documentation backfill for existing cloud connectors

- [x] **`apps/docs/docs/connectors/wiz.md`** — Service-account creation,
      `read:issues` + `read:vulnerabilities` scopes, token rotation, normalised
      severity map, worked Wiz `Issue` → inbox event example.
- [x] **`apps/docs/docs/connectors/aws-security-hub.md`** — IAM-role vs.
      static-key auth, `securityhub:GetFindings` permission, and the
      `BLOCK_IP`/`ALLOW_IP` capability documented end-to-end against
      `services/actions/app/clients/aws_security_groups.py`.
- [x] **`apps/docs/docs/connectors/lacework.md`** — API-token flow, `api_url`
      regional variants, alert → event severity collapse.
- [x] **`apps/docs/sidebars.ts`** — All three backfilled pages + the four new
      Track B–D pages registered under the `Connectors` category.

### Track B — New CNAPP connectors

- [x] **`PrismaCloudConnector`** (`services/connectors/app/connectors/prisma_cloud.py`)
      — Full CSPM/CWPP coverage. JWT auth via `POST /login`, paginated
      `GET /alert/v1/alert` with windowed `time.from`/`time.to`, severity collapse,
      `compute_url` override for self-hosted Compute Edition.
- [x] **`OrcaConnector`** (`services/connectors/app/connectors/orca.py`) —
      `https://api.orcasecurity.io/api/alerts` with `api_token` auth, severity
      collapse with Orca-specific `hazardous → high` rule.
- [x] Manifests at `plugins/prisma-cloud/plugin.yaml` and `plugins/orca/plugin.yaml`,
      docs at `apps/docs/docs/connectors/{prisma-cloud,orca}.md`, full test
      suites under `services/connectors/tests/test_{prisma_cloud,orca}.py`.

### Track C — Native AWS connectors

- [x] **`AWSGuardDutyConnector`** (`services/connectors/app/connectors/aws_guardduty.py`)
      — boto3-based, supports IAM-role + static-key auth via `_resolve_session`,
      iterates detectors with `list_findings` + `get_findings`. Collapses
      GuardDuty's continuous numeric severity scale (`0.1`–`10.0`) into AiSOC's
      four-tier `info|low|medium|high` ladder.
- [x] **`AWSCloudTrailConnector`** (`services/connectors/app/connectors/aws_cloudtrail.py`)
      — `cloudtrail.lookup_events` with a curated 21-event allow-list covering
      identity abuse, persistence, data-plane abuse, network exposure, and trail
      tampering. Allow-list overridable via the `event_names` field.
- [x] **`AWSVPCFlowLogsConnector`** (`services/connectors/app/connectors/aws_vpc_flow.py`)
      — `cloudwatch_logs.filter_log_events`, v2 + v5 format parsing,
      RFC-5735-aware public-IP heuristic, default `?REJECT` filter pattern,
      severity heuristic (`public REJECT → medium`, `internal REJECT → low`,
      `ACCEPT → info`).
- [x] Manifests + docs + tests for all three connectors. 27 unit tests for
      `AWSVPCFlowLogsConnector` covering v2/v5 parsing and public-IP edge cases.

### Track D — Kubernetes audit logs (dual-mode)

- [x] **`KubernetesAuditConnector`** (`services/connectors/app/connectors/kubernetes_audit.py`)
      ships with two delivery modes selected via the `mode` config field:
      - **`webhook` (recommended)** — apiserver pushes audit events to AiSOC's
        new dedicated `POST /v1/ingest/k8s-audit/{tenant_id}` route,
        authenticated with a shared secret in the `X-AiSOC-K8s-Token` header
        (constant-time compared so a partial-prefix attacker can't shave
        bytes off via timing). Legacy `/v1/inbox/{token}` path with the
        `k8s-audit` template is kept as a fallback for control planes that
        cannot inject custom headers into the audit-webhook kubeconfig.
      - **`file_tail`** — AiSOC's connector pod tails a local `audit.log` using
        a byte-position cursor (atomically written via `os.replace` to a
        `.aisoc-cursor` sidecar) with rotation/truncation detection and a hard
        per-poll byte cap so a backlog can't blow up a single poll cycle.
- [x] **`services/ingest/internal/handler/k8s_audit.go`** — Dedicated Go
      handler for the webhook route. Caps body size via
      `K8S_AUDIT_MAX_BODY_BYTES` (default 16 MiB), rejects oversized batches
      with `413` so the apiserver shrinks `--audit-webhook-batch-max-size`
      and retries, and publishes each `EventList.items[]` entry through the
      existing normalizer + Kafka publisher using
      `connector_type: kubernetes_audit`. The route is disabled (returns
      `503`) until an operator sets `K8S_AUDIT_SHARED_SECRET`, so a fresh
      install never accidentally accepts unauthenticated audit traffic.
- [x] **`kubernetes_audit` normalizer profile**
      (`services/ingest/internal/normalizer/normalizer.go`) — Maps `auditID`
      to `external_id`, `verb` to `activity_name`, `user.username` to
      `actor.user.name`, `objectRef.{namespace,resource,name}` to a
      composite `target.resource.name`, and translates the connector's
      string severity (`critical|high|medium|low|info`) into OCSF integer
      severities (5/4/3/2/1).
- [x] **`k8s-audit` inbox template**
      (`services/ingest/internal/normalizer/templates/k8s-audit.yaml`) —
      maps apiserver `Event` payloads onto AiSOC's normalised event shape
      for the legacy inbox-token path; severity is derived in the
      connector's `_classify_severity` heuristic so the same logic applies
      to both delivery modes.
- [x] **Severity heuristic** — `exec`/`attach`/`portforward` on Pod and
      `create` on `ClusterRoleBinding` → `high`; writes to `Secret`/`ConfigMap`/
      `ClusterRole`/`Role` → `medium`; successful reads on sensitive resources
      → `low`; everything else → `info`.
- [x] **`plugins/kubernetes-audit/plugin.yaml`** — 4-field config schema
      (`mode`, `cluster_name`, `inbox_token`, `audit_log_path`, `cursor_path`),
      `category: cloud`, capabilities `pull_audit` + `pull_alerts`.
- [x] **`apps/docs/docs/connectors/kubernetes-audit.md`** — Sample `AuditPolicy`
      + sample `AuditSink` for both managed and self-hosted clusters.

### Cross-cutting

- [x] **`pnpm marketplace:sync`** — `marketplace/index.json` +
      `apps/web/public/marketplace/index.json` rebuilt; plugin count rose
      `43 → 49`. Total: `total=7104 detections=6993 playbooks=62 plugins=49
      mitre_techniques=493`.
- [x] **`apps/web/package.json`** bumped to `7.1.0`; sidebar and landing-page
      footer surface the new version dynamically.

---

## v8.0 — Planned

- Mobile responder console (React Native) — triage and acknowledge from phone
- Plugin publishing marketplace v3 (commercial plugins, revenue sharing)
- MSSP RBAC enforcement on `/api/v1/actors/*` endpoints (threat attribution)
- Automated IOC sharing to community MISP instances via STIX/TAXII push
- NL→query: "show me failed logins from new ASNs last 24h" → ES|QL / KQL
- AI-generated threat intelligence briefings from public feeds
- Embedded red-team scoring (ATT&CK coverage %) as a live dashboard widget
- SLA breach predictor (ML model on historical MTTR data)
- Incident cost estimator (breach impact calculator)
- SOC-in-a-box one-click cloud deploy (Terraform module for AWS / GCP)

---

## Ideas Backlog (unscheduled)

- "Explain this alert" button using LLM with enrichment context
- Browser-extension recorder for analyst playbook capture
- Voice-driven incident commander (TTS / STT for hands-free triage)
- Automated retro/blameless post-mortem drafting from case timeline
