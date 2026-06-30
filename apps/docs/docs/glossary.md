---
sidebar_position: 99
---

# Glossary

A reference for terminology used across AiSOC docs, code, and the UI.
Terms are grouped so you can find them by area; everything is also
alphabetized within each group.

## Core platform

**AiSOC** — Open-source AI Security Operations Center. The agent itself is
MIT-licensed and self-hostable, with a public eval harness gating every PR
that touches the substrate.

**Ambient Copilot** — Context-aware suggestion strip that appears on every
alert, case, rule, and playbook page. Each suggestion is a one-click action
that runs an agent tool with a pre-filled payload.

**Case** — A unit of investigation grouping one or more alerts, evidence
items, agent decisions, and analyst actions. Cases are the surface where
the [Investigation Ledger](./concepts/cases) is rendered.

**Connector** — Schema-driven integration that pulls events from a vendor
API (EDR, SIEM, cloud, IAM, SaaS, VCS, network) and pushes normalized OCSF
records into the ingest spine. See the [connector catalog](./connectors).

**Detection rule** — A query (Sigma / YARA / KQL / EQL) that fires an
alert when matching events are seen. AiSOC ships ~800 native rules plus
~6,000 imported from public catalogs, each tagged with provenance.

**Investigation Ledger** — Append-only, replayable record of every
prompt, tool call, evidence citation, and decision the agent emits while
working a case. See [Concepts → Cases](./concepts/cases).

**MCP (Model Context Protocol)** — Protocol used by `@aisoc/mcp` to expose
AiSOC tools to IDE-side LLM clients (Claude Desktop, Cursor, Continue,
Cody). See [Integrations → MCP](./integrations/mcp).

**Playbook** — Visual, reusable automation workflow built from trigger,
enrichment, decision, action, and notification nodes. See
[Concepts → Playbooks](./concepts/playbooks).

**Responder PWA** — Installable mobile route at `/responder/*` for
on-call analysts. Passkey-only login, on-call rotation, approvals queue,
VAPID Web Push, and an offline shell.

**Substrate** — The deterministic non-LLM layer (extractors, fusion,
templates, judges) that the eval harness exercises against synthetic
data. Three of the four eval suites measure substrate self-consistency,
not live agent accuracy.

## Detection & alerting

**Alert** — A single signal emitted by a detection rule, fusion model, or
external SIEM. Alerts are the raw input to triage and may roll up into a
case.

**Detection-as-Code (DAC)** — Workflow where detection rules are proposed,
reviewed, and gated by the eval harness before promotion. Proposals that
regress MITRE accuracy are blocked.

**Detection confidence** — Each fused alert carries a `high / medium /
low` label derived from weighted factors (rule fidelity, ML score, IOC
reputation, UEBA Z-score). The label is computed, not hand-set.

**Detection drift** — Change in MITRE ATT&CK coverage over time.
Scheduled coverage snapshots enable "delta vs. last week" tracking on
the heatmap.

**Fusion** — Real-time stage that ingests alerts off the Kafka spine,
applies ML scoring (LightGBM + Isolation Forest), deduplicates on a
Bloom filter of 10M+ IOCs, and writes correlated alerts to the storage
tier.

**Hunt-as-Code** — YAML hunt definitions in `hunts/` with hypothesis,
indicator matching (`equals` / `in` / `regex` / `gte` / `lte` / `exists` /
`contains_any` / `iendswith`), and APScheduler-driven continuous
execution.

**Indicator (IOC)** — Indicator of Compromise. An observable (IP,
domain, hash, email, URL) used in detection and enrichment.

**MITRE ATT&CK** — Adversary tactics-and-techniques framework that AiSOC
uses for tagging detections, tracking coverage, and grading agent
accuracy in the eval harness.

**Risk-Based Alerting (RBA)** — Mode where alerts contribute time-decayed
risk points to entities (user, host, IP, domain). Crossing a configurable
threshold promotes the entity to an incident with contributing alerts
attached.

**Sigma** — Generic, vendor-agnostic detection rule format. AiSOC stores
all native rules in a Sigma-shaped schema and translates at query time.

**UEBA (User and Entity Behavior Analytics)** — Per-entity online
baselines (Welford's online algorithm) and Z-score anomaly scoring.
Anomalies are published back to Kafka for fusion.

## Investigation & response

**Attack graph** — Neo4j entity graph of users, hosts, processes,
network flows, and IOCs. Used for attack-path reconstruction and
blast-radius gating on automated response actions.

**Blast radius** — The set of entities a proposed automated action would
affect. Destructive actions are gated by approvals and ATT&CK-aware
blast-radius checks.

**ChatOps** — Slack and Teams interactive prompts with HMAC-signed
callback choices (`acknowledge` / `deny` / `escalate`) for human-in-the-
loop response actions.

**Honeytoken** — HMAC-SHA256-signed deceptive credential (URL, file, AWS
key, email, document) that fires a webhook the moment it is touched.

**Incident** — Promoted case representing a confirmed or high-confidence
threat. RBA, manual escalation, and certain auto-triage verdicts can
produce incidents.

**On-call rotation** — Scheduled set of analysts who receive Web Push
notifications via the Responder PWA when high-priority alerts or
approval requests arrive.

**Triage** — First-pass classification of an alert as true positive,
false positive, or benign. AiSOC's auto-triage agent assigns a confidence
score; high-confidence false positives close automatically, uncertain
alerts escalate to humans.

## Threat intelligence

**MISP** — Open-source threat intel platform. AiSOC ingests MISP feeds
into its triple-storage model (search · vector · graph).

**OTX** — AlienVault Open Threat Exchange. Ingested alongside MISP and
TAXII feeds.

**STIX 2.1** — Structured Threat Information eXpression. AiSOC publishes
and consumes STIX 2.1 bundles for bidirectional intel sharing.

**TAXII 2.1** — Trusted Automated eXchange of Indicator Information.
Transport layer for STIX. AiSOC supports TAXII collection management
and pull-based ingestion.

## Identity, access, security

**Audit log** — Immutable, tenant-scoped record of mutating operations
on the API and console. Backed by Postgres with cryptographic chaining.
See [Operations → Security](./operations/security).

**API key** — Long-lived service credential. Stored hashed (SHA-256);
the plaintext is shown exactly once at creation.

**Credential vault** — Application-layer Fernet (AES-128-CBC + HMAC-
SHA256) encryption for connector secrets. Key in `AISOC_CREDENTIAL_KEY`;
rotation supported via `MultiFernet` and
`AISOC_CREDENTIAL_KEY_ROTATION_FROM`. Vault tokens are formatted
`vault:v1:<base64>`. See [Operations → Credentials](./operations/credentials).

**JWT** — JSON Web Token used as the session credential between the web
console and the API. Signed with `SECRET_KEY` (HS256 by default).

**MFA (Multi-Factor Authentication)** — TOTP and WebAuthn (passkeys)
supported. Passkeys are required on the Responder PWA.

**Passkey** — WebAuthn credential bound to a user account; used as
primary auth on the Responder PWA and as an MFA factor on the desktop
console.

**RBAC (Role-Based Access Control)** — Permissions granted via roles.
AiSOC ships `viewer`, `analyst`, `responder`, `admin`, and `owner` roles
with granular per-resource scopes.

**RLS (Row-Level Security)** — Postgres feature used to enforce multi-
tenant isolation. Every tenant-scoped table has an RLS policy keyed on
the `app.current_tenant_id` session variable.

**SAML 2.0** — Enterprise SSO protocol. Supported alongside OIDC for
console and API authentication.

**Tenant** — Top-level isolation boundary. All tenant-scoped tables
carry a `tenant_id` column and are protected by RLS.

## Eval & quality

**Alert reduction** — Real measurement: ratio of raw alerts in to
correlated incidents out, computed over a fixed noisy stream.

**Eval harness** — Reproducible suite that runs in CI against a fixed
200-incident synthetic dataset. Three suites measure substrate self-
consistency; one (`mitre_accuracy`) calls the live agent. See
[Benchmark](./benchmark).

**False positive rate (FPR)** — Share of alerts marked false positive
by analysts or auto-triage. Drives noise-tuning recommendations.

**MTTD / MTTR / MTTC** — Mean Time To Detect / Respond / Contain.
SLA-tracked on the compliance dashboard.

## Operations & deployment

**Air-gapped deploy** — Fully offline install with mirrored container
images and signed plugin bundles. See [Operations → Air-gapped](./operations/airgap).

**APScheduler** — Python in-process job scheduler used by connectors
(per-instance polling) and Hunt-as-Code (continuous hunt execution).

**Demo profile** — Slim Docker Compose stack (`infra/compose/docker-compose.demo.yml`)
spun up by `pnpm aisoc:demo`. Pulls prebuilt GHCR images, seeds canonical
data, and lands you on a live case.

**Doctor** — `pnpm aisoc:doctor` health-check that walks ports,
containers, demo data, the API, and the WebSocket gateway, and tells you
exactly what's red.

**Ingest spine** — Kafka-backed message bus that all connectors,
ingestors, and stream processors read and write. Sub-second alert
latency end-to-end.

## Compliance & governance

**DORA** — EU Digital Operational Resilience Act. AiSOC ships a DORA
evidence dashboard alongside SOC 2, ISO 27001, NIST CSF, PCI-DSS, and
HIPAA.

**EASM (External Attack Surface Management)** — Continuous asset
discovery, exposed-service detection, certificate monitoring with expiry
alerts, and risk scoring.

**Evidence** — Compliance artefact (configuration snapshot, log query
result, attestation) collected automatically from connected sources and
mapped to control IDs.

**MSSP** — Managed Security Service Provider. AiSOC's MSSP dashboard
gives cross-tenant aggregated KPIs and per-tenant risk scoring.

## Plugin & SDK

**Marketplace** — In-app catalog (`/marketplace`) of plugins, playbooks,
and detection packs, surfaced via [`marketplace/index.json`](https://github.com/beenuar/AiSOC/tree/main/marketplace)
and filterable by tier (`stable` / `beta` / `imported` / `community`).

**Plugin manifest** — `plugin.yaml` mirroring a connector's `schema()`
classmethod. Required for marketplace listing.

**SDK** — Python, TypeScript, and Go client libraries plus matching
plugin SDKs. Plugins are Ed25519-signed at publish time.

**Tier** — Marketplace quality bucket. `stable` plugins/rules ship and
are supported by the AiSOC project; `beta` are usable but evolving;
`imported` come from public catalogs (SigmaHQ, Splunk Security Content,
Chronicle, MITRE CAR); `community` are user-contributed.

## See also

- [Concepts → Cases](./concepts/cases) — including the Investigation Ledger
- [Concepts → Detections](./concepts/detections)
- [Concepts → Playbooks](./concepts/playbooks)
- [Operations → Security](./operations/security)
- [Operations → Credentials](./operations/credentials)
- [Benchmark](./benchmark)
