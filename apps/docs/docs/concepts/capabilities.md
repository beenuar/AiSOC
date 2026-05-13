---
sidebar_position: 1
title: Platform Capabilities
description: Full index of AiSOC Tier 1, 2, and 3 capabilities with API references.
---

# Platform Capabilities

AiSOC ships a layered capability model across three tiers.  Tier 1 items are core
SOC operations shipped from day one.  Tier 2 items are intelligent-automation
extensions.  Tier 3 items are advanced analyst workflows.

---

## Tier 1 — Core SOC Operations

| Capability | API prefix | Notes |
|---|---|---|
| **Alerts & triage** | `/api/v1/alerts` | Multi-source ingestion, severity normalisation |
| **Case management** | `/api/v1/cases` | Full lifecycle, observable graph, evidence chain |
| **Detection rules** | `/api/v1/detection-rules` | CRUD + Sigma/YARA-L2/KQL/SPL/ES\|QL |
| **Connectors** | `/api/v1/connectors` | EDR, SIEM, Cloud, IAM, SaaS, VCS, Network |
| **Playbooks** | `/api/v1/playbooks` | Runbook steps, action blocks, approvals |
| **Investigations** | `/api/v1/investigations` | Evidence collection, timeline, MITRE mapping |
| **Threat intelligence** | `/api/v1/threat-intel` | IOC lookup, enrichment, feed management |
| **Compliance evidence** | `/api/v1/compliance` | Audit trails with hash-chain integrity |
| **RBAC + tenants** | `/api/v1/rbac`, `/api/v1/tenants` | Multi-tenant, role-based access |
| **SLA tracking** | `/api/v1/sla` | MTTR/MTTD dashboards and breach alerts |
| **Marketplace** | `/api/v1/marketplace` | Community plugins and integrations |

---

## Agent Intelligence (2026 H2)

Six capabilities make the agent loop honest, calibrated, and steerable. Every
verdict the AI produces is measurable, configurable, and learnable from.

| Capability | API / Surface | Description |
|---|---|---|
| **Three-tier memory** | `services/agents/app/memory/` | Session (in-process LRU) + working (Redis, 24h TTL) + institutional (Postgres, permanent) tiers; pgvector-ready schema |
| **Calibrated confidence** | every agent output | Each verdict carries `confidence` (0–1) + `confidence_basis` (list of factors); Brier-score gate in CI eval harness |
| **Autonomy guardrails** | `/api/v1/autonomy-policy` | Per-action `auto / review / escalate / reject` thresholds in YAML; tenant-specific overrides via DB; admin UI in **Settings → Autonomy Policy** |
| **SOC metrics dashboard** | `/api/v1/metrics/soc` | MTTD / MTTR / MTTC / FPR / escalation rate / ATT&CK heatmap / confidence calibration over time; auto-refresh every 60s |
| **Analyst-override feedback loop** | `/api/v1/feedback` | When an analyst corrects a verdict: persists `disposition`, writes the lesson to `aisoc_institutional_memory`, and surfaces *retroactive candidates* — past alerts in the same tenant matching the same coarse signature that would now flip disposition; bulk-apply with one click |
| **Investigation cost telemetry** | `services/agents/app/core/cost_telemetry.py` | Tokens / model / $ / latency per run; aggregate in metrics dashboard |

### Override loop pipeline

```
analyst override
  ├── PATCH alert.disposition           ← correct verdict on the alert
  ├── INSERT aisoc_institutional_memory ← agent learns for next investigation
  │     key: override:<sig-hash>
  │     tags: [analyst-override, <category>, <connector>, <mitre>]
  └── SELECT similar past alerts        ← coarse signature match (category +
        WHERE tenant_id = ?               connector_type + primary MITRE technique)
          AND signature = ?               returned to UI as RedispositionCandidates
          AND disposition IS DISTINCT FROM corrected_verdict
```

The signature is a deterministic SHA-256 over `(category, connector_type,
primary_mitre_technique)` so identical alerts produce identical memory keys
across runs. Empty signatures (alerts missing all three components) skip
institutional memory ingestion to avoid polluting the knowledge base.

---

## Detection Engineering (2026 H2)

Five capabilities bring detection content under the same CI rigor as application
code, with continuous drift tracking, eval-gated promotions, and scheduled
hypothesis-driven hunts.

| Capability | API / Surface | Description |
|---|---|---|
| **Detection-as-Code (DAC)** | `/api/v1/detection-proposals` | Propose → review → eval-gate → promote lifecycle. Every proposal carries an eval result from `scripts/run_evals.py`; candidates that regress MITRE accuracy by ≥ 1 pp cannot be promoted. Endpoints: list, create, comment, attach eval, decide (approve/reject), promote to `detection_rules`, baseline management. |
| **Detection confidence + explainability** | every fused alert | Each alert leaves the fusion service with a `high / medium / low` confidence label and an ordered evidence chain (`ConfidenceFactor[]`). The label is derived, not assigned — analysts can reproduce the score from the rationale alone. Implemented in `services/fusion/app/services/confidence.py`. |
| **Detection drift monitoring** | `services/purple-team/app/services/drift.py` | Turns the ATT&CK coverage heatmap from a point-in-time view into a tracked time series. Scheduled snapshots enable "delta vs. last week" on the MITRE heatmap. Includes drift-diff computation in `drift_diff.py`. |
| **Hunt-as-Code** | `services/agents/app/hunt/` | YAML hunt definitions in `hunts/` with hypothesis, indicators (operators: equals/in/regex/gte/lte/exists/contains_any/iendswith), and schedule metadata. The `HuntEngine` matcher runs against event streams; `HuntScheduler` (APScheduler) executes hunts continuously. Results flow through `HuntStore` to Postgres. API at `services/agents/app/api/hunts.py`. |
| **Cloud-native detections** | `detections/cloud/` | 27 new cloud-native rules: 20 M365 (Exchange, SharePoint, Teams, Defender, Purview, Power Platform, Entra ID), 3 Azure (Key Vault, management group, Defender for Cloud), 4 GCP (org policy, VPC firewall, Cloud Armor, audit log sink). |

---

## Response & Automation (2026 H2)

| Capability | API / Surface | Description |
|---|---|---|
| **Risk-Based Alerting (RBA)** | `services/fusion/app/services/entity_risk.py` | Alerts contribute time-decayed risk points to entities (user, host, src_ip, domain). Points decay exponentially with a configurable half-life. When an entity's score crosses `rba_promotion_threshold`, AiSOC promotes it to an incident with contributing alerts attached. The entity-centric queue surfaces the top-N highest-risk entities. CI-gated at ≥ 50:1 alert-to-incident ratio. |
| **ChatOps user verification** | `services/actions/app/executors/chatops.py` | Sends Slack/Teams interactive prompts with three HMAC-signed callback choices (acknowledge / deny / escalate). Tokens carry action, case, tenant, user reference, and expiry. Timeout auto-escalates. |
| **L0–L4 remediation maturity tiers** | `/api/v1/remediation` | Each tier unlocks progressively more autonomous remediation. `evaluate_gate()` checks tier, blast-radius, and per-action whitelist before allowing auto-execution. Full gate audit log. See the [Automation Maturity concept page](./automation-maturity.md) and the [L0–L4 white paper](https://tryaisoc.com/papers/l0-l4-automation-maturity.pdf) for the full model. |

---

## Platform Expansion (2026 H2)

| Capability | API prefix | Description |
|---|---|---|
| **EASM** | `/api/v1/easm` | External Attack Surface Management — passive (Shodan/Censys) + optional active port scanning. Discovers assets, tracks drift (new ports, certs, subdomains), and generates alerts. Feature-flagged via `AISOC_FEATURE_EASM`. |
| **Insider threat** | `/api/v1/insider-threat` | User risk profiles, behavioural indicators (login anomaly, data exfil, privilege abuse), peer-group deviation scoring, and watchlist management. |
| **Asset inventory** | `/api/v1/assets` | Auto-correlated asset records with vulnerability tracking and alert-to-asset linking for blast-radius context. |
| **MSSP console** | `/api/v1/mssp` | Parent-tenant console — onboard/manage child tenants, delegate actions cross-tenant, view rollup metrics, per-tenant detection scoping via rule packs with overrides. |
| **CSPM / KSPM** | `/api/v1/posture` | Cloud Security Posture Management — ingest findings, track drift between scan runs, per-provider summary with suppress/resolve workflows. |
| **Identity graph** | `/api/v1/identity-graph` | Entity relationship graph of users, devices, and service accounts with edge traversal and alert-identity linking. |
| **Internal threat intelligence** | `/api/v1/threat-intel` (extended) | Harvest IOCs from alert history, track threat actors and campaigns, manage external STIX/TAXII feed subscriptions. |
| **Board reports** | `/api/v1/reports` | Scheduled PDF/HTML executive summaries with template management, async generation, artefact storage, and webhook/email delivery. |

---

## Eval Harness & Benchmarking (2026 H2)

| Capability | Surface | Description |
|---|---|---|
| **Public benchmark scoreboard** | `/benchmark` page | Live-from-main badge, KPI bar (alert-to-incident ratio, MTTD, MTTR, FPR), per-suite results fetched from `eval-results` branch, community submission leaderboard. |
| **AI-vs-AI adversary eval** | `scripts/run_evals.py` (sixth suite) | Deterministic attacker-LLM mutator (synonym swap, leetspeak, zero-width injection, fragmentation) generates 200 adversarial incidents. Graceful-degradation gate: overall ≥ 0.40, light ≥ 0.85, heavy ≤ 0.50. |
| **Per-feature eval suites** | `scripts/run_evals.py` | Memory recall, override accuracy, confidence calibration (Brier score + ECE), and autonomy adherence suites — each with floor gates. |

---

## Tier 2 — Intelligent Automation

| Capability | API prefix | Description |
|---|---|---|
| **NL detection authoring** | `/api/v1/nl-detection` | Write detection rules in plain English; LLM converts to Sigma YAML |
| **Closed-loop detection engineering** | `/api/v1/detection-loop` | FP feedback → LLM drafts tuned Sigma → opens DAC proposal |
| **NL query → ES\|QL / SPL / KQL** | `/api/v1/nl-query` | Ask questions in natural language; get executable queries + chart spec |
| **Identity-centric timeline** | `/api/v1/identity-timeline` | Per-entity event timeline correlated across sources |
| **Cross-platform rule translation** | `/api/v1/translation` | Sigma ↔ SPL ↔ KQL ↔ ES\|QL ↔ YARA-L2 / UDM bidirectional conversion |
| **Hypothesis-driven hunting** | `/api/v1/hunts` | Define hypothesis → auto-generate multi-platform queries → track findings |

---

## Tier 3 — Advanced Analyst Workflows

| Capability | API prefix | Description |
|---|---|---|
| **Phishing triage** | `/api/v1/phishing` | Submit email/URL/attachment → LLM extracts IOCs, assigns verdict, maps MITRE |
| **Knowledge-base + RAG** | `/api/v1/kb` | Ingest runbooks/policies → full-text + LLM-synthesised answers |
| **Federated search** | `/api/v1/federated` | Cross-SIEM query fan-out with query translation |
| **Identity graph** | `/api/v1/identity-graph` | Entity relationship graph across IAM/CASB/EDR data |
| **Posture management** | `/api/v1/posture` | Asset hygiene scoring and drift detection |
| **Reports** | `/api/v1/reports` | Scheduled and on-demand PDF/JSON security reports |

---

## Detection Rule Formats

AiSOC translates between the following formats natively:

| Format | Read | Write |
|---|---|---|
| **Sigma YAML** | ✅ | ✅ |
| **Splunk SPL** | ✅ | ✅ |
| **Microsoft Sentinel KQL** | ✅ | ✅ |
| **Elastic ES\|QL** | ✅ | ✅ |
| **Google Chronicle YARA-L2** | ✅ | ✅ |
| **Google Chronicle UDM Search** | ✅ | read-only |

---

## Severity Ladder

All connectors normalise to the AiSOC four-tier severity model:

```
info → low → medium → high
```

Vendor-specific ladders (Azure 5-tier, SCC 5-tier, GitHub 4-tier) collapse to
this set in each connector's `normalize()` method.

---

## Compliance Frameworks Supported

The compliance evidence trail supports any framework tag.  Built-in control
mappings are provided for:

- SOC 2 Type II
- PCI-DSS v4
- HIPAA Security Rule
- ISO 27001:2022
- NIST CSF 2.0

Evidence records form a hash-linked chain (SHA-256, similar to a blockchain)
to provide audit-grade tamper evidence.

---

## Connector Categories

| Category | Examples |
|---|---|
| `edr` | CrowdStrike, SentinelOne, Microsoft Defender |
| `siem` | Splunk, Microsoft Sentinel, Elastic Security |
| `cloud` | AWS CloudTrail, Azure Activity, GCP Audit |
| `iam` | Okta, Azure AD, Google Workspace |
| `saas` | GitHub, Slack, Salesforce, Jira |
| `vcs` | GitHub, GitLab |
| `network` | Palo Alto, Cisco, Zeek |

Add a new connector by implementing `BaseConnector` in
`services/connectors/app/connectors/<name>.py` and registering it in
`_CONNECTOR_CLASSES`.  No other wiring required.
