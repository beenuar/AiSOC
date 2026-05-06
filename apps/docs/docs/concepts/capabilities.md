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
