---
sidebar_position: 14
title: Capability matrix
description: Per-connector capability coverage — which connectors can pull alerts, query logs, pivot on entities, push cases to ITSM, isolate hosts, and more.
---

# Capability matrix

Every connector in AiSOC declares a set of **capabilities** — concrete verbs the orchestrator and agents are allowed to ask it to perform. Capabilities are not free text; they are members of the [`Capability` enum](https://github.com/AiSOC-community/AiSOC/blob/main/services/connectors/app/connectors/base.py) defined in `services/connectors/app/connectors/base.py`. The agent runtime, the federated-search planner, and the case-fanout service all consult this set before dispatching work; a connector that does not declare `PUSH_CASE`, for example, will simply be skipped when AiSOC tries to mint an ITSM ticket.

This page is the canonical "what works where" reference. It is generated from the connector source and is kept in sync with the registry in `services/connectors/app/connectors/__init__.py`.

## Capabilities, defined

| Capability | What it means in practice |
|---|---|
| `PULL_ALERTS` | Connector polls the vendor on a schedule and emits normalized alert/detection events into the AiSOC ingest stream. |
| `PULL_AUDIT` | Connector polls the vendor's audit/activity log surface (admin actions, sign-ins, configuration changes) and emits normalized audit events. |
| `QUERY_LOGS` | Connector exposes an ad-hoc search interface (KQL / SPL / ES&#124;QL / vendor DSL) so the federated-search planner can fan a single human question across multiple SIEMs. |
| `PIVOT_HOST` / `PIVOT_USER` / `PIVOT_IP` / `PIVOT_DOMAIN` | Connector can answer "what else has this entity touched?" — used by agents during investigation to widen the blast-radius view. |
| `ISOLATE_HOST` / `UNISOLATE_HOST` | Containment verb. The connector can ask the vendor to network-isolate or release an endpoint. Always gated behind ChatOps verification. |
| `QUARANTINE_FILE` / `BLOCK_HASH` | Endpoint response verbs — push a file to quarantine, block a hash globally. Also gated behind ChatOps verification. |
| `ENRICH_DOMAIN` / `ENRICH_VULN` / `ENRICH_ASSET` | Read-only enrichment — fetch reputation, CVE detail, or asset metadata to attach to a case as evidence. |
| `READ_AUDIT_TRAIL` | Connector exposes a stable, queryable audit trail used by compliance flows (e.g. "show me every grant of admin to this user across the last 90 days"). |
| `PUSH_CASE` | **Bidirectional ITSM, outbound.** Connector can mint a new ticket in the external system from an AiSOC case. AiSOC remains source of truth — see [ITSM as source of truth](/docs/architecture/itsm-as-source-of-truth). |
| `PUSH_STATUS` | **Bidirectional ITSM, outbound.** Connector can project an AiSOC case status change onto the external ticket (transitioning it through the vendor's workflow, closing it, etc.). |

When a capability is not listed for a connector, the connector simply does not support it today — it is **not** a misconfiguration to surface. Adding a capability requires an explicit code change in that connector's `capabilities()` classmethod and matching method implementation.

## Coverage table — 78 connectors

The matrix below is grouped by category. `OAuth (hosted)` indicates the connector is wired into the hosted OAuth marketplace flow (no client secret in tenant config). `Federated search` means the connector participates in the federated-query planner.

### Identity / IAM

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| Auth0 (`auth0`) | ✅ | — | `PULL_AUDIT`, `PIVOT_USER`, `READ_AUDIT_TRAIL` |
| Microsoft Entra ID (`azure_entra`) | ✅ | — | `PULL_AUDIT`, `PULL_ALERTS` |
| Duo Security (`duo_security`) | — | — | `PULL_AUDIT` |
| Okta (`okta`) | ✅ | — | `PULL_AUDIT` |
| 1Password Events (`onepassword`) | — | — | `PULL_AUDIT` |

### EDR / XDR

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| Microsoft Defender (`azure_defender`) | ✅ | — | `PULL_ALERTS` |
| VMware Carbon Black Cloud (`carbon_black`) | — | — | `PULL_ALERTS`, `PULL_AUDIT`, `PIVOT_HOST`, `ISOLATE_HOST`, `QUARANTINE_FILE`, `BLOCK_HASH` |
| Cortex XDR (`cortex_xdr`) | — | — | `PULL_ALERTS` |
| CrowdStrike Falcon (`crowdstrike`) | — | — | `PULL_ALERTS` |
| SentinelOne (`sentinelone`) | — | — | `PULL_ALERTS` |
| Trend Vision One (`trend_vision_one`) | — | — | `PULL_ALERTS`, `PULL_AUDIT`, `PIVOT_HOST`, `ISOLATE_HOST`, `UNISOLATE_HOST` |

### SIEM

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| Google Chronicle (`chronicle`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER`, `PIVOT_IP` |
| Cortex XSIAM (`cortex_xsiam`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER`, `ISOLATE_HOST` |
| Datadog Cloud SIEM (`datadog_cloud_siem`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER`, `PIVOT_IP` |
| Elastic SIEM (`elastic`) | — | ✅ | `PULL_ALERTS`, `QUERY_LOGS` |
| Microsoft Sentinel (`microsoft_sentinel`) | — | ✅ | `PULL_ALERTS`, `QUERY_LOGS` |
| Rapid7 InsightIDR (`rapid7_insightidr`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER` |
| Splunk (`splunk`) | — | ✅ | `PULL_ALERTS`, `QUERY_LOGS` |
| Sumo Logic Cloud SIEM (`sumo_logic`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER` |
| Trellix Helix (`trellix_helix`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_USER` |

### Cloud (control plane / posture)

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| AWS Security Hub (`aws_security_hub`) | — | — | `PULL_ALERTS` |
| Azure Activity Logs (`azure_activity`) | ✅ | — | `PULL_AUDIT` |
| GCP Cloud Audit Logs (`gcp_cloud_audit`) | — | — | `PULL_AUDIT` |
| GCP Security Command Center (`gcp_scc`) | — | — | `PULL_ALERTS` |
| Lacework (`lacework`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_HOST`, `PIVOT_IP`, `ENRICH_VULN` |
| Tenable.io (`tenable_io`) | — | — | `PULL_ALERTS`, `PIVOT_HOST`, `PIVOT_IP`, `ENRICH_VULN`, `ENRICH_ASSET` |
| Wiz (`wiz`) | — | — | `PULL_ALERTS` |

### SaaS

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| Cloudflare (`cloudflare`) | — | — | `PULL_AUDIT` |
| Email Inbox / IMAP (`email_inbox`) | — | — | `PULL_ALERTS` |
| Google Workspace (`google_workspace`) | — | — | `PULL_AUDIT` |
| Jira (`jira`) | ✅ | — | `PULL_ALERTS`, **`PUSH_CASE`**, **`PUSH_STATUS`** |
| Microsoft 365 Audit (`m365_audit`) | ✅ | — | `PULL_AUDIT` |
| Mimecast (`mimecast`) | — | — | `PULL_ALERTS`, `PULL_AUDIT`, `PIVOT_USER`, `ENRICH_DOMAIN` |
| Proofpoint TAP (`proofpoint`) | — | — | `PULL_ALERTS` |
| Salesforce (`salesforce`) | ✅ | — | `PULL_AUDIT`, `QUERY_LOGS`, `PIVOT_USER`, `READ_AUDIT_TRAIL` |
| ServiceNow (`servicenow`) | — | — | `PULL_ALERTS`, **`PUSH_CASE`**, **`PUSH_STATUS`** |
| Slack Audit (`slack_audit`) | ✅ | — | `PULL_AUDIT`, `PIVOT_USER`, `READ_AUDIT_TRAIL` |

### VCS / AppSec

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| GitHub (`github`) | ✅ | — | `PULL_AUDIT`, `PULL_ALERTS` |
| Snyk (`snyk`) | — | — | `PULL_ALERTS` |

### Network

| Connector | OAuth (hosted) | Federated search | Capabilities |
|---|---|---|---|
| Cisco Umbrella (`cisco_umbrella`) | — | — | `PULL_ALERTS`, `QUERY_LOGS`, `PIVOT_DOMAIN`, `PIVOT_IP`, `ENRICH_DOMAIN` |
| Tailscale (`tailscale`) | — | — | `PULL_AUDIT` |
| Zscaler Internet Access (`zscaler`) | — | — | `PULL_ALERTS` |

## How the orchestrator uses this

Three subsystems read this matrix at runtime:

1. **The agent runtime.** Before an agent calls a connector tool, it checks `connector.capabilities()`. If the agent wants to ask "isolate this host," and the only EDR connected for that tenant is one that does not declare `ISOLATE_HOST`, the tool is hidden from the model's tool list — the model never sees a button it cannot push.
2. **The federated-search planner.** A natural-language query is translated into per-vendor DSLs only for connectors that declare `QUERY_LOGS`. SIEMs without that capability are skipped silently.
3. **The case fan-out service** (`services/api/app/services/case_fanout.py`). When an AiSOC case is created or its status changes, the fan-out service iterates connector instances filtered by `PUSH_CASE` / `PUSH_STATUS` and calls them in turn. A connector without those capabilities is invisible to the ITSM projection layer — see [ITSM as source of truth](/docs/architecture/itsm-as-source-of-truth) for the full lifecycle.

## Adding a capability to a connector

If you are extending an existing connector to do more (e.g. teaching SentinelOne to `ISOLATE_HOST`):

1. Implement the corresponding method on the connector class (`isolate_host`, `push_case`, `query_logs`, etc.). The base contracts live in `services/connectors/app/connectors/base.py`.
2. Add the new value to the connector's `capabilities()` classmethod.
3. Add a focused unit test under `services/connectors/tests/` — happy path, error path, and one vendor-specific edge case (status mapping, ID resolution, transitions).
4. Update this page so the matrix stays honest. The capability column is the contract the rest of the system relies on; if the matrix says `ISOLATE_HOST`, the runtime will route isolation requests to that connector.

The full method signatures and contracts are in [`base.py`](https://github.com/AiSOC-community/AiSOC/blob/main/services/connectors/app/connectors/base.py); for end-to-end ITSM examples see the [Jira](/docs/connectors/) and [ServiceNow](/docs/connectors/) connector docs (per-vendor walkthroughs).
