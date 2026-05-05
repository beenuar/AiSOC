---
sidebar_position: 6
title: GCP Security Command Center
description: Posture and threat findings from Google Cloud Security Command Center (SCC) into AiSOC.
---

# GCP Security Command Center

The SCC connector pulls **findings** from Google Cloud Security Command Center — vulnerabilities, misconfigurations, threats, and posture violations across the GCP organization — into AiSOC.

## What you get

- **Vulnerability** findings (CVEs, exposed credentials, public buckets)
- **Misconfiguration** findings from Security Health Analytics
- **Threat** findings from Event Threat Detection (anomalous IAM behavior, brute force, crypto mining)
- **Posture** findings from Posture Management

Events are normalized with `category: cloud_posture` (vulnerability/misconfig) or `category: threat` (threat).

## Prerequisites

- **Security Command Center** enabled at the **organization** level. Project-level SCC does not expose the API used here.
- An **Organization ID** (the numeric one — find it in `gcloud organizations list`).
- A **service account** with the **Security Center Findings Viewer** role (`roles/securitycenter.findingsViewer`) at the **organization** scope.
- The **JSON key** for that service account.

## Setup walkthrough

### 1. Confirm SCC is on

`gcloud scc settings services list --organization=<ORG_ID>` — you should see `SECURITY_HEALTH_ANALYTICS`, `EVENT_THREAT_DETECTION`, etc. enabled. If not, [enable SCC Standard or Premium](https://cloud.google.com/security-command-center/docs/quickstart-scc-setup) at the org level.

### 2. Create the service account

1. **GCP Console → IAM & Admin → Service Accounts** in any project (we recommend a dedicated `security-tools` project).
2. **Create service account** → name `aisoc-scc-reader`.

### 3. Grant org-level access

1. **Console → IAM & Admin → IAM** at the **organization** level (use the org switcher).
2. **Grant access** → principal = the new service account email → role = **Security Center Findings Viewer**.

This must be at the **organization** level, not at a project level. SCC findings are an org-scoped resource.

### 4. Mint the JSON key and add to AiSOC

1. Service account → **Keys → Add key → Create new key → JSON**.
2. **AiSOC → Connectors → Add connector → GCP Security Command Center**.
3. `organization_id` = the numeric org ID (e.g. `123456789012`, not `example.com`).
4. `service_account_json` = paste the JSON.
5. **Test connection** → calls `findings.list` with `pageSize=1` against the org.
6. **Save**.

## Polling details

- Default interval: **600 seconds** (10 min). SCC findings update slower than audit logs and the API has tight quotas.
- Filter: `state="ACTIVE" AND eventTime > "{since}"` — only currently-active findings, not muted/resolved ones.

## Severity mapping

SCC carries explicit severity; AiSOC uses it directly:

| SCC severity | AiSOC severity |
|---|---|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| unset | `low` |

`category` mapping:

| SCC `findingClass` | AiSOC category |
|---|---|
| `THREAT` | `threat` |
| `VULNERABILITY` | `cloud_posture` |
| `MISCONFIGURATION` | `cloud_posture` |
| `OBSERVATION`, `SCC_ERROR` | `cloud_posture` |

## Troubleshooting

**`PERMISSION_DENIED: ... does not have securitycenter.findings.list ... on organization ...`** — the service account does not have **org-level** access. Re-grant at the org IAM page (not at any project).

**`NOT_FOUND: Organization "organizations/123456789012" was not found`** — wrong org ID, or SCC has never been enabled at the org. Run `gcloud scc settings describe --organization=<ORG_ID>` to confirm.

**Empty findings on a known-vulnerable org** — verify findings exist via `gcloud scc findings list organizations/<ORG_ID>`. If the CLI works but the connector returns zero, check that `state="ACTIVE"`; the connector deliberately filters out muted findings.

## Related

- [GCP Cloud Audit Logs](/docs/connectors/gcp-cloud-audit) — pair these two for full GCP coverage. SCC tells you what's wrong; Cloud Audit tells you who/what changed.
- [Credential vault](/docs/operations/credentials)
