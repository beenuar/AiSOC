---
sidebar_position: 20
title: Orca Security
description: Orca Security CNAPP alerts across workload, container, cloud configuration, identity, and data risk surfaces into AiSOC via the unified /api/alerts API.
---

# Orca Security

The Orca Security connector pulls **open security alerts** from an Orca
tenant into AiSOC. One connector instance covers every Orca surface —
**workload**, **container**, **cloud configuration (CSPM)**, **identity
(CIEM)**, and **data risk (DSPM)** — because the `/api/alerts` REST
endpoint aggregates findings across all of them. There is no per-product
configuration to babysit.

## What you get

| Source | Orca endpoint | Notes |
|---|---|---|
| Alerts | `GET /api/alerts` | Open alerts only, last poll window |

Events are normalized with `source: orca` and the original Orca alert
envelope is preserved on `raw_event` so playbooks can target specific
finding categories (e.g. `IAM`, `Vulnerability`, `Misconfiguration`).

## Prerequisites

- An **Orca Security tenant** with an admin or auditor-class user.
- An Orca **API token** scoped to read alerts. Tokens are minted in the
  Orca console under **Settings → Users & Permissions → API Tokens →
  Create Token**.

API tokens are long-lived; copy the secret immediately — Orca only
shows it once.

## Setup walkthrough

### 1. Create the API token

1. In the Orca console, **Settings → Users & Permissions → API Tokens →
   Create Token**.
2. Name the token `aisoc-prod` (or similar) and set an expiry — match it
   to your secrets-rotation policy.
3. Assign the role **Auditor** (read-only) or higher. Auditor is
   sufficient for alert ingestion.
4. Copy the token value to a password manager.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Orca Security**.
2. **API Token** — paste the token from step 1.
3. **API URL** — leave blank unless you're on a region-specific
   endpoint. The default `https://api.orcasecurity.io` works for the
   standard commercial cloud.
4. **Test connection** — AiSOC calls `GET /api/user/session` to confirm
   the token is valid and live.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll requests alerts opened in the last `interval` seconds via
  `start_at_gte` (ISO-8601).
- Only alerts with `status = "open"` are pulled. Resolved / dismissed
  alerts are filtered out at the source.
- Result set is capped at 200 alerts per poll. If your tenant routinely
  emits more than that in 5 minutes, lower the polling interval rather
  than raising the cap — it keeps each request well within Orca's API
  timeout.

## Severity mapping

Orca uses a 5-tier severity ladder. AiSOC's canonical ladder is 4-tier:

| Orca severity | AiSOC severity |
|---|---|
| `hazardous` | `high` |
| `imminent_compromise` | `high` |
| `critical` | `high` |
| `high` | `high` |
| `medium` | `medium` |
| `low` | `low` |
| `informational` | `info` |

`hazardous` is Orca-internal terminology for "actively exploited" and is
unambiguously high-impact, so it collapses into `high`. The original
tier is preserved under `raw_event.state.severity` so playbooks that
need to distinguish `hazardous` vs `critical` vs `high` still can.

## Coverage breakdown

The unified `/api/alerts` endpoint includes findings from every Orca
module you license:

| Module | What you'll see in AiSOC |
|---|---|
| **Workload** | Vulnerable packages, malware, runtime drift, exposed secrets in workloads |
| **Container / Kubernetes** | Image vulnerabilities, runtime risks, K8s misconfig |
| **CSPM** | Misconfigured S3 buckets, public DBs, IAM drift, network exposure |
| **CIEM** | Over-privileged identities, unused permissions, role-chain risks |
| **DSPM** | Sensitive data exposure, data-flow risks, compliance breaches |

If a module isn't licensed on the tenant, no alerts of that type appear
— there is nothing to disable in AiSOC.

## Live actions

The Orca connector is **read-only** in v7.1.0. Containment for cloud
findings flows through the
[AWS Security Hub](/docs/connectors/aws-security-hub),
[AWS GuardDuty](/docs/connectors/aws-guardduty),
[Cloudflare](/docs/connectors/cloudflare), or
[GCP Cloud Audit](/docs/connectors/gcp-cloud-audit) connectors.

## Troubleshooting

**`orca auth failed: HTTP 401`** — the API token is wrong, expired, or
revoked. Test directly:

```bash
curl https://api.orcasecurity.io/api/user/session \
  -H "Authorization: Token YOUR_TOKEN"
```

A 200 response with a JSON session body confirms the token is good — the
issue is then in the AiSOC field value.

**`orca auth failed: HTTP 403`** — the token's role does not have
permission to read alerts. Reassign the token to **Auditor** or higher
in **Settings → Users & Permissions → API Tokens → Edit**.

**`events_added: 0` between polls** — the tenant generated no new
**open** alerts in the last 5 minutes. Resolved alerts are filtered out
at the source by the `status = "open"` filter; that is expected steady
state for a quiet tenant.

**Tenant on a region-specific endpoint** — set the **API URL** field to
the regional value (e.g. `https://api.eu.orcasecurity.io`). The console
URL is **not** the API URL.

## Related

- [Wiz](/docs/connectors/wiz) — alternative CNAPP path with broader
  cloud-graph context.
- [Prisma Cloud](/docs/connectors/prisma-cloud) — alternative CNAPP from
  Palo Alto Networks.
- [Lacework](/docs/connectors/lacework) — alternative CNAPP focused on
  workload + compliance.
- [AWS Security Hub](/docs/connectors/aws-security-hub) — native AWS
  finding aggregation for AWS-only deployments.
