---
sidebar_position: 19
title: Prisma Cloud
description: Prisma Cloud (Palo Alto Networks) cloud security alerts across CSPM, CWPP, CIEM, and DSPM into AiSOC via the unified /alert/v1/alert API.
---

# Prisma Cloud

The Prisma Cloud connector pulls **open security alerts** from a Prisma
Cloud tenant into AiSOC. One connector instance covers every Prisma Cloud
surface — **CSPM**, **CWPP**, **CIEM**, and **DSPM** — because the
`/alert/v1/alert` REST endpoint aggregates findings across all of them.
There is no per-product configuration to babysit.

## What you get

| Source | Prisma Cloud endpoint | Notes |
|---|---|---|
| Alerts | `POST /alert/v1/alert` | All open alerts, last poll window, sorted newest first |

Events are normalized with `source: prisma_cloud` and the original
Prisma Cloud envelope is preserved on `raw_event` so playbooks can target
specific alert categories (e.g. policy type, finding subtype).

## Prerequisites

- A **Prisma Cloud tenant** with admin or System Admin access.
- A Prisma Cloud **access key pair**:
  - `accessKeyId` — the access-key ID (UUID-formatted).
  - `secretKey` — the matching secret.
- Your **region-specific API endpoint** (e.g. `https://api.prismacloud.io`,
  `https://api2.eu.prismacloud.io`, `https://api.gov.prismacloud.io`).
  Find it in **System → API Endpoints** in the Prisma Cloud console.

Access keys are created in the Prisma Cloud console under **Settings →
Access Control → Access Keys → Add New**. Copy the secret immediately —
Prisma Cloud only shows it once.

## Setup walkthrough

### 1. Create the access key

1. In the Prisma Cloud console, **Settings → Access Control → Access
   Keys → Add New**.
2. Name the key `aisoc-prod` (or similar) and pick an expiry — match it
   to your secrets-rotation policy.
3. Copy the **Access Key ID** and **Secret Key** to a password manager.
4. Confirm the **role** attached to the key has at least read access to
   the `Alerts` resource. The built-in `System Admin` and `Account Group
   Admin` roles work; for least-privilege, create a custom role with the
   `Alerts: View` permission only.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Prisma Cloud**.
2. **API URL** — paste the region-specific value from
   **System → API Endpoints** (e.g. `https://api.prismacloud.io`).
3. **Access Key ID** and **Secret Key** — paste from step 1.
4. **Compute API URL** — leave blank. AiSOC only consumes the unified
   `/alert` endpoint, which already includes runtime findings collapsed
   in from Compute (Twistlock).
5. **Test connection** — AiSOC exchanges the access keys for a
   short-lived JWT via `POST /login` and confirms a successful auth.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll calls `POST /login` to mint a fresh JWT. Prisma Cloud tokens
  have a sliding TTL and re-auth is cheap; doing it every poll avoids
  cache-invalidation bugs around expiry windows.
- The poll requests **alerts in the last `interval` seconds** with
  `timeRange.type = "absolute"` and a `startTime`/`endTime` pair in
  epoch milliseconds.
- Only alerts with `status = "open"` are pulled. Resolved /
  snoozed / dismissed alerts are filtered out at the source.
- Result set is capped at 200 alerts per poll. If your tenant routinely
  emits more than that in 5 minutes, lower the polling interval rather
  than raising the cap — it keeps each request well within Prisma
  Cloud's API timeout.

## Severity mapping

Prisma Cloud uses a 4-tier severity ladder. AiSOC maps directly into the
canonical 4-tier set:

| Prisma Cloud severity | AiSOC severity |
|---|---|
| `critical` | `high` |
| `high` | `high` |
| `medium` | `medium` |
| `low` | `low` |
| `informational` | `info` |

`critical` collapses into `high` because AiSOC does not expose a
separate critical band. The original tier is preserved under
`raw_event.policy.severity` so playbooks that need to distinguish
`critical` vs `high` still can.

## Coverage breakdown

The unified `/alert` endpoint includes findings from every Prisma Cloud
module you license:

| Module | What you'll see in AiSOC |
|---|---|
| **CSPM** (Cloud Security Posture) | Misconfigured S3 buckets, public DBs, IAM drift, network exposure |
| **CWPP** (Workload Protection) | Vulnerable images, runtime drift, host posture findings |
| **CIEM** (Identity & Entitlements) | Over-privileged identities, unused permissions, role-chain risks |
| **DSPM** (Data Security Posture) | Sensitive data exposure, classification findings, data-flow risks |

If a module isn't licensed on the tenant, no alerts of that type appear
— there is nothing to disable in AiSOC.

## Live actions

The Prisma Cloud connector is **read-only** as of v7.3.1. Containment for
cloud findings flows through the
[AWS Security Hub](/docs/connectors/aws-security-hub),
[AWS GuardDuty](/docs/connectors/aws-guardduty),
[Cloudflare](/docs/connectors/cloudflare), or
[GCP Cloud Audit](/docs/connectors/gcp-cloud-audit) connectors.

## Troubleshooting

**`could not exchange access keys for prisma cloud JWT`** — the
`accessKeyId` / `secretKey` pair is wrong, the access key has expired,
or the API URL points to a different region than the tenant. Test
directly:

```bash
curl -X POST "https://api.prismacloud.io/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"YOUR_ACCESS_KEY_ID","password":"YOUR_SECRET"}'
```

A 200 response with `{ "token": "..." }` confirms the credentials are
good — the issue is then in the AiSOC field values (most often, wrong
region URL).

**`HTTP 403` on `/alert/v1/alert`** — the role attached to the access
key lacks `Alerts: View`. Check **Settings → Access Control → Access
Keys → \<your key\> → Role** and confirm the role has the permission.

**`events_added: 0` between polls** — the tenant generated no new
**open** alerts in the last 5 minutes. Resolved / snoozed alerts are
filtered out at the source by the `alert.status = "open"` filter; that
is expected steady state for a quiet tenant.

**Tenant in EU / Gov region not returning data** — confirm the API URL
matches the region. EU tenants use `api2.eu.prismacloud.io`, Gov uses
`api.gov.prismacloud.io`. The console URL is **not** the API URL.

## Related

- [Wiz](/docs/connectors/wiz) — alternative CNAPP path with broader
  cloud-graph context.
- [Lacework](/docs/connectors/lacework) — alternative CNAPP focused on
  workload + compliance.
- [AWS Security Hub](/docs/connectors/aws-security-hub) — native AWS
  finding aggregation for AWS-only deployments.
