---
sidebar_position: 74
title: Opsgenie
description: Pull Opsgenie alerts and tenant audit log events into AiSOC via the REST API.
---

# Opsgenie

The Opsgenie connector pulls two streams from a single Opsgenie tenant:

1. **Alerts** — `GET /v2/alerts` lists active and recently closed alerts with the vendor `priority` ladder (`P1..P5`) and `status` (`open / acknowledged / closed`).
2. **Audit logs** — `GET /v2/audit-logs?type=customer` exposes the tenant audit trail: API key issuance, role changes, integration create/delete, escalation policy edits.

Events are normalised with `source: opsgenie`, `category: saas`.

## Prerequisites

- An **Opsgenie account** on any paid plan (API access is not in the free tier).
- An **API key** issued under **Settings → Integration List → API**. Tenant administrators only.
- Knowledge of your **data residency region**: US (`api.opsgenie.com`) or EU (`api.eu.opsgenie.com`). Opsgenie does not auto-route between regions.

## Setup walkthrough

### 1. Create the API integration

1. **Settings → Integration List → API → Add integration**.
2. **Read Access**: tick. **Create/Update/Delete Access**: leave off — the connector is read-only.
3. **Access Configuration**: tick **Read Audit Logs** if you want the audit stream (recommended).
4. Copy the API key (a UUID).

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Opsgenie**.
2. `api_key` = the API key (encrypted in the credential vault).
3. `region` = `us` or `eu` to match your Opsgenie account.
4. **Test connection** — probes `GET /v2/account` and returns the account name + plan.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `GET /v2/alerts?limit=100&query=createdAt+%3E+<ms>+OR+updatedAt+%3E+<ms>&sort=createdAt&order=desc` — Lucene-style time filter against ms-since-epoch.
  - `GET /v2/audit-logs?limit=100&createdAtStart=<iso8601>&type=customer`
- Pagination follows the `paging.next` URL that Opsgenie returns; the connector calls it without re-attaching query params because the URL already carries the cursor.

## Severity mapping

| Source | Vendor value | AiSOC severity |
|---|---|---|
| alert | priority `P1` | `high` |
| alert | priority `P2` | `medium` |
| alert | priority `P3` / `P4` | `low` |
| alert | priority `P5` | `info` |
| alert | `status = closed` | collapses to `info` |
| audit | `ApiIntegrationCreated` / `ApiIntegrationDeleted` | `high` |
| audit | `ApiKeyCreated` / `ApiKeyDeleted` | `high` |
| audit | `UserRoleChanged` / `UserAdded` / `UserDeleted` | `high` |
| audit | `EscalationPolicyDeleted` / `TeamDeleted` | `high` |
| audit | `WebhookCreated` / `WebhookDeleted` / `IntegrationDisabled` | `high` |
| audit | actions ending `Deleted` / `Disabled` | `medium` |
| audit | other operations | `info` |

## Troubleshooting

**`HTTP 401`** — the API key is invalid or scoped to a different region. Opsgenie does *not* return a helpful body on auth failures; the only signal is the 401. Recreate the key on the correct region.

**`HTTP 422` on `/v2/alerts`** — the Lucene query has invalid syntax. This usually means the `since_seconds` window resolved to a non-numeric `ms` value; check your system clock and that the connector isn't running with a pre-1970 default.

**Audit endpoint empty** — confirm the integration has the **Read Audit Logs** access tick set. The base API key permission does not include audit access by default.

## What this connector does **not** cover

- **Outbound paging actions** — Opsgenie alert creation from AiSOC is a separate write-mode plugin (planned, not in wave-1).
- **Schedule on-call lookups** — `/v2/schedules` is intentionally omitted from polling; that data is fetched on-demand by the agent layer when investigating an alert.

## Related

- [PagerDuty](/docs/connectors/pagerduty) — sibling on-call platform with the same audit surface.
