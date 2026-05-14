---
sidebar_position: 73
title: PagerDuty
description: Pull PagerDuty incident lifecycle and audit-record events into AiSOC via the REST API.
---

# PagerDuty

The PagerDuty connector pulls two streams from a single PagerDuty tenant:

1. **Incidents** — `GET /incidents` returns the full incident lifecycle (`triggered → acknowledged → resolved`) with `urgency` (`high / low`) and an optional `priority` (`P1..P5`).
2. **Audit records** — `GET /audit/records` returns the tenant audit trail: user role changes, service config edits, API key issuance, webhook subscription create/delete.

Events are normalised with `source: pagerduty`, `category: saas`.

## Prerequisites

- A **PagerDuty account** on any plan that includes API access (Professional, Business, Enterprise, or Digital Operations).
- A **REST API key**. Two variants:
  - **General-access key** — tenant-scoped, can read incidents but not the audit log.
  - **User-level key** — paired to a specific user; *the user must be an Account Owner or Account Admin* to read `/audit/records`.
- Both variants are generated under **Integrations → API Access Keys**.

## Setup walkthrough

### 1. Create the API key

1. **Integrations → API Access Keys → Create API User Token** (or "Create General Access Key").
2. **Read-only** is sufficient — the connector never writes to PagerDuty.
3. Copy the token (PagerDuty does not show it again).

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → PagerDuty**.
2. `api_key` = the REST API key (encrypted in the credential vault).
3. `subdomain` *(optional)* = the `acme` part of `acme.pagerduty.com`. Used to build clickable links in normalised events.
4. **Test connection** — probes `GET /users/me` first (user-level key); falls back to `GET /incidents?limit=1` for general-access keys.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `GET /incidents?limit=100&since=<since>&sort_by=incident_number:desc&statuses[]=triggered,acknowledged,resolved` — paginates with classic `offset` + `more`.
  - `GET /audit/records?limit=100&since=<since>` — paginates with the opaque `next_cursor` field.
- Pagination terminates when `more=false` (incidents) or `next_cursor` is empty (audit).

## Severity mapping

Vendor signals collapse to the AiSOC 4-tier ladder per the wave-1 PagerDuty rule:

| Source | Vendor value | AiSOC severity |
|---|---|---|
| incident | priority name `P1` or `critical` | `high` |
| incident | priority name `P2` or `error` | `medium` |
| incident | priority name `P3` or `warning` / `warn` | `low` |
| incident | priority name `P4` / `P5` / `info` | `low` / `info` |
| incident | no priority, urgency `high` | `high` |
| incident | no priority, urgency `low` | `low` |
| incident | `status = resolved` | collapses to `info` |
| audit | `user.role_changed` / `user.create` / `user.delete` | `high` |
| audit | `api_key.create` / `api_key.delete` | `high` |
| audit | `extension.create` / `extension.delete` | `high` |
| audit | `webhook_subscription.create` / `webhook_subscription.delete` | `high` |
| audit | `service.delete` / `escalation_policy.delete` | `high` |
| audit | other `*.delete` / `*.destroyed` | `medium` |
| audit | other operations | `info` |

## Troubleshooting

**`HTTP 401`** — the key is invalid or revoked. If you used a general-access key against the audit endpoint, you'll see `401` on `/audit/records` even though `/incidents` works. Switch to a user-level key from an Account Owner.

**`HTTP 403` on audit** — auth is fine but the user lacks the **Account Owner** or **Account Admin** role required to read the audit log. Adjust the user's role or use a different account.

**Resolved incidents flooding the timeline** — by design the connector pulls resolved incidents but collapses them to severity `info`. If you want to drop them entirely, add a downstream filter in the alert-fusion pipeline.

## What this connector does **not** cover

- **Triggering pages from AiSOC** — that's the PagerDuty Paging action plugin (a separate write-mode integration, doc page TBD).
- **Per-incident log entry stream** — only the top-level incident envelope is pulled. The fine-grained "log_entries" stream is a separate endpoint and deliberately omitted from wave-1 to avoid quota pressure.

## Related

- [Opsgenie](/docs/connectors/opsgenie) — sibling on-call platform with the same audit surface.
- PagerDuty Paging — outbound paging action plugin (write-mode counterpart, doc page TBD).
