---
sidebar_position: 70
title: Tines
description: Pull Tines story audit log + case lifecycle events into AiSOC via the REST API.
---

# Tines

The Tines connector pulls two streams from a single Tines tenant:

1. **Story / agent audit events** — admin actions on tenants, stories, agents, credentials, and team membership. This is the audit trail for *configuration* changes (who edited a story, who rotated a credential).
2. **Case events** — the cases produced by stories, with status (`open / in_progress / closed`) and a vendor-side record severity (`info / warn / error / critical`).

Events are normalised with `source: tines`, `category: saas`.

## Prerequisites

- A **Tines tenant** (Cloud or self-hosted).
- A **Personal Access Token** with the `read_only` role. The token is created under **Profile → Personal Access Tokens** on the Tines UI.
- For self-hosted deployments, the full HTTPS URL of the Rails app (e.g. `https://tines.internal.acme.io`).

## Setup walkthrough

### 1. Create the token

1. Log in to Tines as the operator account.
2. **Profile → Personal Access Tokens → New token**.
3. **Role**: `read_only` (sufficient for both `audit_logs` and `cases` endpoints).
4. **Expiration**: ≤ 180 days, rotate from the AiSOC edit screen.
5. Copy the token (`tines_pat_…`) — Tines does not show it again.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Tines**.
2. `base_url` = your tenant URL with scheme (e.g. `https://acme.tines.com`).
3. `api_token` = the personal access token (encrypted in the credential vault).
4. `team_id` *(optional)* = scope ingestion to a single Team; leave blank for tenant-wide.
5. **Test connection** → calls `GET /api/v1/users/info` to verify the token resolves to a real user.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `GET /api/v1/audit_logs?per_page=100&page=N` — paginates admin events, sorted desc by `created_at`. The connector stops early once it crosses the poll window.
  - `GET /api/v1/cases?per_page=100&modified_after=<since>&page=N` — server-side time filter on the cases index.
- Pagination uses the `meta.next_page` cursor; the connector follows it up to **20 pages per stream per poll** as a runaway guard.

## Severity mapping

The Tines case `record_severity` and audit `operation_name` collapse into the AiSOC 4-tier ladder:

| Source | Vendor value | AiSOC severity |
|---|---|---|
| audit | `credential.created` / `credential.deleted` / `tenant.api_key_*` | `high` |
| audit | `story.deleted` / `story.disabled` / `tenant.sso_disabled` | `high` |
| audit | `team.member_role_changed` / `team.member_added` / `team.member_removed` | `high` |
| audit | other `*.deleted` / `*.destroyed` | `medium` |
| audit | `*.failed` | `low` |
| audit | all other operations | `info` |
| case | `record_severity = critical / error / high` | `high` |
| case | `record_severity = warn / warning` | `low` |
| case | `record_severity = medium` | `medium` |
| case | `record_severity = info / success / ok` | `info` |
| case | `status = closed` and `resolution ∈ {resolved, closed, completed}` | collapses to `info` regardless |

## Troubleshooting

**`401 Unauthorized`** — token is invalid, revoked, or for a different tenant. Personal access tokens are tenant-scoped; pasting a token from a sibling Tines workspace will fail this way.

**Empty audit log** — the token is read-only at the *user* scope rather than the *tenant* scope. Tines requires a token from a user with **Admin** or **Team Admin** role to read tenant audit events. Recreate the token from an admin account.

**Cases not appearing** — confirm the optional `team_id` filter isn't excluding them. The `modified_after` filter only includes cases that have changed since the poll window opened; long-idle cases will not re-emit.

## What this connector does **not** cover

- **Story-execution event detail** — only audit metadata is pulled, not the per-step input/output of a story run.
- **Webhook signing verification** — Tines outbound webhooks are signed but this connector is pull-only; webhook verification will land as a follow-on capability.

## Related

- [Torq](/docs/connectors/torq) — sibling SOAR platform with comparable workflow + audit semantics.
