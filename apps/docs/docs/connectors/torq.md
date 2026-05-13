---
sidebar_position: 71
title: Torq
description: Pull Torq workflow execution outcomes and audit events into AiSOC via the Public API.
---

# Torq

The Torq connector pulls two streams from a single Torq tenant:

1. **Workflow executions** — per-run outcomes for every workflow the API key can see, with status (`success / warning / failed / killed / running`) and timing data.
2. **Audit log events** — workflow create / edit / delete, integration credential changes, user role changes, API token issuance.

Events are normalised with `source: torq`, `category: saas`.

## Prerequisites

- A **Torq tenant** on the SaaS platform (`api.torq.io`) or a regional / self-hosted deployment.
- An **API key pair** (`key_id` + `key_secret`) issued under **Settings → API Keys**.
- The key pair is exchanged for a short-lived bearer token at `https://api.torq.io/auth/v1/token`; the connector handles refresh automatically.

## Setup walkthrough

### 1. Create the API key

1. **Settings → API Keys → New key**.
2. **Scope**: choose read-only / observer if available; the connector only reads.
3. Copy `key_id` and `key_secret` immediately — Torq does not show the secret again.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Torq**.
2. `key_id` = the API Key ID.
3. `key_secret` = the API Key Secret (encrypted in the credential vault).
4. `base_url` *(optional)* = override only for regional or self-hosted deployments; defaults to `https://api.torq.io/public/v1`.
5. **Test connection** → exchanges the key pair for a bearer token, then probes `GET /workflows?page_size=1`.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls:
  - `POST /auth/v1/token` (token exchange).
  - `GET /workflows/executions?page_size=100&started_after=<since>` — server-side time filter on execution start.
  - `GET /audit-logs?page_size=100&from=<since>` — server-side time filter on event timestamp.
- Pagination follows the `next_page_token` cursor on both streams, up to **20 pages per stream per poll**.

## Severity mapping

| Source | Vendor value | AiSOC severity |
|---|---|---|
| execution | `success` / `completed` / `running` | `info` |
| execution | `warning` / `warn` | `low` |
| execution | `failed` / `error` / `killed` / `critical` | `high` |
| audit | `workflow.deleted` / `workflow.disabled` | `high` |
| audit | `credential.created` / `credential.deleted` / `credential.updated` | `high` |
| audit | `user.role_changed` / `user.invited` / `user.removed` | `high` |
| audit | `api_key.created` / `api_key.revoked` | `high` |
| audit | `integration.created` / `integration.deleted` / `sso.disabled` | `high` |
| audit | other `*.deleted` / `*.destroyed` | `medium` |
| audit | `*.failed` | `low` |
| audit | other operations | `info` |

## Troubleshooting

**`torq auth failed: HTTP 401`** — the key pair is invalid or revoked. Regenerate at **Settings → API Keys** and rotate via the AiSOC connector edit screen. Torq does *not* return a useful body on auth failures; the only signal is the 401 itself.

**Empty executions** — confirm the API key's scope includes the target workflows. Some Torq tenants enforce a per-workflow access list; the API key must be granted explicit access.

**Audit events lag** — Torq batches audit events server-side; expect a small delay (~ 1–2 minutes) between an admin action and its appearance on `/audit-logs`. This is normal.

## What this connector does **not** cover

- **Workflow step output** — only the execution outcome is pulled, not the per-step input/output payloads.
- **Webhook receive mode** — Torq outbound webhooks are an alternative push-based channel; this connector is pull-only.

## Related

- [Tines](/docs/connectors/tines) — sibling SOAR platform with comparable workflow + audit semantics.
