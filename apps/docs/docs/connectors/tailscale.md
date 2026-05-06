---
sidebar_position: 11
title: Tailscale
description: Zero-trust network audit logs from Tailscale into AiSOC — ACL changes, device approvals, key rotations, and more.
---

# Tailscale

The Tailscale connector pulls administrative audit logs from your tailnet via the [Tailscale API v2](https://tailscale.com/api).

Two conceptual streams are ingested:

1. **Administrative audit log** — every action taken in the admin console or via the API: ACL/policy changes, device approvals and removals, key rotations, user role and tag changes, subnet router and exit-node approvals, OIDC/SAML configuration mutations, DNS updates, and webhook CRUD operations.
2. **ACL policy diff events** — `acl:update` events are surfaced at **HIGH** severity because ACL changes are a common lateral-movement enabler in zero-trust networks.

Events are normalized with `source: tailscale`, `category: network`.

## Prerequisites

- A **Tailscale organization** account (Starter, Premium, or Enterprise). The audit log API is available on all paid plans; the free personal plan may have limited history.
- One of the following authentication options:
  - **API key** (starts with `tskey-api-`): simplest for development and small deployments. Long-lived; revoke and rotate via the Tailscale admin console.
  - **OAuth 2.0 client credentials** (client ID + client secret): preferred for production. Grants a short-lived, auto-refreshed token. Requires the `audit:read` OAuth scope.

## Setup walkthrough

### Option A — API Key

1. Go to **Tailscale admin console → Settings → Keys**.
2. Click **Generate API key**.
3. Copy the key (it starts with `tskey-api-…`) — you will not be able to see it again.
4. In AiSOC, go to **Connectors → Add connector → Tailscale**.
5. Fill in:
   - **Tailnet**: your organisation slug or email (e.g. `example.com`). Use `-` to auto-detect from the key.
   - **API Key**: paste the key.
6. Click **Test connection**, then **Save**.

### Option B — OAuth Client Credentials (production)

1. Go to **Tailscale admin console → Settings → OAuth clients**.
2. Click **Generate OAuth client**.
3. Grant the **`audit:read`** scope.
4. Copy the **Client ID** and **Client Secret**.
5. In AiSOC, go to **Connectors → Add connector → Tailscale**.
6. Fill in:
   - **Tailnet**: your organisation slug.
   - **OAuth Client ID**: paste the client ID.
   - **OAuth Client Secret**: paste the secret (stored encrypted in the credential vault).
7. Click **Test connection**, then **Save**.

The connector automatically refreshes the access token before expiry — no manual rotation required.

## Polling details

- Default interval: **300 seconds**.
- Per poll, the connector calls `GET /api/v2/tailnet/{tailnet}/audit?startTime=<lastpoll>` with cursor-based pagination.
- The `startTime` parameter is set to `now() - poll_interval` on each run. For the very first run, the connector looks back 5 minutes.
- Cursor pagination continues until no `nextCursor` is returned, ensuring no events are dropped between polls.

## Severity heuristics

| Action | Severity |
|---|---|
| `acl:update` — policy/ACL file modified | `high` |
| `acl:delete` | `high` |
| `device:approve`, `device:delete`, `device:expire_key` | `high` |
| `routes:approve`, `routes:set_advertised` | `high` |
| `auth_key:create`, `auth_key:delete` | `high` |
| `user:invite`, `user:delete`, `user:role_update` | `high` |
| `oidc:update`, `saml:update` | `high` |
| `tailnet:transfer_ownership`, `tailnet:delete` | `high` |
| `webhook:create`, `webhook:update`, `webhook:delete` | `high` |
| `settings:update`, `logging:set_config` | `high` |
| `device:update`, `tag:update` | `medium` |
| `posture:create`, `posture:update`, `posture:delete` | `medium` |
| Any `*:delete` or `*:remove` not already mapped | `medium` |
| Everything else | `info` |

## Troubleshooting

**`403 Forbidden` on audit endpoint** — the token or OAuth client is missing the `audit:read` scope. Create a new API key / OAuth client with the correct scope; you cannot patch scopes on an existing credential.

**Empty results** — the selected tailnet name may be incorrect. Try using `-` to auto-resolve from the token, then update the tailnet field to the resolved name shown in test-connection output.

**OAuth token refresh errors** — verify that the client secret has not been revoked in the Tailscale admin console. Re-generate and update the connector config.

**Short audit log history** — Tailscale retains audit logs according to your plan's data retention policy. Events older than the retention window will not appear regardless of the `startTime` value sent.

## False positives

- Misconfigured CI/CD runners that trigger ACL validation via the Tailscale CLI.
- Automated key rotation scripts that cycle `auth_key` or `tailnet_key` on a schedule.
- Red-team / penetration tests: ensure exercises are documented in the change management system and acknowledged as false positives in AiSOC.

## Related

- [GitHub Audit + Code Scanning](/docs/connectors/github) — for VCS-side changes that may accompany infrastructure ACL updates.
- [Cloudflare](/docs/connectors/cloudflare) — for edge network policy changes on the same zero-trust surface.
