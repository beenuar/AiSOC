---
sidebar_position: 9
title: Cloudflare Audit Logs
description: Account-scope audit log entries from Cloudflare — admin actions, API token usage, edge config changes — into AiSOC.
---

# Cloudflare Audit Logs

The Cloudflare connector pulls **account-scope audit log entries** from the Cloudflare API — every administrative action taken in the dashboard or via API, including DNS changes, WAF rule edits, page rule modifications, API token creation, and member role changes.

## What you get

| Resource type | Examples |
|---|---|
| `account` | Member added, role changed, 2FA disabled |
| `zone` | DNS record create/delete, SSL setting change |
| `firewall` | WAF rule create/edit, rate-limit change |
| `access` | Cloudflare Access policy edit, identity provider change |
| `r2` / `workers` | Bucket policy change, Worker route deploy |
| `api_token` | Token created, scope granted, token revoked |

Events are normalized with `source: cloudflare`, `category: saas`.

## Prerequisites

- A **Cloudflare account ID**. Find it at the bottom right of any zone overview page.
- A **Cloudflare API token** with at minimum:
  - **Account → Audit Logs → Read**
  - (Optional) **Account → Account Settings → Read** for member resolution
- The token must be **account-scoped**, not user-scoped, so it survives if the creating user leaves the team.

We strongly recommend creating a dedicated `aisoc-readonly` token with only the audit-log scope. Do not reuse your global API key.

## Setup walkthrough

### 1. Create the API token

1. **Cloudflare dashboard → My Profile → API Tokens → Create Token**.
2. Use the **Custom token** template.
3. Permissions:
   - **Account** | **Audit Logs** | **Read**
4. Account Resources: **Include → Specific account → &lt;your account&gt;**.
5. (Optional) Set a TTL or IP restriction.
6. **Continue → Create Token**. Copy the token now — you won't see it again.

### 2. Find your account ID

Any zone's **Overview** page shows the account ID in the right-hand sidebar (32-character hex string). Or run:

```bash
curl -H "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/accounts | jq -r '.result[].id'
```

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → Cloudflare**.
2. `account_id` = the 32-character hex string.
3. `api_token` = the token from step 1 (stored encrypted in the credential vault).
4. **Test connection** → calls `GET /accounts/:id/audit_logs?per_page=1`.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- The connector calls `GET /accounts/:id/audit_logs?since=<lastpoll>&before=<now>&direction=desc&per_page=100`, paginating until exhaustion or an upper bound of 1000 events per poll.
- Cloudflare returns audit events with **near-zero latency** (typically &lt;30 sec from action), making this one of the lower-latency connectors in the catalog.

## Severity heuristics

| Action | Severity |
|---|---|
| `member.add` with `Super Administrator` role | `high` |
| `api_token.create` with broad scopes (e.g. `Account.*`) | `high` |
| `account.2fa.disable` | `high` |
| `zone.firewall.rule.delete` on production zone | `medium` |
| `dns.record.delete` of an MX/A record on production zone | `medium` |
| `worker.route.create` pointing to an unverified worker | `medium` |
| Routine `zone.settings.read` | dropped |

## Troubleshooting

**`Authentication error (code: 10000)`** — token lacks the `Audit Logs Read` permission, or token is user-scoped on an account where the user has been removed. Recreate as account-scoped.

**`Resource not found (code: 7003)`** — the account ID is wrong. Confirm against the dashboard sidebar — it is **not** the same as the zone ID.

**Empty results despite recent dashboard changes** — the audit log API only includes a subset of dashboard activity (administrative changes). Read-only browsing does not appear. This is expected and matches Cloudflare's documented behavior.

## Related

- [GitHub Audit + Code Scanning](/docs/connectors/github) — for the source-control side of edge changes (e.g. workers committed to a repo before they were deployed).
- For zone-level WAF and bot events, see the dedicated **Cloudflare Logpush** documentation (separate, paid feature) — out of scope for this connector.
