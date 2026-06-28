---
sidebar_position: 85
title: Cloudflare WAF + Zero Trust
description: Pull Cloudflare WAF firewall events and Zero Trust Access audit logs into AiSOC.
---

# Cloudflare WAF + Zero Trust

This connector pulls **data-plane events** from two Cloudflare streams and folds them into the same normalised AiSOC alert shape. It's distinct from the [Cloudflare Audit Logs](./cloudflare.md) connector, which only covers **control-plane** changes (who edited what in the dashboard).

| Stream | Endpoint | What it captures |
|---|---|---|
| **WAF / firewall events** | `GET /zones/{zone_id}/security/events` | Per-request decisions: block, challenge, log, jschallenge. Includes rule_id, action, source IP, country, ray_id. |
| **Zero Trust (Access) audit** | `GET /accounts/{account_id}/access/logs/access_requests` | App-access decisions: who tried to reach which Access app, were they allowed, why. Includes email, ip, app_uid, decision. |

> One stream per connector instance. The form has a `mode` field — pick **`waf`** or **`zero_trust`**. Operators who want both streams add the connector **twice** (once per mode) so per-stream rate limits stay isolated.

Events are normalized with `source: cloudflare`, `category: edge` (WAF) or `category: identity` (Zero Trust).

## Prerequisites

- A Cloudflare Enterprise or Pro plan for WAF event retention (Free tier expires events too quickly to be useful).
- For Zero Trust mode: an active Cloudflare Zero Trust subscription.
- An **account-scoped API token** with both:
  - **Account → Access: Audit Logs → Read** (Zero Trust mode)
  - **Zone → Firewall Services → Read** (WAF mode — replaces the legacy WAF Events: Read scope retired in 2024)
- Your Cloudflare **account ID** (Zero Trust mode) and your **zone IDs** (WAF mode).

## Setup walkthrough

### 1. Mint the API token

1. **Cloudflare dashboard → My Profile → API Tokens → Create Token**.
2. Use **Custom token**.
3. Permissions:
   - **Account** | **Access: Audit Logs** | **Read**
   - **Zone** | **Firewall Services** | **Read**
4. Account Resources: **Include → Specific account → &lt;your account&gt;**.
5. Zone Resources: **Include → Specific zone → &lt;your prod zones&gt;** (or **All zones from an account** if you want every zone).
6. **Continue → Create Token**. Copy it now — you won't see it again.

### 2. Find your IDs

- **Account ID**: bottom-right of any zone Overview page (32-char hex).
- **Zone IDs**: any zone Overview shows it in the same sidebar.

### 3. Add the connector — WAF mode

1. **Connectors → Add connector → Cloudflare WAF + Zero Trust**.
2. `mode` = `waf`.
3. `api_token` = the token from step 1.
4. `zone_ids` = comma-separated list (e.g. `dc4f...,90af...`).
5. `account_id` = optional in WAF mode.
6. **Test connection** → calls `GET /zones/{first_zone}/security/events?per_page=1`.
7. **Save**.

### 4. Add the connector — Zero Trust mode

Add a **second** instance:

1. **Connectors → Add connector → Cloudflare WAF + Zero Trust**.
2. `mode` = `zero_trust`.
3. `api_token` = same token (reusable).
4. `account_id` = the 32-char hex.
5. `zone_ids` = leave blank.
6. **Test connection** → calls `GET /accounts/{account_id}/access/logs/access_requests?per_page=1`.
7. **Save**.

## Polling details

- Default interval: **60 seconds** (configurable down to 30s and up to 600s).
- WAF mode walks the `since`/`until` cursor for each zone independently — per-zone rate limits stay isolated.
- Zero Trust mode walks a single account-scoped cursor; 1000 events per poll cap absorbs bursts.
- Both modes deduplicate by Cloudflare's `ray_id` (WAF) or `id` (Zero Trust) so a connector restart inside the cursor window doesn't double-emit.

## Severity heuristics

### WAF mode

| Action / pattern | Severity |
|---|---|
| `action == "block"` on a WAF Managed Rule | `medium` |
| `action == "block"` from rate-limit rule with high source-IP volume | `high` |
| `action == "jschallenge"` on a non-bot path | `low` |
| `action == "log"` | `info` |

### Zero Trust mode

| Decision / pattern | Severity |
|---|---|
| `decision == "deny"` because of group / IDP mismatch | `medium` |
| `decision == "deny"` for an admin app | `high` |
| `decision == "deny"` because of geo / posture rule | `medium` |
| `decision == "allow"` | `info` |

## Troubleshooting

**`Authentication error (code: 10000)`** — token lacks one of the two required scopes. Re-mint with both `Access: Audit Logs: Read` and `Firewall Services: Read`.

**`HTTP 429: rate limited`** — too many zones polled per cycle, or poll interval too aggressive. Either raise `poll_interval_seconds` to 120s or split zones across multiple connector instances.

**Empty WAF results despite traffic** — confirm the zone has WAF or rate-limit rules deployed. The endpoint only returns events for **rules that fired**; quiet zones legitimately return empty.

**Zero Trust mode returns 404** — the account does not have Zero Trust enabled, or the token's account scope doesn't match `account_id`.

## Related

- [Cloudflare Audit Logs](./cloudflare.md) — control-plane edits in the Cloudflare dashboard. Pair this connector with that one for full coverage of Cloudflare as a security control.
- [Tailscale](./tailscale.md) — for cross-vendor Zero Trust posture. Pair Tailscale node events with Cloudflare Access decisions to spot policy bypasses.
