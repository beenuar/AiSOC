---
sidebar_position: 85
title: Cloudflare WAF + Zero Trust
description: Pull Cloudflare WAF firewall events and Zero Trust Access audit logs into AiSOC.
---

# Cloudflare WAF + Zero Trust

This connector pulls **data-plane events** from two Cloudflare streams and folds them into the same normalised AiSOC alert shape. It's distinct from the [Cloudflare Audit Logs](./cloudflare.md) connector, which only covers **control-plane** changes (who edited what in the dashboard).

| Stream | Endpoint | What it captures |
|---|---|---|
| **WAF / firewall events** | `POST /graphql`, dataset `firewallEventsAdaptive` | Per-request decisions: block, challenge, log, skip. Includes `ruleId`, `action`, `clientIP`, `clientCountryName`, `rayName`. |
| **Zero Trust (Access) audit** | `GET /accounts/{account_id}/access/logs/access_requests` | App-access decisions: who tried to reach which Access app, were they allowed, why. Includes email, ip, app_uid, decision. |

> One stream per connector instance. The form has a `mode` field — pick **`waf`** or **`access`**. Operators who want both streams add the connector **twice** (once per mode) so per-stream rate limits stay isolated.
>
> This page used to call the second mode `zero_trust`, which the connector has never accepted. `zero_trust` is now taken as a spelling of `access` so a config copied from the old text keeps working.

Events are normalized with `source: cloudflare_zt` and `stream: waf` or `stream: access`.

:::note Why WAF events come over GraphQL
Earlier versions of this connector polled `GET /zones/{zone_id}/security/events`. That route does not exist — Cloudflare answers it with **HTTP 404, error `10404` "No route for that URI"** — so WAF mode could never return an event ([#1686](https://github.com/beenuar/AiSOC/issues/1686)). Cloudflare exposes firewall events through the GraphQL Analytics API or through Logpush (Enterprise); this connector uses GraphQL.
:::

## Prerequisites

- For Access mode: an active Cloudflare Zero Trust subscription.
- Retention on the `firewallEventsAdaptive` dataset is plan-dependent; poll often enough that your interval sits inside your plan's window.
- An **API token** with:
  - **Account → Access: Audit Logs → Read** (Access mode)
  - **Zone → Analytics → Read** (WAF mode — this is what the GraphQL analytics dataset reads. *Not* `Firewall Services: Read`, which governs rule management and is what this page used to ask for.)
- Your Cloudflare **account ID** (both modes) and the **zone ID** (WAF mode).

## Setup walkthrough

### 1. Mint the API token

1. **Cloudflare dashboard → My Profile → API Tokens → Create Token**.
2. Use **Custom token**.
3. Permissions:
   - **Account** | **Access: Audit Logs** | **Read**
   - **Zone** | **Analytics** | **Read**
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
4. `zone_id` = one zone (the field is a single id, not a list — add one instance per zone).
5. `account_id` = the 32-char hex. Required in both modes.
6. **Test connection** → verifies the token, then runs a one-row `firewallEventsAdaptive` query against that zone. A zone with no firewall events still passes; only an error fails.
7. **Save**.

### 4. Add the connector — Zero Trust mode

Add a **second** instance:

1. **Connectors → Add connector → Cloudflare WAF + Zero Trust**.
2. `mode` = `access`.
3. `api_token` = same token (reusable).
4. `account_id` = the 32-char hex.
5. `zone_id` = leave blank.
6. **Test connection** → calls `GET /accounts/{account_id}/access/logs/access_requests?per_page=1`.
7. **Save**.

## Polling details

- WAF mode pages **by time**: `firewallEventsAdaptive` has no cursor, so rows come back ordered by `datetime` ascending and the next request's lower bound is the last row's timestamp. That bound is inclusive, so the boundary row repeats; emitted `rayName` values are remembered for the duration of a poll and a repeat is dropped.
- Access mode walks the endpoint's own `result_info.cursor`. An empty cursor is end-of-stream.
- Both modes stop after 20 pages of 100 rows, so one poll reads at most 2,000 events per instance.

## Severity heuristics

These are what the connector computes, not a description of what it could.

### WAF mode

| Condition | Severity |
|---|---|
| `action == "block"` **and** `ruleId` contains `owasp` | `high` |
| `action` in `block`, `drop`, `managed_challenge`, `jschallenge`, `challenge` | `medium` |
| anything else, including `log` and `skip` | `info` |

### Access mode

| Condition | Severity |
|---|---|
| `action` / `decision` is `blocked` | `high` |
| `allowed` is `false`, or the decision is `denied` / `non_identity` | `medium` |
| anything else | `info` |

## Troubleshooting

**`No route for that URI` (code `10404`) on WAF mode** — you are on a build before this connector moved to GraphQL. Upgrade; no token change fixes it, because the route the old build called does not exist.

**`cloudflare_zt graphql error: ...insufficient permissions`** — the token lacks **Zone → Analytics → Read**. The connector reports this rather than returning zero events, because "this token cannot read the dataset" and "your zone saw no attacks" are different sentences.

**`the token sees no zone with that id`** — the `zone_id` is not in the token's zone scope, or belongs to another account.

**`Authentication error (code: 10000)`** — token lacks one of the required scopes. Re-mint with `Access: Audit Logs: Read` and `Zone: Analytics: Read`.

**`HTTP 429: rate limited`** — too many zones polled per cycle, or poll interval too aggressive. Either raise `poll_interval_seconds` to 120s or split zones across multiple connector instances.

**Empty WAF results despite traffic** — confirm the zone has WAF or rate-limit rules deployed. The dataset only returns events for **rules that fired**; quiet zones legitimately return empty, and the connector reports that as a successful poll with zero events.

**Access mode returns 404** — the account does not have Zero Trust enabled, or the token's account scope doesn't match `account_id`.

## Related

- [Cloudflare Audit Logs](./cloudflare.md) — control-plane edits in the Cloudflare dashboard. Pair this connector with that one for full coverage of Cloudflare as a security control.
- [Tailscale](./tailscale.md) — for cross-vendor Zero Trust posture. Pair Tailscale node events with Cloudflare Access decisions to spot policy bypasses.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `mode` | Event stream | select | yes | — | Pick which stream this instance pulls. Run two instances side-by-side for full coverage. · one of: `waf`, `access` |
| `account_id` | Account ID | string | yes | — | Cloudflare account ID, found in the dashboard right pane. |
| `zone_id` | Zone ID (WAF mode only) | string | no | — | Required when mode=waf. Leave empty for Access mode. |
| `api_token` | API Token | secret | yes | — | **encrypted at rest** · Token with Zone:Analytics:Read (WAF — this is what the GraphQL analytics dataset reads, not Firewall Services:Read) AND Account:Access Audit Logs:Read (Zero Trust). |

:::note Credential handling
`api_token` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
