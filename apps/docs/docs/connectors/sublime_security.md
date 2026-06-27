---
sidebar_position: 81
title: Sublime Security
description: Sublime Security email-detection events into AiSOC via /v1/messages.
---

# Sublime Security

The Sublime Security connector polls the **/v1/messages** endpoint of
the Sublime API and emits one AiSOC alert per detected message. Sublime
itself is a rule-marketplace email security platform: rules either
auto-triage benign mail or quarantine attacks (BEC, credential
phishing, impersonation).

## What you get

| Source | Sublime endpoint | Notes |
|---|---|---|
| Messages | `GET /v1/messages` | Inbound mail with a detection result attached |

Events are normalised with `source: sublime_security` and the original
Sublime envelope is preserved on `raw_event` so detection rules can
match on `triggered_rules[*].name`, `classification`, and the message
metadata (`subject`, `from`, `to`).

## Prerequisites

- A **Sublime Security tenant** (SaaS or self-hosted).
- An **API key** generated under *Sublime → Settings → API → Create token*.
- (Optional) A `base_url` override if you are on a self-hosted /
  regional Sublime deployment.

## Setup walkthrough

1. Sign in to the Sublime Console as an administrator.
2. Navigate to **Settings → API**.
3. Click **Create token**, name it `aisoc-ingest`, and copy the value
   immediately — Sublime will not show it again.
4. In AiSOC: **Connectors → Add connector → Sublime Security**.
5. Paste the API key. Override `base_url` only if you run a self-hosted
   tenant.
6. Click **Test connection**. AiSOC issues a `GET /v1/me` and confirms
   a `200`.
7. Save.

## Severity mapping

The connector collapses Sublime `classification` (or `verdict`) into
the AiSOC ladder:

| AiSOC severity | Sublime classification |
|---|---|
| `high`   | `malicious` — escalated to high regardless of rule names |
| `medium` | `suspicious`, `spam` |
| `low`    | `graymail`, `commercial` |
| `info`   | `benign`, `trusted`, `safe`, unknown |
| `high` (override) | any message whose first triggered rule name contains `bec`, `credential`, `phishing`, or `impersonation` |

## Capabilities

- `pull_alerts` — passive polling of messages.
- `pivot_user` — given a mailbox, surface that user's Sublime context.
- `quarantine_file` — Sublime can be instructed to quarantine an attachment
  (mapped to the AiSOC `quarantine_file` verb).

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: cursor-based using `next_cursor`. The connector follows
  up to 25 pages per poll cycle.
- The connector applies a `created_at__gte={since}` filter so it does
  not re-emit stale messages.
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`401 Unauthorized`** — token revoked or rotated. Regenerate under
  *Settings → API* and update the connector.
- **`404 Not Found`** — likely an incorrect `base_url` for a
  regional / self-hosted tenant.
- **No events** — Sublime only emits message rows when its rule engine
  evaluates a message. A brand-new tenant with no rules enabled will
  produce no rows.
