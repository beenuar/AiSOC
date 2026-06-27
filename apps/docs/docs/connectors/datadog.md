---
sidebar_position: 78
title: Datadog
description: Datadog logs and Cloud SIEM signals into AiSOC via the Datadog v2 API.
---

# Datadog

The Datadog connector streams from either the **Logs Search v2 API** or
the **Events v1 API** (APM monitor alerts + custom events), depending
on the configured `mode`.

For Cloud SIEM **Security Signals**, use the separate
`datadog_cloud_siem` connector — splitting the modules keeps each
schema single-purpose.

## What you get

| Mode | Datadog endpoint | Notes |
|---|---|---|
| `logs`   | `POST /api/v2/logs/events/search` | Raw logs filtered by the configured query string |
| `events` | `GET /api/v1/events`              | APM monitor alerts + custom events filtered by tags |

Events are normalised with `source: datadog` and the original Datadog
envelope is preserved on `raw_event` so detection rules can match on
`service`, `env`, `status`, or the monitor `tags` block.

## Prerequisites

- A **Datadog organisation** on any of: `datadoghq.com`,
  `datadoghq.eu`, `us3.datadoghq.com`, `us5.datadoghq.com`,
  `ddog-gov.com`, or `ap1.datadoghq.com`.
- An **API key** (Organisation Settings → API Keys → New Key).
- An **Application key** (Personal Settings → Application Keys → New Key).
- For `mode: signals`, the org must have **Cloud SIEM** enabled.

## Setup walkthrough

1. In Datadog, **Organisation Settings → API Keys → New Key**. Name it
   `aisoc-ingest` and copy the value.
2. **Personal Settings → Application Keys → New Key**. Name it
   `aisoc-ingest-app` and copy the value.
3. In AiSOC: **Connectors → Add connector → Datadog (Logs + APM)**.
4. **Site** — pick the regional site that matches your Datadog tenant.
5. **Mode** — `logs` for general log streaming, `events` for APM
   monitor alerts and custom events.
6. **Query** — any Datadog query-string expression. Defaults to
   `status:error OR status:critical`. Useful filters:
   `service:nginx status:error`, `env:prod source:auth`,
   `@evt.category:authentication status:error`.
7. Paste the **API key** and **Application key**.
8. Click **Test connection**. AiSOC issues a 1-row search and confirms
   a `200`.
9. Save.

## Severity mapping

For `mode: logs` (the `status` / `level` attribute):

| AiSOC severity | Datadog log status |
|---|---|
| `high`   | `emergency`, `alert`, `critical` |
| `medium` | `error` |
| `low`    | `warn`, `warning` |
| `info`   | `notice`, `info`, `debug`, missing |

The split between `critical` (→ high) and `error` (→ medium) is
deliberate: keeping `critical`/`alert`/`emergency` on its own tier
means a paging event stays distinguishable from a routine 5xx in the
alert queue.

For `mode: events` (the monitor `alert_type` attribute):

| AiSOC severity | Datadog event `alert_type` |
|---|---|
| `high`   | `error` |
| `medium` | `warning` |
| `info`   | `info`, `success`, missing |

Event `priority` is used only as a **floor**: `priority:low` can lower
severity from `info`, never raise it.

For **Security Signals**, use the `datadog_cloud_siem` connector.

## Capabilities

- `pull_logs` — passive polling of logs.
- `pull_alerts` — passive polling of APM monitor alerts.
- `query_logs` — ad-hoc query support (the connector accepts arbitrary
  Datadog query strings).
- `pivot_host` — given a hostname, return its recent logs.

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: cursor-based using the v2 API's `meta.page.after` token.
  The connector follows up to 25 pages per poll cycle.
- Time range: the search request always carries
  `filter.from: now-{since_seconds}s`, `filter.to: now`.
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`403 Forbidden`** — the application key was minted by a user
  without read permission on the resource (logs / signals). Re-create
  the application key under an account with the right RBAC.
- **`429 Too Many Requests`** — Datadog throttles aggressively; the
  connector backs off automatically. Tighten the `query` filter or
  raise the poll interval if it persists.
- **No events** — verify the `query` returns rows in the Datadog UI
  (Logs Explorer or Security Signals page). The connector applies the
  query verbatim.
