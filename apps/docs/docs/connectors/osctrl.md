---
sidebar_position: 14
title: osctrl
description: Pull osquery distributed-query results from osctrl into AiSOC for endpoint detection.
---

# osctrl

[osctrl](https://osctrl.net/) is an open-source osquery fleet manager. The osctrl
connector polls the admin REST API for **distributed-query results** and turns
each result row into a normalized AiSOC endpoint event. Severity is synthesised
from the osquery table that produced the row, so detection rules in
`detections/endpoint/` can promote interesting rows (e.g. a new entry in
`startup_items`) to high without having to reason about vendor-specific severity
fields.

This connector is read-only on its own. The companion AiSOC TLS endpoint
(`aisoc-direct`, ships as a separate connector page) and the live-query
response action (see [agent capabilities](/docs/concepts/capabilities)) build
on the same auth surface to dispatch ad-hoc queries from playbooks.

## What you get

| Source | osctrl endpoint | Notes |
|---|---|---|
| Distributed-query results | `GET /api/v1/queries/{env}/list` + `/results/{name}` | One AiSOC event per result row |

Events are normalized with `category: endpoint` and the originating osquery
table is preserved as `osquery_table` for downstream routing.

## Prerequisites

- An installed and reachable **osctrl admin server** (`https://osctrl.example.com`).
- An **API token** issued from **Manage Users → \[user\] → generate token** in the osctrl UI.
- The **environment name** you want to poll (typically `prod`).

## Setup walkthrough

### 1. Issue an API token in osctrl

1. Sign in to the osctrl admin UI as an administrator.
2. Navigate to **Manage Users**, choose the service-account user, and click **generate token**.
3. Copy the token — it is only shown once.

osctrl tokens are long-lived; rotate them on the same cadence as your other
infrastructure secrets.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → osctrl**.
2. Fill in `base_url` (no trailing slash), `api_token`, and `environment`.
3. Leave **Verify TLS** enabled in production. Disable it only for self-signed lab deployments.
4. **Test connection** — the connector calls `GET /api/v1/nodes` to validate auth.
5. **Save**.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- `since_seconds` is honoured client-side because osctrl's list endpoint does not accept a server-side filter.

## Severity mapping

osctrl is a query/event platform, so it does not emit alerts with vendor
severity. AiSOC synthesises severity from the table queried:

| osquery table | AiSOC severity | Why |
|---|---|---|
| `startup_items`, `scheduled_tasks`, `launchd`, `crontab`, `kernel_extensions`, `kernel_modules`, `browser_extensions` | `high` | Persistence + execution surfaces |
| `file_events` | `medium` | FIM rows; detection rules promote write/delete events |
| `processes`, `process_open_sockets`, `listening_ports`, `logged_in_users` | `medium` | Runtime telemetry |
| `system_info`, `os_version`, `uptime` | `info` | Pure inventory |
| Anything else | `medium` | Conservative default |

Operators tune the mapping per environment via detections — the connector keeps
the defaults stable so detection authors have a predictable substrate.

## Troubleshooting

**`auth failure 401/403`** — the API token is missing or revoked. Re-issue from the osctrl UI.

**`no events_added`** — verify the environment name matches a valid osctrl environment, and that at least one distributed query has run recently.

**TLS handshake errors** — set `verify_tls: false` only when you are deliberately running an osctrl instance with a self-signed certificate. In production, install the CA chain instead.

## Related

- [FleetDM](/docs/connectors/fleetdm) — alternative osquery fleet manager with a similar event shape.
- [Detection coverage](/docs/detections/coverage) — endpoint rules that fire on osquery data.

## Live-query response actions (playbook step)

The `osquery_live_query` playbook step dispatches an on-demand osquery
distributed query to one or more hosts via osctrl's distributed-query API.
Responses are polled and returned as structured rows, enabling IR triage
("get all running processes on this host right now") directly inside
AiSOC playbooks.

### Playbook step schema

```yaml
- id: triage-running-procs
  name: "Get running processes from affected host"
  type: osquery_live_query
  params:
    backend: osctrl
    base_url: "https://osctrl.corp.example.com"
    environment: production          # osctrl environment name
    api_token: "{{ secrets.osctrl_token }}"
    template: running_processes      # must be an approved allowlist template
    template_params:
      limit: 100
    target_hosts:
      - "{{ alert.host }}"
    timeout_seconds: 60              # optional, default 60
```

### Supported templates

| Template | SQL intent |
|---|---|
| `running_processes` | `SELECT * FROM processes LIMIT :limit` |
| `active_connections` | `SELECT * FROM process_open_sockets WHERE state='ESTABLISHED'` |
| `logged_in_users` | `SELECT * FROM logged_in_users` |
| `recently_modified_files` | `SELECT * FROM file WHERE path LIKE '/tmp/%' AND mtime > :since` |
| `listening_ports` | `SELECT * FROM listening_ports` |

Only templates in the allowlist can be executed — raw SQL injection is rejected
at the `AllowlistError` boundary before any network call is made.

### Result shape

```json
{
  "results": {
    "hostname-a": [{"pid": "1234", "name": "bash", "cmdline": "..."}],
    "hostname-b": []
  },
  "partial": false,
  "timed_out_hosts": []
}
```

`partial: true` is set when at least one target host did not respond within
`timeout_seconds`.

### Credentials

Store the osctrl API token in the AiSOC secrets store and reference it with
`{{ secrets.osctrl_token }}` in the playbook YAML. Never hard-code tokens.
