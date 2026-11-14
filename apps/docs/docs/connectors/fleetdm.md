---
sidebar_position: 15
title: FleetDM
description: Pull host posture and saved-query report rows from FleetDM into AiSOC.
---

# FleetDM

[FleetDM](https://fleetdm.com/) is an open-source-friendly osquery fleet
manager. The FleetDM connector polls the Fleet REST API for two distinct event
streams:

1. **Host posture changes** — hosts going `online`, `offline`, or `missing`.
2. **Saved-query report rows** — every row of every saved query, normalized as one event per row.

Severity is derived per-stream so that posture changes and query rows can be
routed independently downstream.

## What you get

| Source | Fleet endpoint | Notes |
|---|---|---|
| Hosts | `GET /api/v1/fleet/hosts` | One event per host whose status changed since `since_seconds` |
| Saved queries | `GET /api/v1/fleet/queries` | Discovery only |
| Saved-query report rows | `GET /api/v1/fleet/queries/{id}/report` | One event per row |

Events are normalized with `category: endpoint`. The `kind` field on the event
distinguishes `host` vs `query_row` so playbooks and detections can branch.

## Prerequisites

- A reachable **Fleet server** (`https://fleet.example.com`).
- A **long-lived API token** issued from **Settings → Users → \[user\] → Get API token**.
- Optional **Team ID** if you want to scope polling to a single Fleet team.

## Setup walkthrough

### 1. Issue an API token in Fleet

1. Sign in to Fleet as a global admin or team admin.
2. Open **Settings → Users**, select the service-account user, and click **Get API token**.
3. Copy the token.

Tokens are scoped to the user. Use a dedicated service-account user so
revocation does not lock out a real operator.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → FleetDM**.
2. Fill in `base_url` (no trailing slash; `/api` is appended automatically), `api_token`, and optionally `team_id`.
3. **Test connection** — the connector calls `GET /api/v1/fleet/me` to validate auth.
4. **Save**.

## Polling details

- Default interval: **300 seconds**, overridable per-instance via `connector_config.poll_interval_seconds`.
- The connector pulls hosts and saved-query reports independently in the same poll cycle so a slow saved query does not block host posture ingestion.

## Severity mapping

### Host posture

| Fleet `status` | AiSOC severity |
|---|---|
| `missing` | `medium` |
| `offline` | `low` |
| `online` | `info` |

### Saved-query report rows

Identical table-driven mapping as the [osctrl connector](/docs/connectors/osctrl)
— persistence and execution tables (`startup_items`, `scheduled_tasks`,
`launchd`, `crontab`, `kernel_modules`, `browser_extensions`) get `high`,
`file_events` gets `medium`, inventory tables get `info`.

## Troubleshooting

**`auth failure 401/403`** — the token is invalid or the user has been deleted. Re-issue from the Fleet UI.

**`team_id` is set but no events** — confirm the team has hosts assigned and that the saved queries are scheduled against that team.

**Many duplicate `host` events** — Fleet emits status transitions on poll, not on change. The detection layer is responsible for deduplication via the standard `dedupe_key`.

## Related

- [osctrl](/docs/connectors/osctrl) — alternative open-source fleet manager.
- [Detection coverage](/docs/detections/coverage) — endpoint rules that fire on osquery data.

## Live-query response actions (playbook step)

The `osquery_live_query` playbook step supports FleetDM as a backend,
dispatching live campaigns via Fleet's distributed-query API.

### Playbook step schema

```yaml
- id: triage-logged-users
  name: "Get logged-in users from affected host"
  type: osquery_live_query
  params:
    backend: fleetdm
    base_url: "https://fleet.corp.example.com"
    api_token: "{{ secrets.fleetdm_token }}"   # or use username/password below
    # username: admin
    # password: "{{ secrets.fleetdm_password }}"
    template: logged_in_users
    target_hosts:
      - "{{ alert.host }}"
    timeout_seconds: 60
```

### Authentication

FleetDM supports two credential modes:

| Mode | Params |
|---|---|
| API token | `api_token` |
| User / password | `username` + `password` (token fetched automatically via `/api/v1/fleet/login`) |

The client will authenticate on first use and reuse the token for the duration
of the step.

### Supported templates

Same allowlist as the osctrl backend — see the
[osctrl connector](/docs/connectors/osctrl#supported-templates) for the full
table. Templates are backend-agnostic; only the `backend:` key selects the
fleet manager.

### Result shape

```json
{
  "results": {
    "hostname-a": [{"user": "root", "type": "user", "host": "hostname-a"}]
  },
  "partial": false,
  "timed_out_hosts": []
}
```

### When to choose FleetDM vs osctrl

| Concern | FleetDM | osctrl |
|---|---|---|
| Community / ecosystem | Larger | Smaller |
| Multi-tenant isolation | Teams (paid tier for strict isolation) | Native environments (OSS) |
| Infra footprint | MySQL + Redis | PostgreSQL only |
| AiSOC stack alignment | Needs extra deps | Native fit |

Both backends are fully supported — choose based on your existing fleet
management deployment.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `base_url` | Fleet Server URL | string | yes | — | Base URL of the Fleet server (no trailing slash). The /api prefix is added automatically. |
| `api_token` | API Token | secret | yes | — | **encrypted at rest** · Long-lived token issued from the Fleet UI under Settings -> Users -> [user] -> Get API token. |
| `team_id` | Team ID | string | no | — | Optional Fleet Team ID to scope queries to. Leave empty to span all teams. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | — |

:::note Credential handling
`api_token` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
