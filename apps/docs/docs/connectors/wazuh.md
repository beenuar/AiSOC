---
sidebar_position: 15
title: Wazuh
description: Pull alerts from a Wazuh indexer (OpenSearch-compatible) into AiSOC for SIEM and HIDS coverage.
---

# Wazuh

[Wazuh](https://wazuh.com/) is an open-source XDR/SIEM platform that combines
host-based intrusion detection (HIDS), file-integrity monitoring (FIM),
log analytics, and rule-based alerting on top of an OpenSearch-compatible
indexer. The Wazuh connector polls the **indexer** directly for alerts that
exceed a configurable rule-level threshold and normalizes them into AiSOC's
canonical event shape.

This is a read-path connector — it does not modify Wazuh state. Live response
actions ("isolate this agent", "kill this PID") are tracked separately under
the generic `live_action` capability so the platform stays vendor-neutral.

## What you get

| Source | Wazuh endpoint | Notes |
|---|---|---|
| Alerts | `POST /{index_pattern}/_search` against the indexer | One AiSOC event per alert document |
| Cluster health probe | `GET /_cluster/health` | Used by **Test connection** |

Events are normalized with `category: siem` and the originating Wazuh rule
is preserved as `rule_id`, `rule_level`, and `raw_event` for downstream
routing and pivoting.

## Why we hit the indexer, not the manager

Wazuh exposes two HTTP surfaces:

- The **manager API** on port 55000 — used for agent management, rule deployment,
  and active-response orchestration. JWT-auth.
- The **indexer** on port 9200 — an OpenSearch fork that holds the actual
  alert documents in `wazuh-alerts-*`. Basic-auth.

For ingest we want the alert stream itself, which lives in the indexer. The
manager API is the right surface for live response actions and is documented
separately under [agent capabilities](/docs/concepts/capabilities).

## Prerequisites

- A reachable **Wazuh indexer** (default `https://wazuh.example.com:9200`).
- A read-only **indexer user** with permission to search `wazuh-alerts-*` and
  the cluster permission `cluster:monitor/health` for **Test connection**.
  See the Wazuh docs for [creating indexer roles and users](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
- Optional: the CA chain for the indexer's TLS certificate.

## Setup walkthrough

### 1. Create a read-only indexer user

In the Wazuh dashboard, go to **Indexer management → Security → Roles** and
create a role with:

- Index permissions on `wazuh-alerts-*`: `read`, `search`, `indices:data/read/search*`.
- **Cluster permissions**: `cluster:monitor/health`.

AiSOC's **Test connection** calls `GET /_cluster/health`, which requires
[`cluster:monitor/health`](https://docs.opensearch.org/2.19/api-reference/cluster-api/cluster-health/#required-permissions).
Index read permissions alone do not authorize this probe: a user without the
health permission can receive HTTP 403 even with valid credentials and access
to the alert indices.

If you start from [Wazuh's read-only user guide](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html#creating-and-setting-a-wazuh-read-only-user),
also add `cluster:monitor/health` to the mapped indexer role. The default
`cluster_composite_ops_ro` action group used in that guide does **not** include
cluster health monitoring; see the [OpenSearch action group definitions](https://docs.opensearch.org/2.19/security/access-control/default-action-groups/#cluster-level).

Then **Indexer management → Security → Internal users** → create a user
(e.g. `aisoc-reader`). Open the role's **Mapped users → Manage mapping** and
add that user. Save the password — you will paste it into the AiSOC connector
form.

Reusing the built-in `admin` or `kibanaserver` accounts works for a lab but
must not be used in production.

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Wazuh**.
2. Fill in:
   - `indexer_url`: full URL including port (e.g. `https://wazuh.corp.example.com:9200`).
   - `username` / `password`: the read-only user from step 1.
   - `index_pattern`: leave as `wazuh-alerts-*` unless you have re-templated indices.
   - `min_rule_level`: default `7` keeps low-signal noise out of the lake; set lower for full audit coverage.
   - `verify_tls`: leave **enabled** in production; install the CA chain rather than disabling.
3. **Test connection** — calls `GET /_cluster/health` against the indexer.
   A successful probe confirms access to that endpoint; it does not verify
   search permissions on the configured alert indices.
4. **Save**.

## Polling details

- Default interval: **300 seconds** (5 minutes), overridable per-instance via `connector_config.poll_interval_seconds`.
- The connector queries the indexer with a `range` filter on `@timestamp` so the
  manager-side processing pipeline is not impacted.
- Up to 1000 hits per poll. Tune `min_rule_level` if you find yourself getting
  truncated; for very noisy environments the right answer is usually a higher
  threshold rather than a larger page size.

## Severity mapping

Wazuh emits a 0-15 numeric `rule.level`. AiSOC collapses that ladder onto its
four-tier severity taxonomy so detection logic and fusion rules stay
vendor-agnostic:

| Wazuh rule level | AiSOC severity |
|---|---|
| 0 – 3 | `info` |
| 4 – 7 | `low` |
| 8 – 11 | `medium` |
| 12 – 15 | `high` |

The original `rule.level` is preserved on every event as `rule_level` so
detection rules can still pivot on the exact Wazuh value when they need to.

## Troubleshooting

**`auth failure 401`** — the indexer rejected basic auth. Check the username and
password against the **indexer** dashboard (not the Wazuh manager UI — they are
separate user stores by default).

**HTTP 403 on `GET /_cluster/health`** — if the indexer response contains
`no permissions for [cluster:monitor/health]`, add `cluster:monitor/health`
under **Cluster permissions** on the indexer role mapped to the connector user,
then retry **Test connection**. The connector currently reports both HTTP 401
and HTTP 403 as `authentication failed; check username/password`, so this
message can indicate a missing permission rather than an incorrect password.

To inspect the HTTP status and response body, use the same indexer URL and
username as the connector, with the indexer's trusted CA certificate. This
command prompts for the password:

```bash
curl --include --cacert /path/to/root-ca.pem --user aisoc-reader \
  'https://wazuh.example.com:9200/_cluster/health'
```

**`network error` on Test connection** — verify the URL points at port 9200, not
55000 (manager) or 5601 (dashboard). The manager API uses JWT, not basic auth,
and will reject the connector's requests.

**`no events_added`** — confirm `wazuh-alerts-*` indices actually exist in the
target cluster. Some Wazuh installations re-template the index name; if so,
override `index_pattern` to match.

**TLS handshake errors** — set `verify_tls: false` only when you are deliberately
running a self-signed lab cluster. In production, install the root CA so the
connector trusts the indexer's certificate.

## Backfill after a source-side outage

The alert stream resumes from a **durable cursor**, not from the clock. The
poll window opens at the last event ingest accepted, so when the indexer runs
behind the manager — a full disk, a flood-stage watermark blocking filebeat,
an index rotation hiccup — the connector's successful-but-empty polls hold
the window's left edge in place. When the backlog drains (carrying its
original timestamps, hours inside windows that were already polled), the next
poll requests the whole gap and reads it to the end; rows the overlap re-reads
are dropped by the cursor before they are re-submitted.

Two bounds to know:

- **Lookback cap.** One poll widens at most 7 days past the cursor
  (`connector.checkpoint.lookback_capped` is logged at warning when the cap
  binds). A source behind for longer loses what is older, deliberately —
  an unbounded backlog query is its own outage.
- **Manual backfill.** The cursor lives at `connector_config.checkpoint` on
  the connector instance. To re-read a window deliberately — the operator
  action asked for in issue #1860 — patch `checkpoint.time` back to where the
  re-read should start (`PATCH /api/v1/connectors/{id}` merges config keys,
  so send only `{"connector_config": {"checkpoint": {"time": "...", "id": ""}}}`).
  The next poll opens there; duplicates are collapsed by fusion's
  deduplication downstream.

The vulnerability stream (`vuln_mode: inventory`) deliberately stays on the
clock window: one connector instance persists one cursor, and its CVE
findings are reconciled state that re-converges on later polls.

## Related

- [osctrl](/docs/connectors/osctrl) and [FleetDM](/docs/connectors/fleetdm) — osquery-based fleet managers if you want host telemetry without Wazuh's full agent stack.
- [Detection coverage](/docs/detections/coverage) — SIEM rules that fire on Wazuh alerts via the canonical event shape.
- [Credentials vault](/docs/operations/credentials) — how the indexer password is encrypted at rest.

<!-- BEGIN GENERATED FIELD REFERENCE -->

## Configuration reference

{/* Generated by scripts/generate_connector_docs.py from the connector's
    schema(). Edit the schema, not this table. */}

| Field | Label | Type | Required | Default | Notes |
|-------|-------|------|----------|---------|-------|
| `indexer_url` | Wazuh Indexer URL | string | yes | — | Base URL of the Wazuh indexer (NOT the dashboard or manager). Default port is 9200. |
| `username` | Indexer Username | string | yes | — | Indexer user with read access to wazuh-alerts-*. Create a dedicated read-only role in production. |
| `password` | Indexer Password | secret | yes | — | **encrypted at rest** |
| `index_pattern` | Alert Index Pattern | string | no | `wazuh-alerts-*` | Override only if you have re-templated the default Wazuh index naming. |
| `min_rule_level` | Minimum Rule Level | number | no | `7` | Drop alerts with rule.level below this value at ingest. Default 7 keeps low-signal noise out of the lake; lower to 3 for full audit coverage. |
| `verify_tls` | Verify TLS Certificate | boolean | no | `True` | Disable only for self-signed lab clusters. Production deployments must install the CA chain. |
| `vuln_mode` | Vulnerability Events | select | no | `inventory` | Where vulnerability-detector events go. 'inventory' (default) routes them to the asset vulnerability inventory with patch-window due dates per docs/cve-patch-policy.md; only CVSS>9, KEV, or overdue findings raise alerts. 'alerts' keeps the legacy behaviour of one alert per scan finding. · one of: `inventory`, `alerts` |

:::note Credential handling
`password` is encrypted at rest by the credential vault before the row is written, and decrypted only at poll time. The value is never logged and never returned by the API. See [credential vault](../operations/credentials.md).
:::

<!-- END GENERATED FIELD REFERENCE -->
