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
- A read-only **indexer user** with permission to search `wazuh-alerts-*`.
  See the Wazuh docs for [creating indexer roles and users](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-rbac.html).
- Optional: the CA chain for the indexer's TLS certificate.

## Setup walkthrough

### 1. Create a read-only indexer user

In the Wazuh dashboard, go to **Security → Roles** and create a role with:

- Index permissions on `wazuh-alerts-*`: `read`, `search`, `indices:data/read/search*`.
- No cluster-level permissions.

Then **Security → Internal users** → create a user (e.g. `aisoc-reader`)
and map it to that role. Save the password — you will paste it into the AiSOC
connector form.

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

**`network error` on Test connection** — verify the URL points at port 9200, not
55000 (manager) or 5601 (dashboard). The manager API uses JWT, not basic auth,
and will reject the connector's requests.

**`no events_added`** — confirm `wazuh-alerts-*` indices actually exist in the
target cluster. Some Wazuh installations re-template the index name; if so,
override `index_pattern` to match.

**TLS handshake errors** — set `verify_tls: false` only when you are deliberately
running a self-signed lab cluster. In production, install the root CA so the
connector trusts the indexer's certificate.

## Related

- [osctrl](/docs/connectors/osctrl) and [FleetDM](/docs/connectors/fleetdm) — osquery-based fleet managers if you want host telemetry without Wazuh's full agent stack.
- [Detection coverage](/docs/detections/coverage) — SIEM rules that fire on Wazuh alerts via the canonical event shape.
- [Credentials vault](/docs/operations/credentials) — how the indexer password is encrypted at rest.
