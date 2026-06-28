---
sidebar_position: 84
title: Snowflake
description: Pull Snowflake login + query history from SNOWFLAKE.ACCOUNT_USAGE into AiSOC for exfiltration and anomaly detection.
---

# Snowflake

The Snowflake connector polls the `SNOWFLAKE.ACCOUNT_USAGE` schema to bring login + query history into AiSOC. It surfaces the activity that matters for SOC analysis — failed login bursts, large-result-set downloads, queries from unexpected regions, and service-account queries running against human-named warehouses — and emits one alert per anomaly candidate.

> **Two Snowflake plugins ship today.** This page covers the **core connector** (`services/connectors/app/connectors/snowflake.py`) shipped with the platform image. The reference plugin under `plugins/snowflake-events/` is a Python + Go SDK demonstration of how to build a community plugin against the same data — operators should use the core connector below for production.

## What you get

| Table | Examples surfaced |
|---|---|
| `LOGIN_HISTORY` | Failed login bursts, MFA bypass attempts, logins from a new region |
| `QUERY_HISTORY` | Large `COPY INTO @stage` exfil candidates, queries against `*` from non-service accounts, schema-discovery scans |
| `ACCESS_HISTORY` (Enterprise+) | `WHO READ WHAT` mapping for sensitive tables |
| `SESSIONS` | Long-running sessions from service tokens |

Events are normalized with `source: snowflake`, `category: data`.

## Prerequisites

- A Snowflake account on a tier that exposes `ACCOUNT_USAGE`. The schema ships on every paid tier.
- A user with read access to the schema. We recommend a dedicated `AISOC_AUDIT_READER` user with only the grants below.
- A small dedicated warehouse (X-Small is fine) for the audit poll so its cost is predictable and doesn't contend with production analytical workloads.

### Minimal grants

```sql
-- One-time setup; run as ACCOUNTADMIN.
CREATE ROLE IF NOT EXISTS AISOC_AUDIT;
GRANT USAGE ON DATABASE SNOWFLAKE TO ROLE AISOC_AUDIT;
GRANT USAGE ON SCHEMA SNOWFLAKE.ACCOUNT_USAGE TO ROLE AISOC_AUDIT;
GRANT SELECT ON ALL VIEWS IN SCHEMA SNOWFLAKE.ACCOUNT_USAGE TO ROLE AISOC_AUDIT;

CREATE WAREHOUSE IF NOT EXISTS AISOC_AUDIT_WH
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE;
GRANT USAGE ON WAREHOUSE AISOC_AUDIT_WH TO ROLE AISOC_AUDIT;

CREATE USER IF NOT EXISTS AISOC_AUDIT_READER PASSWORD = '<strong-random>'
  DEFAULT_ROLE = AISOC_AUDIT
  DEFAULT_WAREHOUSE = AISOC_AUDIT_WH
  MUST_CHANGE_PASSWORD = FALSE;
GRANT ROLE AISOC_AUDIT TO USER AISOC_AUDIT_READER;
```

## Setup walkthrough

### 1. Note your Snowflake account identifier

It's the host prefix in your Snowflake URL. Example: `xy12345.us-east-1` (or with the newer naming, `acme-prod` followed by `.snowflakecomputing.com`).

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → Snowflake**.
2. `account` = the identifier from step 1.
3. `user` = `AISOC_AUDIT_READER` (or whatever you named the dedicated user).
4. `password` = the strong random password you set (stored encrypted in the credential vault).
5. `warehouse` = `AISOC_AUDIT_WH`.
6. `role` = `AISOC_AUDIT`.
7. **Test connection** → executes `SELECT CURRENT_VERSION()` against the warehouse.
8. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll runs two parameterised queries against `LOGIN_HISTORY` and `QUERY_HISTORY`, bounded by a `since`/`now` window and a per-poll row limit (default 500) so a sudden burst doesn't lock up the audit warehouse.
- `ACCOUNT_USAGE` has a latency of **up to 45 minutes** from real-time per Snowflake docs. Polling below 60s gives no detection-latency benefit and increases warehouse cost.

## Anomaly heuristics surfaced today

| Pattern | Severity |
|---|---|
| ≥10 failed logins from the same user within 5 minutes | `high` |
| `COPY INTO @stage` with `BYTES_WRITTEN > 1 GiB` | `high` |
| Query against `INFORMATION_SCHEMA.TABLES` from a non-DBA user | `medium` |
| Login from a new IP / region for an existing user | `medium` |
| First successful login by a brand-new service-account user | `low` |

Update the thresholds via the connector's optional `anomaly_*` config keys (see the in-app form).

## Troubleshooting

**`Authentication failed: User '...' is disabled`** — re-enable the user with `ALTER USER ... SET DISABLED = FALSE;` or remint with a fresh password.

**`SQL access control error: Insufficient privileges to operate on schema 'ACCOUNT_USAGE'`** — grant `USAGE` on `SNOWFLAKE.ACCOUNT_USAGE` to the role; the per-view `SELECT` grants are not enough on their own.

**Warehouse suspended every poll** — that's the desired behaviour. `AUTO_SUSPEND = 60` keeps the warehouse cost near zero. The slight startup latency (a few seconds) is acceptable for audit polling.

**No queries returned despite users running queries in the UI** — `QUERY_HISTORY` excludes some internal system queries by design, and queries are written to the view with a delay. Wait at least one poll cycle past the activity time.

## Related

- [snowflake-events plugin reference](https://github.com/beenuar/AiSOC/tree/main/plugins/snowflake-events) — the Python + Go SDK example built against the same data. Useful as a template for community plugins; not for production.
- [AWS CloudTrail](./aws-cloudtrail.md) — pair Snowflake exfil detections with `s3:GetObject` / `s3:PutObject` from CloudTrail to spot data leaving via both the data warehouse and the object store.
