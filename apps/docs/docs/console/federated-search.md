---
sidebar_position: 6
title: Federated search across your SIEMs
description: Query Splunk, Microsoft Sentinel, Elastic and QRadar with one search from the AiSOC console, using your own stored credentials, and read a separate verdict for each backend.
---

# Federated search across your SIEMs

Most SOCs run more than one place to search. An identity question lives in one system, endpoint telemetry in another, cloud audit logs in a third, and the answer to "where else did this account appear in the last hour" is spread across all of them. The usual cost is a tab per tool and a manual reconciliation at the end.

`/federated-search` collapses that into one query. You describe what you are looking for once; AiSOC translates it per backend, runs the searches in parallel against the credentials that tenant already stored, and merges the rows.

## What it queries

Any connector instance the tenant has **enabled** whose type speaks a supported query language:

| Connector type | Query language |
| --- | --- |
| `splunk` | SPL |
| `microsoft_sentinel` | KQL |
| `elastic` | ES\|QL |
| `qradar` | AQL |

You never write vendor syntax. The page takes a free-text string plus optional `field operator value` filters and the translator layer emits the right dialect for each backend.

Connectors of other categories (EDR, IAM, SaaS) are not queried and are not listed on the page — they have no search surface to fan out to.

## Reading the result

The page is built around one property of the underlying endpoint that is easy to lose: **a slow or broken backend does not fail the search**. Each backend is queried inside its own error boundary and reports its own verdict. The response carries a `sources[]` array alongside the merged rows.

That distinction matters more than it first appears. "Sentinel returned nothing" and "Sentinel did not answer" lead to opposite conclusions during an incident, and a UI that shows only merged rows renders them identically. So the per-backend strip sits **above** the rows and is always present:

```
Per-backend result                              1 of 2 answered, 1 failed

┌────────────────────────────┐  ┌────────────────────────────────────────┐
│ Prod Splunk       Answered │  │ Corp Sentinel                   Failed │
│ Splunk · 1 row · 812 ms    │  │ Microsoft Sentinel · 30000 ms          │
└────────────────────────────┘  │ connectors service unreachable:        │
                                │ ReadTimeout                            │
                                └────────────────────────────────────────┘
```

Three rules the page follows so a partial answer cannot be misread as a complete one:

- A backend with `status: error` shows **no row count**. Printing "0 rows" next to a timeout reads as "nothing matched", which is the one conclusion you must not draw from a failure.
- When any backend fails, a banner states that the results are partial and that absence of rows from those sources is not evidence of absence of activity.
- An empty result set is labelled differently depending on why it is empty: **"No matching events"** when at least one backend answered and matched nothing, **"No backend returned results"** when every backend failed.

Each backend also reports its own latency, so a SIEM that is technically answering but taking 28 seconds is visible rather than hidden inside an aggregate.

### Row caps

`limit` applies per backend, then the merged set is capped again at the same figure. When that second cap trims rows the page says so explicitly — a silently truncated result is indistinguishable from a complete one.

## Choosing backends

By default every enabled, federated-capable connector is queried. Untick one to scope the search.

The health dot next to each connector is its **last recorded poll status**, not a live probe. A connector that is healthy for ingest can still fail this particular query — wrong index, expired search token, a workspace the credential cannot read. The per-backend verdict after you run the search is the authoritative answer; the dot is only a hint about where to start.

## Pivoting out of a result

Recognised entities in a row render as pivot chips that deep-link into the attack graph at `/graph?entity=<type>:<value>` — the same URL shape the [Investigation Rail](./investigation-rail.md) entity chips use. The graph selects the node named by the parameter.

Recognition is a fixed list of field names per entity type (`host`, `user`, `ip`, `domain`), covering the common spellings across vendors: `src_ip`, `source.ip` and `SourceIP` all resolve to the same IP pivot. It is deliberately not a heuristic — a substring rule that treats "anything containing `ip`" as an address also matches `zip`, `recipient` and `description`, and a pivot onto the wrong entity is worse than no pivot because it quietly widens the picture while looking correct. Columns that are not recognised render as plain text.

Vendor placeholders for "field present but unset" (`-`, `null`, `n/a`, `unknown`) are skipped rather than linked.

## Enabling it

Federated search is behind a flag on the API service:

```bash
AISOC_FEATURE_FED_SEARCH=true
```

With the flag unset, `/api/v1/federated/*` answers `404` and the console page says the feature is turned off and names the variable, rather than showing a generic not-found. No query is sent while it is disabled.

You also need at least one enabled connector of a supported type. With none, the page says so and links to `/connectors`.

## Permissions and tenancy

Both endpoints require `connectors:read`.

Credentials never leave the API service. `POST /api/v1/federated/search` decrypts each connector's stored `auth_config` through the credential vault, forwards it to the stateless connectors service over the internal network, and the plaintext never round-trips to the browser. Connector selection is tenant-scoped in the query itself, so a `connector_id` belonging to another tenant resolves to "not found" rather than being queried.

Every search writes an audit row recording the **shape** of the query — which fields were filtered, which backends were queried, how many rows came back, how long each took — and never the filter values. A federated query can legitimately contain regulated identifiers, and the audit log is shared across the tenant.

## API

```http
GET /api/v1/federated/backends
```

```json
{
  "backends": [
    {
      "connector_id": "…",
      "connector_type": "splunk",
      "name": "Prod Splunk",
      "health_status": "healthy",
      "is_enabled": true
    }
  ]
}
```

```http
POST /api/v1/federated/search
```

```json
{
  "free_text": "failed logon",
  "indicators": [{ "field": "user", "operator": "in", "value": ["alice", "bob"] }],
  "since_seconds": 3600,
  "limit": 100,
  "connector_ids": null
}
```

`connector_ids: null` (or omitted) means every enabled, federated-capable connector. Supplying a list scopes the fan-out; an id that is missing, disabled, or not federated-capable returns `404` naming it rather than being silently dropped, because a typo should be loud.

Operators: `eq`, `ne`, `contains`, `starts_with`, `ends_with`, `gt`, `gte`, `lt`, `lte`, `in`. Indicators are AND-joined with each other and with `free_text`. `since_seconds` is capped at 7 days — use a SIEM-native search for longer windows.

The response merges the rows and stamps each with its origin:

```json
{
  "rows": [{ "host": "WIN-DC01", "_aisoc_source": { "connector_name": "Prod Splunk", "…": "…" } }],
  "row_count": 1,
  "sources": [{ "connector_id": "…", "status": "ok", "row_count": 1, "duration_ms": 812, "error": null }],
  "truncated": false
}
```

`sources[].status` is `ok`, `error` or `unsupported`. A non-`ok` entry never fails the request.
