---
id: cold-tier-queries
title: Querying the cold tier
sidebar_label: Cold-tier queries
---

A tenant can keep up to 400 days of events, and most of that lives on the
cold volume once the tiering policy has moved it there. Reading it is
slower and costs money, and until recently the only thing the platform
told you about that was a timeout.

Three surfaces now cover it.

## Ask what a query would read

```bash
curl -sS -X POST "$AISOC_URL/api/v1/lake/estimate" \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT event_time, src_ip FROM raw_events WHERE event_time > now() - INTERVAL 300 DAY"}'
```

```json
{
  "estimated_rows": 418000000,
  "estimated_parts": 1240,
  "estimated_bytes": 91273000000,
  "cold_bytes": 84900000000,
  "warm_bytes": 6373000000,
  "touches_cold": true,
  "tables": ["raw_events"],
  "estimated_usd": null,
  "cost_basis": "no retrieval price is configured, so no money figure is reported. …"
}
```

Every figure is ClickHouse's own. Rows and parts come from `EXPLAIN
ESTIMATE` — the planner's answer after partition pruning. The warm/cold
split comes from `system.parts` joined to `system.disks`, matched against
the volume names your storage policy declares, so a part is cold because
ClickHouse says it is on the cold volume and not because of its age. Those
two disagree whenever a move is in flight or the TTL has changed, and the
disk is the one that decides what the read costs.

The estimate is charged at the schema rate rather than the query rate.
Pricing it like a scan would train analysts to skip it.

### Why `estimated_usd` is usually null

Because no retrieval price is configured.
`docs/decisions/storage-cost-model.json` is a **storage** rate card —
dollars per GB-month resident — and using it to price a read would be
quoting the wrong number confidently. Set your provider's retrieval price
and you get a figure derived from it:

```bash
AISOC_LAKE_COLD_RETRIEVAL_USD_PER_GB=0.01
```

`null` means "we do not know what this costs". `0.0` means "this costs
nothing". They are never confused.

## Run it as a job

`POST /api/v1/lake/sql` refuses a query the estimate says must read the
cold volume, with `409` and the estimate attached:

```json
{
  "error": "cold_scan",
  "message": "this query reads the cold tier, which does not reliably finish inside the 30s synchronous bound. Submit it to POST /api/v1/lake/query-jobs, …",
  "estimate": { "...": "..." }
}
```

The routing rule is structural, not a predicted duration. Predicting one
would need a bytes-per-second figure, and the only honest source for that
is a measurement on your own hardware, which the platform has not got.
`force_sync: true` overrides it when you already know the scan is small.

```bash
curl -sS -X POST "$AISOC_URL/api/v1/lake/query-jobs" \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT …", "row_cap": 5000}'
```

Answers `202` with a job. Poll it:

```bash
curl -sS "$AISOC_URL/api/v1/lake/query-jobs/$JOB_ID" -H "Authorization: Bearer $AISOC_API_TOKEN"
```

| Field | Meaning |
|---|---|
| `status` | `queued`, `running`, `succeeded`, `failed`, `cancelled` |
| `rows_read`, `bytes_read` | From `system.processes`, the server's own counters |
| `total_rows_approx` | ClickHouse's running estimate; it moves |
| `progress_ratio` | `0.0`–`1.0`, or **`null`** when the server has not published a total |
| `estimate` | As taken at submit time, never recomputed |
| `columns`, `rows`, `row_count` | Present once `succeeded` |
| `error` | Present once `failed`, with what to change |

`progress_ratio` being null is a real state, not a bug. ClickHouse
publishes `total_rows_approx` best-effort, so a running query can have a
numerator and no denominator — and a bar that renders 100% because the
denominator was zero is worse than one that says it does not know.

The estimate on a job is the number you agreed to before the scan started
and is never recomputed. Moving it afterwards would make the record of
what you were told untrue.

`POST /api/v1/lake/query-jobs/{id}/cancel` stops a running scan and asks
ClickHouse to kill the query. A job that has already ended answers `409`
rather than being quietly re-marked.

## Limits worth knowing

* A job is capped at 15 minutes. That is a policy ceiling, not a
  measurement — nothing here claims a cold scan takes fifteen minutes. It
  is the point past which a human should be asked whether they still want
  the answer.
* Results are held on the job row, bounded by the `row_cap` you submitted.
  The caller is polling, so there is nothing to stream to.
* A job whose runner died — an API replica restarted mid-scan — stays
  `running` with nothing behind it. `list_stuck_jobs` is what surfaces
  those; a job still running long past the ceiling is not progressing.
* If the estimator cannot run (the role cannot read `system.parts`, say),
  a query runs the way it always did rather than being refused. Refusing
  would make the lake unusable on a deployment whose system tables are
  restricted. The skip is logged.
