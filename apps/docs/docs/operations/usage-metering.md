---
title: Usage metering
sidebar_label: Usage metering
description: Per-tenant, per-day usage counted from the rows that record the work, with a monthly CSV export.
---

# Usage metering

What a tenant did, per day, counted from the rows that record it.

There is no pricing here. These are counts and measured model costs. What
they are worth is a commercial question and deliberately lives nowhere near
the code that answers what happened.

## What is metered

| Meter | Source table | Meaning |
|---|---|---|
| `alerts` | `alerts` | Alerts created in the window |
| `triages_model` | `alerts` | Alerts carrying model-generated triage output |
| `triages_deterministic` | `alerts` | Alerts resolved without model output |
| `investigations` | `investigation_runs` | Agent investigation runs started |
| `llm_tokens` | `aisoc_run_costs` | Prompt plus completion tokens |
| `llm_cost_usd` | `aisoc_run_costs` | Measured model spend |
| `actions` | `aisoc_action_records` | Response actions recorded |
| `actions_executed` | `aisoc_action_records` | Of those, the ones that reached a vendor |
| `active_connectors` | `connectors` | Enabled data sources, right now |
| `seats` | `users` | Active user accounts, right now |

`triages_model` and `triages_deterministic` partition `alerts` exactly: their
sum equals the total, so there is no triage unaccounted for and none counted
twice.

The last two are point-in-time rather than windowed. Counting them per day
would report today's value against every historical day, which looks like
data and is not.

## What is not measured

`events_ingested` lives in the ClickHouse event lake, which runs in the
`full` profile. On a deployment without it, that meter is reported as **not
measured**, named with the reason, in both the API response and the CSV
header.

It is never reported as `0`. Zero is a measurement, and a reader who sees it
concludes no events arrived rather than that nothing looked.

## Reading it

```bash
curl "https://<your-aisoc-host>/api/v1/usage?start=2026-03-01&end=2026-03-31" \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN"
```

Defaults to the last 30 days. The maximum window in one request is 186 days;
export a month at a time beyond that.

The response carries the daily series, the totals, the point-in-time figures,
the meters' own definitions and source tables, whatever was not measured, and
the entitlement headroom those counts run against. The last of those is
deliberate: a usage screen and a quota screen that compute their numbers
separately are two surfaces that will eventually disagree in front of a
customer.

The tenant comes from your credential. There is no tenant parameter on any of
these routes, because usage is the input to a commercial conversation and a
surface that let one customer name another's tenant would publish their
volume.

## Monthly CSV

```bash
curl "https://<your-aisoc-host>/api/v1/usage/export.csv?month=2026-03" \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" -o march.csv
```

Requires `reports:read`. The file carries a header block naming the tenant,
the operator organisation and the generation time, because a bare grid of
numbers in a downloads folder cannot answer what it is about.

## Checking the numbers

Metering is computed from the source tables when you ask, rather than kept in
a counter table that is incremented as things happen. A counter drifts from
the table it summarises and nothing notices; a query cannot, because the
number *is* the rows.

You can verify that directly:

```bash
curl "https://<your-aisoc-host>/api/v1/usage/reconciliation?start=2026-03-01&end=2026-03-31" \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN"
```

This runs each meter twice, once per day and summed, and once as a single
query over the whole window, and reports both figures with whether they
agree. Day boundaries are where a row gets dropped or counted twice, and
neither shows up in a single-day check.

The same comparison runs in CI against a seeded corpus, including an alert
placed at exactly midnight.
