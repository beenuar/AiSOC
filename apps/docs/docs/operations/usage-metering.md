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
| `triages_model` | `investigation_runs` | Auto-triage runs that reached a model |
| `triages_deterministic` | `investigation_runs` | Auto-triage runs answered without a model |
| `investigations` | `investigation_runs` | Runs that are not auto-triage: an analyst or an escalation asked for these |
| `llm_tokens` | `aisoc_run_costs` | Prompt plus completion tokens |
| `llm_cost_usd` | `aisoc_run_costs` | Measured model spend |
| `actions` | `aisoc_action_records` | Response actions recorded |
| `actions_executed` | `aisoc_action_records` | Of those, the ones whose executor ran and succeeded |
| `actions_automatic` | `aisoc_action_records` | Graded as runnable without a human |
| `actions_human_gated` | `aisoc_action_records` | Graded as needing a human, or refused by the action's contract |
| `actions_tier_unrecorded` | `aisoc_action_records` | Submitted before the approval tier was recorded on the row |
| `events_ingested` | `aisoc.raw_events` | Normalised events written to the lake |
| `active_connectors` | `connectors` | Enabled data sources, right now |
| `seats` | `users` | Active user accounts, right now |

The three triage and investigation meters partition `investigation_runs`
exactly: their sum equals the run count, so there is no run unaccounted for
and none counted twice. The three action tiers partition `actions` the same
way.

They partition runs rather than alerts, which is the honest shape: an alert
can be re-triaged, and an alert that arrived before auto-triage was switched
on has no run at all.

### Why the triage meters read the run and not the alert

`alerts.ai_summary` and `alerts.ai_score` record that a verdict exists. They
do not record which path produced it — the deterministic path writes both
columns from the same statement the model path does. A meter reading them
reported a deployment with no model configured at all as 100% AI-triaged.

What does record the path is `investigation_runs.model_used`, which
auto-triage stamps as `kafka:auto_triage:llm` or
`kafka:auto_triage:deterministic`. That is what these meters read, and it is
also what `triages_per_month` counts against your plan limit, so the usage
screen and the quota screen cannot disagree about the same rows.

`active_connectors` and `seats` are point-in-time rather than windowed.
Counting them per day would report today's value against every historical
day, which looks like data and is not.

## What is not measured

`events_ingested` lives in the ClickHouse event lake, which runs in the
`full` profile. On a deployment **without** the lake it is reported as **not
measured**, named with the reason, in both the API response and the CSV
header; on a deployment with one it is a column like any other.

It is never reported as `0`. Zero is a measurement, and a reader who sees it
concludes no events arrived rather than that nothing looked. The same
applies if the lake is deployed and unreachable: the request still answers,
the meter still reads "not measured", and the failure is logged.

The lake is a `ReplacingMergeTree` keyed on the event id, so a connector
replaying an event writes a second row that a background merge later
collapses. This meter counts rows as stored, which can therefore exceed the
number of distinct events until that merge runs.

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

## The portfolio CSV

If you run AiSOC for several customers, export the whole portfolio in one
request:

```bash
curl "https://<your-aisoc-host>/api/v1/usage/organization/export.csv?month=2026-03" \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" -o march-portfolio.csv
```

One grid per managed tenant, then a `portfolio total` row computed from
those grids rather than asserted beside them — a tenant missing from the
grids is missing from the total, and the two cannot disagree.

The tenant list is the same portfolio scope the rest of the MSSP API uses,
so an organisation member scoped to three of forty tenants exports three. A
principal who belongs to no operator organisation is refused with a `403`
rather than quietly handed their own tenant: an export that silently changes
scope is worse than one that fails.

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
