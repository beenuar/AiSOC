---
sidebar_position: 7
title: SOC operations dashboard
description: Whether the detection pipeline is working, independent of whether it is finding anything — connector staleness, rejected events, alert posture, detection coverage, agent spend and pending response actions.
---

# SOC operations dashboard

`/dashboard` answers *what is happening in the estate*. `/dashboards/operations` answers a different question: **is the machine that tells me what is happening actually working?**

That distinction matters because every failure mode of a detection pipeline makes it **quieter**. A connector stops polling, a schema changes and events start bouncing, an API token expires — and the alert queue gets calmer. An alert-centric dashboard reports that as good news. The only way to tell "the estate is quiet" from "the pipeline stopped" is to watch the pipeline directly.

## Panels

Each panel is backed by exactly one endpoint, owns its own fetch, and renders one of three states: real figures, an honest empty state, or an error state with a retry. **No panel substitutes sample data.** One dead endpoint blanks one panel and says why; it does not take the page down and does not quietly degrade its neighbours.

### Connector fleet

`GET /api/v1/health/fleet`

Per-connector state, with the server's own operator-actionable wording (`No successful sync for 3.2 poll intervals`) rendered verbatim rather than re-derived into a generic "unhealthy".

Staleness is measured **against each connector's own configured cadence**, which is why the panel reports "3.2 intervals behind" rather than an absolute age. A single global threshold would page constantly on a daily connector and stay silent on a five-minute one, and a surface that pages constantly is a surface that gets muted. Below one missed interval the panel falls back to wall-clock ("synced 12m ago"), which is the more useful reading when nothing is actually late.

Rows sort worst-first. The header badge counts `failed + degraded`, because the fleet is as healthy as its least healthy connector — averaging would let nineteen working connectors hide the one that stopped, and the one that stopped is the whole question.

### Pipeline health

`GET /api/v1/health/pipeline`

The existing per-stage widget (ingest → normalize → fuse → correlate → alert), reused rather than reimplemented.

### Rejected events

`GET /api/v1/health/dead-letters?hours=24`

The companion to fleet health. A connector can poll happily while everything it produces is refused downstream for a schema mismatch, and the symptom from the alert queue is identical: nothing arrives.

Grouped by reason, so the fix is visible from the panel. "Nothing rejected" renders as its own explicit state rather than an empty list, because zero is a real answer here and should not look like a panel that failed to load.

### Alert posture

`GET /api/v1/alerts/stats`

Total, new in 24h, critical still open, plus severity and disposition distributions.

This is a **snapshot, not a trend**, and the panel says so. No endpoint in the tree buckets disposition over time, so there is no series to draw. Period-over-period movement is published by `/metrics/funnel` and rendered by the funnel strip at the top of the page; nothing here duplicates it with an arrow it cannot source.

### Detection coverage

`GET /api/v1/detection/coverage`

Techniques with at least one **enabled** rule, over total techniques. The active-versus-total distinction is the point: a corpus of 800 rules with half disabled covers far less than the headline suggests, and a disabled rule is exactly as useful as no rule. Disabled rules are named explicitly rather than folded into a total.

"Thinnest tactics" ranks by active-coverage ratio — the part an operator can act on this week. Techniques with no tactic attribution are counted in the summary but not ranked, because inventing an "Unknown" bucket would imply a gap in a tactic that does not exist.

### Agent throughput and spend

`GET /api/v1/costs/dashboard?window_days=7`

Real recorded token counts and spend, joined from `aisoc_run_costs` to `investigation_runs` — measured usage, not a projection or a list price.

The counter is labelled **runs**, because `total_runs` counts investigation runs. Labelling it "alerts triaged" would be a different measurement than the one the endpoint takes. The average cost per run is rendered only when the server supplies it; dividing locally when the server returned `null` would manufacture a figure it declined to state.

### Actions awaiting approval

`GET /api/v1/approvals?status=pending`

The agent pauses before a high-risk action — isolate a host, disable an account, revoke a session — and waits. Until someone decides, the containment has not happened, so an approval sitting unnoticed for two hours is an incident still running. The panel sorts by risk then age, and shows how long each has been waiting.

Deciding happens on `/responder/approvals`, which already does it properly with full context and deny-with-comment. This panel links there rather than growing a second approve button: a one-tap irreversible action inside a dashboard tile is a worse affordance than a link to the surface built for it.

## Permissions

| Panel | Permission |
| --- | --- |
| Connector fleet, rejected events, pipeline health | authenticated |
| Alert posture | `alerts:read` |
| Detection coverage | `rules:read` |
| Agent throughput and spend | `reports:read` |
| Actions awaiting approval | authenticated |

A panel whose permission the caller lacks shows its error state with the API's own message, rather than disappearing — a missing panel is indistinguishable from a healthy one.

## Refresh cadences

Fleet health, rejected events, alert posture: 60s. Pending approvals: 30s. Agent spend: 120s. Detection coverage: 5 minutes. These are chosen against how fast each figure can meaningfully change, not set uniformly.
