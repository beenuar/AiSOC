---
sidebar_position: 1
title: Funnel KPIs and pipeline health
description: How AiSOC turns raw telemetry into a six-tile operations funnel, an efficiency report, and a five-stage pipeline-health rail on the dashboard — backed by /metrics/funnel and /health/pipeline.
---

# Funnel KPIs and pipeline health

Tier-1 SOC consoles open on the same picture: a row of funnel tiles that says how much signal made it into the analyst's queue, an efficiency report that says how well the pipeline converted raw events into alerts, and a per-stage health rail that says where the next outage will come from. v1.5 brings that picture to AiSOC's `/dashboard` without breaking the existing flat per-page layout.

This page documents the three widgets, their data sources, and the endpoints they call.

## Where the widgets sit

The new `funnel-kpis` and `efficiency-and-pipeline` widgets render at the top of `/dashboard`, above the existing top-metrics row. Both are drag-and-drop reorderable; their order persists in `localStorage` under `aisoc:dashboard-widget-order` (the dashboard auto-migrates older saved orders to include the new widgets).

```
┌──────────────────────────────────────────────────────────────────────┐
│  Welcome                                                             │
├──────────────────────────────────────────────────────────────────────┤
│  Operations Funnel  ─ 6 tiles                                        │
│  Events of Interest  · Correlation Inst.  · Alerts Generated         │
│  Signal / Noise      · MTTD               · Analyst Queue            │
├──────────────────────────────────────────────────┬───────────────────┤
│  Efficiency Report                               │  Pipeline Health  │
│  Correlation efficiency                          │  Ingest           │
│  Alert yield                                     │  Normalize        │
│  MITRE coverage                                  │  Fuse             │
│                                                  │  Correlate        │
│                                                  │  Alert            │
└──────────────────────────────────────────────────┴───────────────────┘
```

## `FunnelKpiBar` — six tiles, one period

The bar renders six tiles in fixed order. Each tile carries an absolute value and, where the API returns one, a period-over-period delta:

| Tile | Value | Delta direction |
|---|---|---|
| Events of Interest | normalized events in window | up is good |
| Correlation Instances | fired correlations in window | up is good |
| Alerts Generated | alerts created in window | up is good |
| Signal / Noise | `1 − (FP / dispositioned alerts)` | up is good |
| MTTD | mean `created_at → first_seen_at` across alerts in window | **down is good** |
| Analyst Queue | active alerts in `new`/`triaging`/`in_progress` | **down is good** |

Delta direction matters because the same percent change has the opposite meaning on MTTD or Queue: a +20% Analyst Queue is bad, a +20% Alerts Generated is good. The component encodes this so the green/red coloring is correct without the operator having to think about it.

Loading and error states are deliberately quiet:

- **Loading** — six skeleton tiles with the same labels and shape as the loaded view, so the layout never jumps.
- **Error** — a single "Funnel metrics unavailable" line replaces the tiles; the rest of the dashboard keeps rendering. `useSWR` is configured with `shouldRetryOnError: false` so a 5xx doesn't melt the API.

## `EfficiencyReport` — how well the pipeline converts

Three bars, all clamped to `[0, 1]` so the visualization never overflows:

1. **Correlation efficiency** = `alerts / correlation_instances`. Clamped to `1.0`. Tells you how much of your correlation work turned into an actual alert.
2. **Alert yield** = `alerts / events_of_interest`. Always tiny — `0.00208` is healthy. Tells you what fraction of raw signal made it to an analyst.
3. **MITRE coverage** = `covered / total`. Surfaces "42 / 201 · 20.9%" — the count of distinct MITRE tactic + technique IDs (`Txxxx` and `TAxxxx`) referenced by detection rules with at least one alert in the window, divided by the configured total (see [Tunables](#tunables)).

The `EfficiencyReport` and `FunnelKpiBar` deliberately share an SWR cache key (`funnel-metrics:<period>`) so both widgets de-dupe on a single call to `GET /api/v1/metrics/funnel`.

## `PipelineHealth` — five stages, four statuses

The rail mirrors the data path end-to-end:

```
Ingest → Normalize → Fuse → Correlate → Alert
```

Each stage card shows:

- **Backlog** — queued items waiting for the stage. Sourced from connector-level backlog counters for `ingest`/`normalize` and from `alert`-table row counts in `new`/`pending` for `alert`.
- **p95 latency (ms)** — derived from existing alert timestamp fields (`created_at`, `first_seen_at`, `fused_at`, etc.) so we don't need a separate metrics store. Stages without a meaningful latency signal report `0`.
- **Error rate** — fraction of failed runs in the window. Sourced from `Connector.last_error_at` / `last_success_at` counters and aggregated.
- **Status** — `unknown | green | yellow | red`, derived from the same `compute_freshness` service that powers the existing connector health page (`services/api/app/services/connector_freshness.py`) plus per-stage staleness thresholds. The top-of-rail badge reports the worst stage status.

`refreshInterval` is 30 s for pipeline health and 60 s for the funnel — fast enough to spot a fuse-stage backlog spike, slow enough not to pound the API.

## Endpoints

### `GET /api/v1/metrics/funnel`

```
GET /api/v1/metrics/funnel?period=1h|24h|7d|30d
```

Returns:

```json
{
  "period": "24h",
  "events_of_interest": 94612,
  "correlation_instances": 73515,
  "alerts_generated": 153,
  "signal_to_noise": 0.864,
  "mttd_seconds": 252,
  "analyst_queue_depth": 27,
  "correlation_efficiency": 0.777,
  "alert_yield": 0.00208,
  "mitre_coverage": { "covered": 71, "total": 100, "ratio": 0.71 },
  "deltas": {
    "events_of_interest": 0.037,
    "correlation_instances": 0.012,
    "alerts_generated": -0.04,
    "signal_to_noise": 0.005,
    "mttd_seconds": -0.18,
    "analyst_queue_depth": 0.20
  },
  "generated_at": "2026-05-13T10:00:00Z"
}
```

Key implementation notes (`services/api/app/api/v1/endpoints/metrics.py`):

- Tenant-scoped via `AuthUser`; every query joins on `tenant_id` or — for ClickHouse — passes through `services/api/app/services/lake_sql.py:rewrite_for_tenant` which uses `sqlglot` to enforce the tenant clause before the query reaches the lake.
- `events_of_interest` reads from ClickHouse `aisoc.raw_events` when the lake is enabled, with a Postgres-only fallback (alerts table count) for air-gapped deployments where `AISOC_DISABLE_CLICKHOUSE=1`.
- `mttd_seconds` reuses the exact same `AVG(EXTRACT EPOCH FROM (created_at - first_seen_at))` expression as the existing SOC metrics endpoint so the two never disagree.
- `signal_to_noise` is `1 − (FP count / total dispositioned)` — alerts with `disposition` in `false_positive` divided by alerts with any disposition. Returns `0.0` when there is no dispositioned alert (no work done yet).
- Deltas are signed fractions, not percent: `0.05` means +5%. The previous-period window is the same duration immediately before the current one.

### `GET /api/v1/health/pipeline`

```
GET /api/v1/health/pipeline
```

Returns:

```json
{
  "overall_status": "yellow",
  "stages": [
    {"stage": "ingest",    "backlog":  0, "p95_latency_ms":  120, "error_rate": 0,    "status": "green"},
    {"stage": "normalize", "backlog":  5, "p95_latency_ms":  200, "error_rate": 0.01, "status": "green"},
    {"stage": "fuse",      "backlog": 42, "p95_latency_ms": 1800, "error_rate": 0.03, "status": "yellow"},
    {"stage": "correlate", "backlog": 12, "p95_latency_ms":  600, "error_rate": 0,    "status": "green"},
    {"stage": "alert",     "backlog":  3, "p95_latency_ms":  300, "error_rate": 0,    "status": "green"}
  ],
  "generated_at": "2026-05-13T10:00:00Z"
}
```

`overall_status` is the worst per-stage status (`red > yellow > green > unknown`) and drives the colored badge at the top of the rail.

## Tunables

Configuration lives in `services/api/app/core/config.py`:

| Setting | Default | Purpose |
|---|---|---|
| `AISOC_FUNNEL_MITRE_TOTAL` | `201` | Denominator for MITRE coverage. Set to your active framework's technique count (e.g. ATT&CK Enterprise v15 = 201). The numerator is computed live from rules with at least one alert in window. |
| `AISOC_PIPELINE_STALE_WARN_SECONDS` | `300` | Per-stage staleness threshold below which a stage stays `green`. Above this, the stage flips to `yellow`. |
| `AISOC_PIPELINE_STALE_DOWN_SECONDS` | `900` | Per-stage staleness threshold above which a stage flips to `red`. |

All three are env-driven and tenant-uniform (deliberately — the picture of "is my pipeline healthy" should not vary per tenant).

## Why this shape

A few design choices are worth calling out:

1. **One endpoint, two widgets.** `FunnelKpiBar` and `EfficiencyReport` are split for layout reasons, not data-fetching reasons. Sharing the SWR key means the dashboard makes one network call for both. If we ever need to refresh the efficiency report independently, the cache key would split.
2. **No mock data, anywhere.** The previous `34%` SNR in `NoiseTuningView` was the only mocked KPI left in v1.4. It now reads from this endpoint and falls back to a deterministic local computation only when the API is unreachable — never to a fixed constant.
3. **Stages, not connectors.** The reference SOC console renders pipeline health per-stage, not per-connector, because operators want to know "is fusion behind?" — not "which of 47 connectors is having a bad day." The connector health page (`/health`) still exists for the per-connector drill-down.
4. **Worst-status badge.** The top-of-rail status is intentionally pessimistic. A single red stage flips the rail to red, because in SOC operations the worst link defines the chain.

## Operator playbook

| Symptom | Likely cause | First check |
|---|---|---|
| MTTD tile is red and rising | Triage queue is backlogged, or alerts are firing without `first_seen_at` getting written | Open `/queue` and look at oldest unclaimed; verify the alert worker is running |
| Signal / Noise dropping below `0.5` | Recent rule change is over-firing | `/detection/tuning` to find the noisiest rule |
| Fuse stage in yellow with high backlog | Correlation rule is slow or unbounded | Inspect last fusion logs; check rule windowing |
| All stages `unknown` | No connectors have polled in `> AISOC_PIPELINE_STALE_DOWN_SECONDS` | Likely a deployment issue, not a data issue — check the connector scheduler |

## Related

- [Connector health and schema-drift sentinel](../features/connector-health.md) — the per-connector drill-down behind the ingest stage.
- [Credentials vault](../operations/credentials.md) — how connector credentials are encrypted at rest.
- [Architecture](../architecture.md) — the full data-flow diagram these widgets render against.
