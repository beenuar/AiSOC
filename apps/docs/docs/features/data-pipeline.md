---
sidebar_position: 2
title: Security data pipeline & tiered retention
description: Declarative, per-connector pre-ingest filter rules that drop or keep events before they hit hot storage, plus the tiered retention model that backs them.
---

# Security data pipeline and tiered retention

Most SIEMs treat ingest as a tax: every event goes in at the same cost, and you pay until the bill forces you to drop sources. AiSOC takes a different stance — **decide what to keep before it crosses the wire**, with simple, declarative rules that are easy to read in a code review.

## The pre-ingest filter

Every connector instance can carry a `filter_rules` block in its config. On every poll, after normalization but before the events are pushed to ingest, the scheduler runs the filter and either drops or keeps each event.

```yaml
filter_rules:
  - field: "raw.severity"
    op: "eq"
    value: "informational"
    action: "drop"
  - field: "raw.action"
    op: "in"
    value: ["allow", "ignore"]
    action: "drop"
  - field: "raw.user.email"
    op: "ends_with"
    value: "@partner.example.com"
    action: "keep"
```

Rules are evaluated **first match wins**. An event with no matching rule is kept by default — filters are an opt-in deny list, not a strict allow list.

### Supported operators

| Operator | Meaning |
|---|---|
| `eq` / `ne` | Exact equality / inequality. |
| `contains` | Substring match (case-sensitive). |
| `starts_with` / `ends_with` | Prefix / suffix match. |
| `in` | Value is in a list of allowed values. |

The `field` selector is a dotted path into the normalized event (e.g. `raw.severity`, `entities.user.email`). Missing fields cause the rule to skip rather than crash, so a malformed rule degrades gracefully — the event passes through.

### Why declarative, not a Lua hook

We deliberately keep the filter language small:

- **It reads in a code review.** A junior analyst can audit a YAML block.
- **It serializes cleanly.** Filter rules live in `connector_config.filter_rules` and are versioned with the rest of the connector instance.
- **It can't fork, exec, or call out.** The pre-ingest path is on the hot poll loop. Limiting expressiveness is a feature, not a bug.

If you genuinely need a Turing-complete enrichment step, that belongs in the enrichment service, not the filter.

## Drop counters

Every dropped event increments `events_dropped` on the connector instance. That counter is surfaced both per-instance and aggregated across the tenant in `GET /api/v1/connectors/health`:

```json
{
  "events_dropped_total": 247,
  "instances": [
    { "name": "cloudflare-prod", "events_dropped": 247, ... }
  ]
}
```

This lets you answer "is the filter doing what I think it's doing?" without grepping logs.

## Tiered retention model

The pipeline assumes a three-tier storage layout:

| Tier | Backend | Default retention | Purpose |
|---|---|---|---|
| **Hot** | OpenSearch | 7-30 days | Detection rules, real-time queries, the last week of activity. |
| **Warm** | ClickHouse / Parquet on object store | 90 days | Historical investigation, hunt queries, compliance look-back. |
| **Cold** | Object store (S3 / R2) | 1 year+ | Compliance archive. Queryable on demand, cheap at rest. |

The pre-ingest filter sits *in front* of all three: an event the filter drops never lands in any tier. That makes it the highest-leverage knob you have for cost control — drops are free, retries on hot storage are not.

## Operational guidance

- **Start permissive, then tighten.** First week of any new connector: no filter rules. Watch the volume. Then add rules to drop the noisy floor (informational severity, repeated noisy-actor health checks, etc.).
- **Filter rules are per-instance.** Two GitHub connectors for two orgs can have completely different rule sets.
- **`events_dropped` is monotonic.** Reset the counter by re-creating the instance if you want a clean window.
- **Don't filter what detections need.** A detection that triggers on `severity=informational` will silently never fire if a filter drops those events. Review filter rules whenever you ship a new detection rule.

## Where it lives in the code

- Filter engine: `services/connectors/app/pipeline/filter_rules.py`
- Filter integration in the polling loop: `services/connectors/app/scheduler.py`
- Drop counter persistence: `services/connectors/app/db/connector_repo.py`
- API surface: `services/api/app/api/v1/endpoints/connectors.py`
