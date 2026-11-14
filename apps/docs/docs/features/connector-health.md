---
sidebar_position: 1
title: Connector health & schema-drift sentinel
description: How AiSOC fingerprints every connector's event schema, detects drift the moment a vendor changes its API, and gives you a single pane of health across every integration.
---

# Connector health and schema-drift sentinel

Every SOC integration breaks the same way: a vendor ships an API change in their next release, your normalizer silently starts dropping fields, and three weeks later somebody notices a detection went quiet. The schema-drift sentinel exists so that hour-zero is the same as hour-three-weeks: AiSOC notices the drift on the next poll and surfaces it before any downstream rule misfires.

This page documents the model, the API surface, and how to operate it.

## What it does

Every time the connector scheduler polls a vendor and normalizes a batch of events, AiSOC computes a stable **schema fingerprint** — a SHA-256 hash of the sorted set of top-level field names in the normalized payload. That fingerprint is stored on the connector instance.

On the next poll:

- If the fingerprint matches, we record a successful run.
- If it changes, we **diff the previous and current field sets**, persist the drift event with `added`/`removed` fields and the previous/current fingerprint, and surface it via the connector health API.

Because the hash is over the *normalized* schema (not the raw vendor payload), it is stable across order-of-fields changes, cosmetic vendor renames that the connector silently rewrites, and value-only changes — but it changes the moment a real field appears or disappears.

## Why fingerprints, not full diffs

The naive design is "store the whole schema and diff it every time." We don't, for three reasons:

1. **Cheap to compute, cheap to store.** A 32-byte hash per connector beats keeping every prior schema around.
2. **No PII or vendor data leaks into the audit trail.** The fingerprint reveals nothing about the events themselves — it's a one-way hash of the field-name set.
3. **Equality check is O(1).** The hot path on every poll is a single string compare.

When drift is detected, we then *also* persist the human-readable diff (`added`/`removed`/`previous_fingerprint`) so an operator can read what changed without recomputing it.

## Health surface

`GET /api/v1/connectors/health` returns a tenant-scoped health summary:

```json
{
  "total": 12,
  "healthy": 10,
  "degraded": 1,
  "error": 0,
  "drift_in_last_24h": 1,
  "events_dropped_total": 247,
  "instances": [
    {
      "id": "...",
      "connector_id": "github",
      "name": "github-prod",
      "health_status": "healthy",
      "schema_fingerprint": "a3f9...",
      "last_schema_drift_at": null,
      "last_drift_details": null,
      "events_dropped": 0,
      "last_run_at": "2026-05-07T22:31:04Z"
    }
  ]
}
```

The per-instance fields:

| Field | Meaning |
|---|---|
| `schema_fingerprint` | Current normalized-schema hash. |
| `last_schema_drift_at` | Timestamp of the most recent drift event (null if never). |
| `last_drift_details` | `{ "added": [...], "removed": [...], "previous_fingerprint": "..." }`. |
| `events_dropped` | Cumulative count of events the pre-ingest filter dropped (see [Security data pipeline](./data-pipeline.md)). |
| `health_status` | `healthy`, `degraded`, or `error` — derived from recent run history. |

## Operational notes

- **Drift is not a failure.** A drift event is informational: it says "the shape of your incoming events changed". The connector keeps polling. You decide whether to investigate, update the normalizer, or accept the change.
- **First run sets the baseline.** A connector with no prior fingerprint adopts the first observed one without raising drift; only subsequent polls trigger drift events.
- **Empty batches don't reset the fingerprint.** A poll that returns zero events leaves the prior fingerprint intact, so transient vendor outages don't show up as drift.

## Where it lives in the code

- Fingerprinting helpers: `services/connectors/app/pipeline/fingerprint.py`
- Filter rules (used to compute `events_dropped`): `services/connectors/app/pipeline/filter_rules.py`
- Drift integration in the polling loop: `services/connectors/app/scheduler.py`
- API surface: `services/api/app/api/v1/endpoints/connectors.py` (`/health`)
- Schema migration: `services/api/migrations/026_connector_schema_drift.sql`

If you're adding a new connector, you don't need to do anything — the scheduler computes the fingerprint from the normalized batch your `normalize()` returns. Drift detection is implicit.
