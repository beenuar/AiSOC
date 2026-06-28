# Runbook: `AisocDetectionPipelineStalled`

> **Severity:** critical (pages)
> **Alert source:** [`aisoc-pipeline-kpis` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

`sum(rate(aisoc_detections_emitted_total[15m]))` is **zero**
while the ingest service is healthy. AiSOC's central product —
emitting alerts from telemetry — has stopped working. This is the
single alert that should panic the on-call: every other alert
indicates degradation; this one indicates the customer's SOC is
flying blind.

Three plausible causes:

1. **Every detection rule is suppressed.** A bad bulk-suppress
   action from the console, or a tenant-wide tuning rule that
   matched too aggressively.
2. **The rule engine has stopped evaluating.** The
   `services/api/app/detections/runtime.py` evaluator loop has
   crashed, deadlocked, or is awaiting a downstream call (Redis,
   Postgres, ClickHouse) that's hung.
3. **The telemetry stream is empty.** Ingest is healthy but no
   connector is sending data — every connector is throttled,
   credentials rotated, etc. Phase 3.x connectors are the long
   tail.

## First five minutes

```bash
# 1. Are detections evaluating but matching nothing?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=rate(aisoc_detections_evaluated_total[5m])'

# 2. Suppression rate — is everything getting filtered?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=rate(aisoc_detections_suppressed_total[5m])'

# 3. Is the connector queue dry?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=rate(aisoc_connector_events_emitted_total[5m])'

# 4. Last-50 detection-engine log entries.
docker compose logs api --tail 200 \
  | grep -E '"name":"detections\."' \
  | tail -30
```

## Mitigation

- **All detections suppressed:** check the suppression table:
  ```sql
  SELECT rule_id, suppressed_until FROM detection_suppressions
   WHERE suppressed_until > now()
   ORDER BY suppressed_until DESC LIMIT 20;
  ```
  Roll back any tenant-wide suppression that was added in the
  last 30 minutes; restoring fired detections is recoverable
  only via the immutable ledger, so unblocking the FUTURE stream
  is the priority.
- **Engine evaluating nothing:** restart the API service to
  force the evaluator loop to re-bootstrap. If it doesn't
  recover, capture a thread dump (`docker compose exec api
  py-spy dump --pid 1`) before restarting.
- **Telemetry empty:** check each enabled connector's last poll
  time:
  ```sql
  SELECT type, name, last_poll_at FROM connectors
   WHERE enabled = true ORDER BY last_poll_at;
  ```
  Any connector with `last_poll_at < now() - interval '15 min'`
  is stuck; re-trigger the scheduler:
  ```bash
  docker compose --profile connectors restart connectors
  ```

## Root cause

- If this fired DURING the demo seed, the seed itself is silent
  on detection emission — file a follow-up bug. The seed should
  load enough telemetry that at least one rule fires per
  minute.
- If this fired in production, the post-mortem MUST surface:
  the time-to-first-detection after restart, the missing alert
  type (which rule should have fired), and the alert that
  proves the runtime is healthy now. Don't close the incident
  on "we restarted and it came back" alone.

## References

- Source rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- Detection runtime: `services/api/app/detections/runtime.py`
- Suppression table: `services/api/app/db/models/detection_suppression.py`
- Connector scheduler: `services/connectors/app/scheduler.py`

Updated: **2026-06-28** (Phase 2.5).
