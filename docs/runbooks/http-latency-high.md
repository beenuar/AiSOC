# Runbook: `AisocHttpP95LatencyHigh`

> **Severity:** warning (ticket)
> **Alert source:** [`aisoc-http-latency` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

The 95th-percentile HTTP request latency for `{{ $labels.job }}`
has exceeded **1.5 seconds for the last 10 minutes**, excluding
the `/metrics` scrape. p95 — not p99 — is the right tier here:
p99 is too noisy for a sustained-trigger alert, p50 hides the
"long tail of 5% slow requests" failure mode that customers
actually notice.

Common root causes, in order of likelihood:

1. Postgres slow query (missing index, full-table scan on a
   newly-large table).
2. Redis pool saturation (every request blocking on a connection
   acquire).
3. Kafka consumer lag back-pressuring the API's `await
   producer.send_and_wait(...)`.
4. Upstream LLM provider slow (only on agent service).

## First five minutes

```bash
# 1. Top contributing handlers.
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=topk(5,histogram_quantile(0.95,sum%20by%20(handler,le)(rate(http_request_duration_seconds_bucket{job=~"<job>"}[5m]))))'

# 2. Database slow-query log (the API + agents service both use
#    the same Postgres).
docker compose exec postgres psql -U aisoc aisoc \
  -c "SELECT pid, now() - query_start AS dur, state, query
       FROM pg_stat_activity
       WHERE state='active' AND now() - query_start > '500ms'
       ORDER BY dur DESC LIMIT 10;"

# 3. Redis connection pool stats (FastAPI service uses
#    `redis.asyncio.from_url` with a default pool size of 10).
docker compose exec redis redis-cli INFO clients | head -10

# 4. Are we Kafka-blocked?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=kafka_consumer_lag_records'
```

## Mitigation

- **Slow query on a specific handler:** check `EXPLAIN
  (ANALYZE, BUFFERS)` for the top-contributing query. If the plan
  shows a sequential scan on a column we filter often, add the
  missing index in a migration and apply with zero downtime
  (`CREATE INDEX CONCURRENTLY`).
- **Redis pool saturation:** double the pool size in the affected
  service's `REDIS_URL` (?max_connections=20) and restart. This
  is band-aid; the real fix is identifying the leaking caller
  with `redis-cli CLIENT LIST` filtered by source IP.
- **Kafka lag back-pressure:** increase the producer queue depth
  in the affected service's config OR temporarily drop the
  request-level Kafka write to log-only (the API's
  `audit_log` writer is the typical culprit).

## Root cause

Once mitigated, capture:

- The query (or call graph) that drove p95 up.
- The volume change vs. the previous week (rollup with `1d` step).
- Any deploys in the past 24h that touched the slow path.

## References

- Source rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- FastAPI instrumentation lives in `services/<svc>/app/
  observability/metrics.py`.
- Postgres slow-query log is enabled in `docker-compose.yml` via
  `command: -c log_min_duration_statement=500ms`.

Updated: **2026-06-28** (Phase 2.5).
