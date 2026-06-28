# Runbook: `AisocHttpErrorRateHigh`

> **Severity:** critical (pages)
> **Alert source:** [`aisoc-http-latency` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

`{{ $labels.job }}` is returning HTTP 5xx for **more than 5% of
requests over the last 5 minutes**, excluding the `/metrics`
scrape. This is a customer-visible failure: every request to the
SOC console UI funnels through `services/api`, and every fired
detection writes through `services/api` to Postgres. A sustained
5xx burst means the operator's analysts cannot work the queue.

## First five minutes

```bash
# 1. Which handler is bleeding?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=topk(5,sum%20by%20(handler)(rate(http_requests_total{job="<job>",status=~"5.."}[5m])))'

# 2. Tail the structured logs for stack traces.
docker compose logs <service> --tail 200 \
  | grep -E '"level":"(error|critical)"' \
  | tail -20

# 3. Postgres connection state — saturation = 5xx storm.
docker compose exec postgres psql -U aisoc aisoc \
  -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# 4. Is the upstream LLM provider (when agents service is the
#    affected job) returning 5xx itself?
docker compose logs agents --tail 200 \
  | grep -E 'openai|anthropic' \
  | tail -10
```

## Mitigation

- **One handler is 100% failing while others are clean:** the
  most recent deploy introduced a code path that always errors.
  Pin the previous image tag in `.env` and `docker compose up -d
  <service>`. Open a follow-up bug to investigate offline.
- **All handlers are degrading uniformly:** dependency outage —
  Postgres, Redis, Kafka, or the LLM provider. Check the
  `aisoc-availability` dashboard.
- **5xx burst correlates with deploy time:** revert. The dev
  stack does not yet ship blue-green; `docker compose up -d
  <service>` is the rollback.
- **LLM provider 5xx storm (agents service only):** flip
  `AISOC_LLM_PROVIDER=mock` in the agents service env vars and
  restart. The mock provider returns deterministic stubs so
  customer-facing detection / triage continues without the LLM.
  Re-enable real LLM once the upstream is healthy.

## Root cause

- **Always:** capture a sample of the 5xx response bodies and
  attach to the post-mortem. The FastAPI exception handler
  records a `request_id` in the structlog; reproducing the
  request offline starts there.
- **For deploys:** what guard tests would have caught this?
  Phase 2.1's wave-2 service tests are the first answer; missing
  cases land as new test files in the same diff that ships the
  fix.

## References

- Source rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- `request_id` middleware: `services/api/app/middleware/`
- LLM provider switch: `services/agents/app/llm/__init__.py`

Updated: **2026-06-28** (Phase 2.5).
