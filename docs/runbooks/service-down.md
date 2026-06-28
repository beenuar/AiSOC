# Runbook: `AisocServiceDown`

> **Severity:** critical (pages)
> **Alert source:** [`aisoc-availability` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

Prometheus has been unable to scrape `/metrics` from a registered
target for at least 2 minutes. The scrape target's `up` metric is
0, which means one of:

- the container is stopped or crash-looping;
- the container is up but the application isn't listening on the
  metrics port (mis-pinned env var, blocked init);
- the container is up and listening but the metrics path 404s
  (route mis-registered);
- a network split between Prometheus and the target.

The alert label `{{ $labels.job }}` names the affected scrape job
(e.g. `aisoc-api`). The mapping job → container → port lives in
[`scripts/audit_prometheus_targets.py`](../../scripts/audit_prometheus_targets.py).

## First five minutes

```bash
# 1. Confirm the alert is current (not stale).
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=up{job="<job>"}'

# 2. Container running?
docker compose ps <service>

# 3. Last container exit reason.
docker compose logs --tail 80 <service>

# 4. Is the metrics port reachable from the same network?
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://<host>:<port>/metrics' | head -20
```

If step 4 returns HTML or a 404, the service is listening but the
`/metrics` route isn't registered. If it times out, the listener
itself is down (step 2/3 will tell you why).

## Mitigation

In priority order:

1. **Container down:** `docker compose restart <service>`. If it
   re-enters crash loop, capture `docker compose logs <service>
   --tail 200` for the post-mortem, then pin a known-good image
   tag in `.env` (`AISOC_VERSION=<previous-tag>`) and
   `docker compose up -d <service>`.
2. **Container up, app not bound to port:** check the env vars
   the application reads for its port. The `api` service binds
   `0.0.0.0:8000`; the `ingest` service reads `METRICS_PORT` (set
   in `docker-compose.yml`).
3. **Network split:** if Prometheus itself is unhealthy
   (`docker compose ps prometheus` shows `restarting`), restart
   Prometheus AFTER fixing it. Otherwise: `docker network inspect
   aisoc` and look for the service among `Containers`.

## Root cause

After bleeding has stopped, capture the following for the
post-mortem doc:

- Which deploy introduced the regression? `git log --oneline
  --since='1 day ago' services/<svc>/`
- Was the failure mode visible in CI? If yes, the missing test is
  a blocker on closing the incident. Open a follow-up issue.
- Did the service announce its readiness correctly?
  `/readyz` should return 200 once dependencies are connected
  (Phase 2.6).

## References

- Source map: [`scripts/audit_prometheus_targets.py`](../../scripts/audit_prometheus_targets.py)
- Prometheus rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- Container layout: [`docker-compose.yml`](../../docker-compose.yml)

Updated: **2026-06-28** (Phase 2.5).
