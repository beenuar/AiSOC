# Runbook: Postgres incident (manual triage)

> **Severity:** varies — typically critical
> **Alert source:** indirect (this runbook is invoked from any of
> the alerts above when symptoms point at Postgres)

## When to use this runbook

You arrive here when one of the alerts above
(`AisocHttpErrorRateHigh`, `AisocHttpP95LatencyHigh`,
`AisocDetectionPipelineStalled`) traced back to Postgres. Symptoms
that point at the database:

- API logs show `asyncpg.exceptions.ConnectionDoesNotExistError`
  / `TooManyConnectionsError` / `SerializationError`.
- `pg_stat_activity` shows queries with `state='active'` and
  `now() - query_start > 5s` piling up.
- Postgres process is restarting (`docker compose ps postgres`
  shows `restarting`).
- Disk full on the Postgres volume.

## First five minutes

```bash
# 1. Is Postgres reachable from the API container?
docker compose exec api \
  python -c "import asyncio, asyncpg, os; \
  print(asyncio.run(asyncpg.connect(os.environ['DATABASE_URL'].replace('+asyncpg','')).fetchval('SELECT 1')))"

# 2. Connection-state breakdown — saturation kills throughput.
docker compose exec postgres psql -U aisoc aisoc \
  -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# 3. Slowest currently-active queries.
docker compose exec postgres psql -U aisoc aisoc \
  -c "SELECT pid, now()-query_start AS dur, query
       FROM pg_stat_activity
       WHERE state='active'
       ORDER BY dur DESC LIMIT 10;"

# 4. Disk usage on the Postgres data volume.
docker compose exec postgres df -h /var/lib/postgresql/data

# 5. Last 100 Postgres log lines.
docker compose logs postgres --tail 100
```

## Mitigation

- **Connection saturation:** the API + agents services each
  default to a 10-connection pool. Long-running migrations or a
  rogue analytical query can starve everyone else. Identify the
  blocker with step 3 above, then:
  ```sql
  SELECT pg_cancel_backend(<pid>);   -- graceful
  SELECT pg_terminate_backend(<pid>); -- last resort
  ```
- **Disk full:** AiSOC writes durable event ledgers
  (`detection_runs`, `agent_traces`, `audit_events`) on every
  fired alert. Run
  `services/api/scripts/prune_ledger.py --older-than 30d --apply`
  to reclaim space. The script is no-op without `--apply`.
- **Postgres restart loop:** check the `postgres` service
  config: was the password rotated without updating the
  `POSTGRES_PASSWORD` env var? Was the data volume corrupted
  (Postgres logs will show "PANIC: could not locate ...")?
  Restore from the most recent `pg_dump` under
  `infra/docker/backups/`.
- **Replica reconciliation:** the dev stack runs a single
  Postgres node. Production deployments use the
  [`rds` Terraform module](../../infra/terraform/modules/rds/) —
  follow your cloud provider's standby promotion runbook if
  primary is unrecoverable.

## Root cause

- **Slow query:** add the index in a migration, ship it through
  CI (the `python-test` job will run the migration in its boot
  test step).
- **Disk fill from event ledger:** schedule the
  `prune_ledger.py` script as a cron job. Default retention
  config lives in `services/api/app/core/config.py`.
- **Long-running migration:** `alembic upgrade head` should
  always be applied in a maintenance window for any schema that
  rewrites rows. Add a comment to the migration explaining the
  expected duration so the next operator doesn't run it during
  business hours.

## References

- Connection pool sizing: `services/api/app/core/config.py`
  (`DATABASE_POOL_SIZE`)
- Migrations: `services/api/alembic/versions/`
- Backup tooling: `infra/docker/backups/`

Updated: **2026-06-28** (Phase 2.5).
