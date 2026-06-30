---
sidebar_position: 4
title: Troubleshooting
description: Common AiSOC errors, where to look, and how to recover — from a stuck connector poll to a wedged Kafka consumer to a silent agent.
---

# Troubleshooting

Most AiSOC issues fall into a handful of buckets: a service can't reach a dependency, a credential is wrong, a queue is wedged, or an LLM provider is unreachable. This page is the field guide — what symptom maps to which subsystem, where to read the log, and how to recover without paging the whole rotation.

If the symptom is not listed here, the fastest diagnostic is almost always:

```bash
pnpm aisoc:doctor
```

It runs an end-to-end health check across ports, containers, demo data, the API, and the WebSocket gateway, and tells you exactly what is red.

---

## First: where logs live

| Surface | Where to look |
|---|---|
| Service logs (Docker Compose dev) | `docker compose logs -f <service>` |
| Service logs (Kubernetes) | `kubectl logs -n aisoc deploy/<service> -f` |
| Structured app events | All services emit JSON via `structlog` (Python) or `pino` (Node). Pipe to your log aggregator (Loki, Elastic, Datadog, Splunk). |
| Audit log (every state-changing API call) | UI → **Audit Log**, or `GET /api/v1/audit-log` |
| Investigation Ledger (every agent decision) | UI → case workspace → **Ledger** tab, or `GET /api/v1/cases/{id}/ledger` |
| Connector poll history | UI → **Connectors** → click instance → **Run history** tab |
| Kafka consumer lag | `docker compose exec kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --all-groups` |
| Database health | `docker compose exec postgres psql -U aisoc -c '\l'` |

Every log line carries `tenant_id`, `correlation_id`, and (where relevant) `case_id`, `alert_id`, `connector_id`. Filter by these — never grep raw text in production.

---

## Stack won't start

### `pnpm aisoc:demo` hangs at "waiting for healthchecks"

```
[demo] Waiting for postgres healthcheck …  (still waiting after 120s)
```

Almost always one of:

1. **Old container state.** Run `pnpm aisoc:demo:down` (which also drops the demo volumes) and try again.
2. **Port collision.** Postgres `5432`, Redis `6379`, or Kafka `9092` is already bound on the host. Either stop the local service or set `DATABASE_URL`, `REDIS_URL`, `KAFKA_BOOTSTRAP_SERVERS` to non-default ports in `.env` before re-running.
3. **Docker resource limits.** Compose needs ~6 GB RAM for the slim demo and ~12 GB for the full stack. On Docker Desktop, raise the memory limit in **Settings → Resources**.

### A service container restarts in a loop

Read the last 50 lines of its log:

```bash
docker compose logs --tail=50 <service>
```

The four most common causes and fixes:

| Symptom in log | Likely cause | Fix |
|---|---|---|
| `connection refused` to `postgres:5432` | The DB hasn't finished initializing yet | Compose `depends_on` retries automatically; if the loop persists for more than 60 s, restart `postgres` and check disk space |
| `password authentication failed for user "aisoc"` | `.env` overridden after the volume was created | Either match the existing volume credentials or `pnpm aisoc:demo:down` and recreate |
| `InvalidToken` in API or connectors | `AISOC_CREDENTIAL_KEY` is missing or differs between API and connectors services | Set the same key in both, see [Credentials](./credentials) |
| `JWT_SECRET must be set in non-development environments` | Ingest service refuses to boot without a real key | Set `JWT_SECRET` in `.env` and restart |

---

## API service

### `/healthz` returns 503

The API healthcheck reports per-subsystem status. A 503 means at least one required subsystem is down. The response body lists which one:

```json
{ "status": "degraded", "subsystems": { "postgres": "ok", "redis": "ok", "kafka": "down", "opensearch": "ok" } }
```

Restart only the offending subsystem rather than the whole stack. If you intentionally don't run a subsystem (common in air-gap or minimal deployments), set the matching `AISOC_DISABLE_*` flag — see [Environment Variables](../deployment/env-vars). Endpoints that need the disabled subsystem will return 503 cleanly instead of crashing.

### `401 Unauthorized` on every API call

Three causes, in order of likelihood:

1. **Token expired.** Access tokens default to 30 minutes. The web app refreshes silently; CLI / SDK clients must call `/auth/refresh` themselves.
2. **`SECRET_KEY` rotated.** Existing tokens were signed with the old key. After any `SECRET_KEY` rotation, all sessions are invalidated by design. Users must re-authenticate.
3. **Tenant mismatch.** The token is for tenant `A` but the request hit a route scoped to tenant `B`. Decode the JWT (no signature check needed for diagnosis): `python -c "import jwt; print(jwt.decode('<token>', options={'verify_signature': False}))"`.

### `403 Forbidden` despite a valid token

Almost always RBAC. The user has a role, the role lacks the required permission. Check **Settings → Roles** in the UI, or:

```bash
GET /api/v1/rbac/users/{user_id}/effective-permissions
```

Permissions are additive across roles; if the permission is missing here, no role grants it.

### Slow API responses

```bash
docker compose exec api python -c "import asyncio, asyncpg; asyncio.run(...)"   # quick DB probe
```

In practice, when the API gets slow, check three things in order:

1. **Database connection pool.** `DATABASE_POOL_SIZE` defaults to 20. If you have ≥10 simultaneous heavy users, raise to 50 and watch.
2. **OpenSearch query latency.** `/api/v1/alerts` with broad time ranges and no filters fans out to OpenSearch. Add a tenant or time-range filter, or pre-aggregate.
3. **Realtime fan-out backlog.** If `realtime` is restarting, the API blocks briefly on internal RPC. Restart `realtime`.

---

## Connectors

### Connector shows `last_run: failed` in the UI

Click into the instance → **Run history** → expand the failed run. The error is captured verbatim from the upstream API.

| Error pattern | Cause | Fix |
|---|---|---|
| `401` / `invalid_client` / `invalid_grant` | Upstream credential expired or rotated | Click **Configure**, paste a new secret, **Save** |
| `403` / `insufficient_scope` | The connector identity doesn't have the required scope/role on the source | Re-check the per-connector setup doc (e.g. [Azure Entra](../connectors/azure-entra), [GitHub](../connectors/github)) — they list the exact scopes |
| `429` / `rate_limited` | We hit the upstream API rate limit | Increase `connector_config.poll_interval_seconds` for that instance; AiSOC honors `Retry-After` automatically |
| `Timeout after 30 s` | Upstream is slow or unreachable | Transient — retry on next poll. Persistent → check upstream status page |
| `InvalidToken` | The vault can't decrypt this instance's `auth_config` | Means `AISOC_CREDENTIAL_KEY` was rotated without running the rewrite step. See [Credentials → Rotation](./credentials) |

### Connector is enabled but `events_added` stays at 0

In order of how often this is the cause:

1. **Source has no new events.** Verify upstream — most APIs have a "view audit events" UI you can compare against.
2. **Time window starts in the future.** A connector's first poll uses a default lookback (typically 24 h). If the source's clock is skewed or the connector was disabled then re-enabled with a too-recent watermark, you'll get no events. **Manual fix**: click **Configure** → **Reset watermark** → choose a timestamp in the past.
3. **Polling is paused.** The scheduler is global and pausable via `AISOC_CONNECTORS_DISABLE_SCHEDULER=1`. Make sure that flag is *not* set in production.
4. **Filters in the connector instance exclude everything.** Some connectors expose a `filter` field — check it.

### Connector polls succeed but alerts don't show up

The pipeline is `Connector → Ingest → Kafka → Fusion → Alerts`. Each hop has visibility:

```bash
# Did the connector hand events to ingest?
curl -s http://localhost:8081/internal/metrics | grep ingest_events_received_total

# Did Kafka receive them?
docker compose exec kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic security.events --from-beginning --max-messages 1

# Did fusion pick them up?
docker compose logs --tail=200 fusion | grep "fused_alert"
```

If ingest received events but Kafka has none → check `KAFKA_BOOTSTRAP_SERVERS` matches between ingest and Kafka. If Kafka has them but fusion ignored them → most likely no detection rule fired (which is normal — most events are not alerts). Check the **Detections** page for active rule count.

### `aisoc submit` succeeds but `/alerts` is still empty (v7.3.1+)

The `aisoc submit` CLI (and the [`POST /api/v1/alerts/submit`](../api/rest) endpoint behind it) writes a single `Alert` row directly to Postgres — it intentionally bypasses Kafka / `services/ingest` / `services/fusion`, so this path has a different failure surface than the connector pipeline above.

In order of how often this is the cause:

1. **Migrations weren't applied on a fresh clone.** The `alerts` table needs the v7.3.1 schema (eleven columns added by `042_alerts_schema_drift_fix.sql`). Run `aisoc db upgrade` — it's idempotent, so re-running on an already-migrated database is safe. If you see `column "..." of relation "alerts" does not exist` in `docker compose logs api`, this is the cause.
2. **`AISOC_CREDENTIAL_KEY` mismatch.** The submit endpoint writes through the same vault decrypt path as the rest of the API. If the API service was started with a different key than the one in `.env`, the row inserts but downstream lookups (e.g. tenant resolution) fail silently. Stop the stack, set the key in `.env`, restart.
3. **Wrong tenant filter in the UI.** The web console scopes `/alerts` to the currently selected tenant. `aisoc submit` defaults to the dev tenant. If you've switched tenants in the UI, you won't see the row. Switch back to the dev tenant or pass `--tenant` to `aisoc submit`.
4. **API is on a port other than 8000.** `aisoc submit` reads `AISOC_API_URL` (default `http://localhost:8000`). If you remapped the port in `infra/compose/docker-compose.dev.yml`, set the env var.

Confirm the row really landed:

```bash
docker compose exec postgres psql -U aisoc -d aisoc -c \
  "select id, rule_id, severity, status, created_at from alerts order by created_at desc limit 5;"
```

If the row is there but the UI still shows empty, it's a tenant-filter issue (cause #3), not a submit issue.

---

## Agents (the AI investigator)

### Agent investigation hangs forever

Open the case → **Ledger** tab. The last entry is the diagnostic. The most common patterns:

| Last ledger entry | Cause | Fix |
|---|---|---|
| `tool: search_alerts` with no follow-up after 2+ minutes | OpenSearch is unreachable or the query is too broad | Restart `opensearch`; check `OPENSEARCH_URL` |
| `tool: search_threat_intel` then 30 s gap | Qdrant is unreachable | Check `QDRANT_URL`; restart `qdrant` |
| `llm: <model>` with no response | OpenAI / Anthropic outage or invalid `OPENAI_API_KEY` | Check the provider status page; rotate the API key if a 401 is in agent logs |
| Empty ledger after "Investigation started" | Agent crashed before its first tool call | `docker compose logs agents` — almost always a missing `OPENAI_API_KEY` |

There's a manual escape: click **Cancel investigation** on the case to stop the run cleanly. The ledger is preserved.

### Agent says "I don't have enough information"

Two-thirds of the time, this means a connector hasn't fired yet for the relevant identity / host / IOC, so the agent's tools return empty. One-third of the time, RAG memory is empty (Qdrant is fresh) and the agent has no retrievable similar cases. Run `pnpm seed:demo` to populate Qdrant in dev; in production, accept that the first dozen investigations are the agent learning the environment.

---

## Web app

### Login redirects to `/login` immediately after submitting

Almost always cookie / domain mismatch:

1. **`PASSKEY_RP_ORIGINS` doesn't include the URL the browser is actually using.** Localhost over `http://` and `127.0.0.1` over `http://` are *different* origins. Set both.
2. **`CORS_ORIGINS` doesn't include the web app origin.** API rejects the cookie with no error visible in the UI. Set the env var, restart `api`.
3. **Browser blocks third-party cookies.** Only matters if you put the API on a different eTLD+1 from the web app. Move them to the same parent domain or set `Strict-Transport-Security` plus `SameSite=None; Secure` on cookies.

### "Realtime disconnected" banner

The web app keeps a WebSocket open to `realtime`. If that drops:

1. **Browser tab was backgrounded for a long time.** Browser killed the socket. The app auto-reconnects within a few seconds.
2. **`realtime` service is down or restarting.** `docker compose logs realtime`. If it's stuck in `EADDRINUSE` on port 8086, another process is holding it.
3. **Internal token mismatch.** `realtime`'s `INTERNAL_TOKEN` must equal the API's `REALTIME_INTERNAL_TOKEN`. Mismatch → API calls to push fan out 401, banner shows.

### Push notifications don't arrive on the Responder PWA

In order:

1. The browser must have granted **Notifications** permission. Check via the address bar lock icon.
2. The PWA must have an active subscription. Check the **Settings → Notifications** screen — it lists the active VAPID subscription per device.
3. `VAPID_PUBLIC_KEY` (web) and `VAPID_PUBLIC_KEY` (realtime) must match exactly. A trailing newline in the env var will silently break it.
4. Apple / Android quiet hours can suppress delivery. The Investigation Ledger and Audit Log will still record the push *was sent* even if the OS dropped it.

---

## Detections, alerts, and triage

### A new detection rule never fires

1. **Wrong `logsource`**. The Sigma `logsource` block must match the OCSF category your connector emits. Use the [Connector field reference](../connectors/api-coverage) to confirm.
2. **Status is `disabled`.** New rules default to `disabled` to avoid noise on import. Enable in the UI before expecting fires.
3. **Tier filter excludes it.** The Detections page filters by tier (stable / beta / imported / community). Imported rules from SigmaHQ default to the `imported` tier and can look invisible if the filter is set to `stable`.
4. **`condition` is too restrictive.** Run the rule against historical data: **Detections → click rule → Backtest**. If the backtest shows zero matches over a known-positive window, the condition is wrong, not AiSOC.

### Auto-triage closed an alert you wanted to investigate

The auto-triage agent only auto-closes alerts above a configured confidence threshold *and* when no autonomy gate blocks the action. To recover:

- Click the alert in the **Closed** tab → **Reopen**. Auto-triage will not touch it again on this run.
- The analyst-override feedback loop captures this correction. See [Capabilities → Override loop](../concepts/capabilities#agent-intelligence-2026-h2). Future similar alerts will respect your verdict.
- To globally lower autonomy, **Settings → Autonomy Policy** → set `auto_triage_close` to `review` instead of `auto`.

---

## Database / Kafka / search

### `psql` shows healthy DB but the API can't connect

Verify the DSN actually used by the API:

```bash
docker compose exec api python -c "from app.core.config import settings; print(settings.DATABASE_URL)"
```

If this prints the default `localhost:5432` from inside the container, your `.env` isn't being loaded into the API service. Check `docker-compose.yml` — every service block needs `env_file: .env` or `environment:` entries.

### Kafka consumer lag keeps growing

```bash
docker compose exec kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --all-groups
```

Lag on `aisoc.normalized_events` → fusion is overloaded or stalled. Lag on `aisoc.alerts.fused` → realtime can't keep up, usually because a downstream WebSocket client backed up. Either restart the consumer or scale it horizontally (more replicas of `fusion` / `realtime`).

### OpenSearch shards are red

Run:

```bash
curl -s http://localhost:9200/_cluster/health?pretty
```

Red almost always means disk pressure (default flood-stage watermark is 95 %). Free disk space, then:

```bash
curl -X PUT 'http://localhost:9200/_all/_settings' \
  -H 'Content-Type: application/json' \
  -d '{ "index.blocks.read_only_allow_delete": null }'
```

This unsticks any indices that auto-locked themselves into read-only mode.

---

## Eval harness

### `python scripts/run_evals.py` exits with a regression error

Expected behaviour after a substrate change. The harness compares your branch's score against the saved baseline; a regression on `mitre_accuracy` blocks the PR. Fix paths:

1. **Genuine regression.** Roll back the substrate change or re-tune the affected component (extractor, fusion, judge).
2. **Intentional improvement that moves the score in either direction.** Update the baseline: `python scripts/update_eval_baseline.py --suite mitre_accuracy`. Commit the new baseline alongside the change.
3. **Synthetic dataset drift.** The dataset is fixed at 200 incidents; if you edited it, you must update the baseline.

See [Benchmark](../benchmark) for what each suite measures.

---

## When to escalate

If after the above:

- A subsystem keeps crash-looping for more than 10 minutes,
- The Investigation Ledger shows the agent has been silent for more than 5 minutes on an active P1,
- Kafka consumer lag exceeds 1 hour and is growing,
- Or any data integrity error appears (`audit_log` checksum mismatch, `evidence` row missing in ledger reference),

— page the on-call platform owner. Open a GitHub issue with:

- Git SHA running in production (`docker exec api cat /etc/aisoc.version`).
- Output of `pnpm aisoc:doctor`.
- Last 200 lines of the offending service log.
- A correlation_id from a failing request.

Most data-plane issues are caught and explained by `aisoc:doctor` — please run it before opening the issue.

## Related

- [Operations: Credentials](./credentials)
- [Operations: Air-gap deployments](./airgap)
- [Operations: Security & access](./security)
- [Environment Variables](../deployment/env-vars)
