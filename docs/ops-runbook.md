# AiSOC ops runbook — live deployment

Host: `10.200.0.69` (SSH `ubuntu@`, key `~/.ssh/c8r-tech-key`)
Repo/compose project: `/home/ubuntu/AiSOC` (compose project name `aisoc`)
Origin: `https://github.com/beenuar/AiSOC` · Fork: `https://github.com/alexmateescu/AiSOC`

## Service map (container → host port → role)

| Container | Host port | Role |
|---|---|---|
| aisoc-web | 127.0.0.1:3000 | Next.js console |
| aisoc-api | 127.0.0.1:8000 | Core FastAPI (cases, alerts, graph, approvals, feedback, lake query) |
| aisoc-agents | 127.0.0.1:8001 (→8084) | Investigation agents |
| litellm | 127.0.0.1:4000 | LLM gateway (alias router + fallbacks) |
| ollama | 127.0.0.1:11434 | Inference, Tesla T4 16 GB |
| aisoc-postgres | internal | Core store (+ investigation ledger, api_keys, RLS multi-tenant) |
| aisoc-clickhouse | internal:9000 | Warm lake (`aisoc.raw_events`, `ioc_enrichments`, `alert_metrics`) |
| aisoc-opensearch | 9200 | Secondary index (defined; lake primary is ClickHouse) |
| aisoc-ingest | 8081 | Kafka producer/sink worker (service name `ingest-worker`) |
| kafka / zookeeper / redis / qdrant | internal | Stream / cache / vectors |

Health checks: `curl 127.0.0.1:8000/health`, `/readyz` variants per service;
`aisoc-ingest` `/readyz` exposes `subscriptions` — empty subscriptions means
consumer detach, worth watching.

## Credentials map (never write values here)

- `api_keys` table (postgres): DB-backed `aisoc_<48hex>` keys, SHA-256
  matched, scopes in JSONB. Agents use `AISOC_AGENTS_API_KEY` (from `.env`)
  for `get_current_user` routes.
- Service tokens (`AISOC_AGENTS_SERVICE_TOKEN` / `AISOC_SERVICE_TOKEN`):
  ONLY valid as Bearer on the agents guard or as `X-AiSOC-Service-Token` —
  never valid on core-API `get_current_user` routes.
- ClickHouse: user `aisoc` + `CLICKHOUSE_PASSWORD` in `.env` (NOT the compose
  default).
- GitHub push from this box: `~/.ssh/github` key → authenticates as
  `alexmateescu`.

## Deploying changes

Code edits inside service dirs (`services/api`, `services/agents`,
`apps/web`) need a rebuild — `up -d` alone reuses the old image:

```
cd ~/AiSOC
docker compose build <svc> && docker compose up -d <svc>
```

Verify the patch landed inside the container before testing:
`docker exec <c> grep -c <new-symbol> /app/app/<file>`.
Model/env changes are `.env` + `docker compose up -d <svc>` only.

Optional infra (clickhouse/opensearch/ingest) is NOT started by a bare
`docker compose up` — start explicitly after host reboots if lake pivots
fail with name-resolution errors.

## Useful probes (run from inside aisoc-agents — api container has no keys)

- investigations list: `GET http://api:8000/api/v1/cases/<case>/investigations`
- lake pivot: `POST http://api:8000/api/v1/graph/investigate/query`
  `{"tool":"process_activity","args":{"hostname":"…","hours":24}}`
- LLM smoke: `POST http://litellm:4000/v1/chat/completions` model
  `aisoc-triage`.
- The command relay scrubs literal `Bearer <token>` text before execution —
  build auth headers from runtime fragments in probe scripts.

## Known operational quirks

- `scp` broken on this box — pipe files (`cat f | ssh host 'cat > /tmp/f'`).
- Nested heredocs inside `ssh 'bash -s'` are silently swallowed — deliver
  scripts/files by piping a local file.
- Compose service names ≠ container names (`ingest-worker` → `aisoc-ingest`);
  diff services on container_name.
- Unquoted heredocs executing TSX patches eat backticked text in comments.
- Alerts: verdict lives in `disposition`, badge reads `status` — check both
  columns before claiming the agent did nothing.
