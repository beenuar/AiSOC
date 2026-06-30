# Migration Guide: v3 → v4

This guide covers the breaking changes and upgrade path from AiSOC v3 to v4.
Read it before running `docker compose pull` or deploying to production.

---

## Table of Contents

1. [What Changed in v4](#what-changed-in-v4)
2. [Prerequisites](#prerequisites)
3. [Upgrade Steps](#upgrade-steps)
   - [Step 1 — Back up your data](#step-1--back-up-your-data)
   - [Step 2 — Update environment variables](#step-2--update-environment-variables)
   - [Step 3 — Database migrations](#step-3--database-migrations)
   - [Step 4 — Migrate plugins (aisoc-plugin.json → plugin.yaml)](#step-4--migrate-plugins)
   - [Step 5 — Migrate playbooks (schema upgrade)](#step-5--migrate-playbooks)
   - [Step 6 — Pull and restart](#step-6--pull-and-restart)
   - [Step 7 — Verify](#step-7--verify)
4. [Breaking API Changes](#breaking-api-changes)
5. [Removed Features](#removed-features)
6. [FAQ](#faq)

---

## What Changed in v4

| Area | v3 | v4 |
|------|----|----|
| Core engine | Rule-based SOAR engine | LangGraph multi-agent investigator |
| Playbook format | Custom JSON (no schema) | JSON Schema 2020-12 (`playbook.schema.json`) |
| Plugin manifest | `aisoc-plugin.json` only | `plugin.yaml` (preferred) + `aisoc-plugin.json` (legacy) |
| Plugin types | `enricher`, `action`, `connector` | + `responder`, `detection`, `widget` |
| Plugin distribution | Local directory only | Local directory + OCI images (via `oras`) |
| API auth | JWT only | JWT + scoped API tokens (`/api/v1/api-keys`) |
| API schema | REST only | REST (OpenAPI 3.1) + GraphQL |
| Observability | Prometheus metrics only | Prometheus + OpenTelemetry traces (Jaeger/OTLP) |
| SDKs | None | Python SDK, Go SDK, TypeScript SDK |
| Marketplace | None | Community playbook & plugin marketplace |

---

## Prerequisites

- Docker Compose v2 (`docker compose version` should show ≥ 2.0)
- Python 3.11+ (for migration scripts)
- PostgreSQL 15+ (we recommend 16)
- 8 GB RAM available for the full stack

---

## Upgrade Steps

### Step 1 — Back up your data

```bash
# PostgreSQL
docker compose exec postgres pg_dump -U aisoc aisoc > backup_v3_$(date +%Y%m%d).sql

# ClickHouse (event store)
docker compose exec clickhouse clickhouse-client \
  --query "BACKUP DATABASE aisoc TO Disk('backups', 'aisoc_v3_$(date +%Y%m%d).zip')"

# Copy plugin directory
cp -r plugins plugins_v3_backup
```

---

### Step 2 — Update environment variables

New required variables in v4 (add to your `.env` / Kubernetes secrets):

```dotenv
# OpenTelemetry — set to "none" to disable, or "otlp" for Jaeger/Tempo
OTEL_EXPORTER=none
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317

# LLM provider for the multi-agent investigator
OPENAI_API_KEY=sk-...        # or use ANTHROPIC_API_KEY
LLM_MODEL=gpt-4o             # recommended; use gpt-4o-mini for lower cost

# Qdrant (new vector store for MITRE ATT&CK embeddings)
QDRANT_URL=http://qdrant:6333

# GraphQL
ENABLE_GRAPHQL=true          # false to keep REST-only mode

# Scoped API tokens (salt for HMAC)
API_TOKEN_SIGNING_SECRET=<32-char-random-string>
```

Variables **removed** in v4:

```dotenv
# Remove these — the v4 engine does not use them:
RULE_ENGINE_WORKERS=
SOAR_LEGACY_MODE=
PLUGIN_SANDBOX=
```

---

### Step 3 — Database migrations

v4 introduces new tables (`api_keys`, `playbook_runs`, `investigation_steps`).
Run Alembic:

```bash
docker compose run --rm api alembic upgrade head
```

Expected output:

```
INFO  [alembic.runtime.migration] Running upgrade abc123 -> def456, add api_keys table
INFO  [alembic.runtime.migration] Running upgrade def456 -> ghi789, add playbook_runs table
INFO  [alembic.runtime.migration] Running upgrade ghi789 -> jkl012, add investigation_steps table
```

---

### Step 4 — Migrate plugins

The preferred manifest file is now `plugin.yaml`. Existing `aisoc-plugin.json`
files continue to work, but we recommend migrating for richer metadata support.

**Automated migration** (converts all plugins in `./plugins/`):

```bash
python3 scripts/migrate_plugins.py
```

**Manual migration example:**

`plugins/my-plugin/aisoc-plugin.json` (v3):
```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "version": "1.0.0",
  "type": "enricher",
  "description": "Does something useful"
}
```

`plugins/my-plugin/plugin.yaml` (v4):
```yaml
id: my-plugin
name: My Plugin
version: "1.0.0"
plugin_type: enricher          # ← renamed from "type"
description: Does something useful
author: Your Name
tags: [my-tag]
min_aisoc_version: "4.0.0"
config_schema:
  type: object
  properties: {}
```

**New plugin types** available in v4 (no action required if you don't use them):
- `responder` — execute response actions (block IP, isolate host, etc.)
- `detection` — contribute Sigma/YARA detection rules
- `widget` — add custom widgets to the SOC dashboard

---

### Step 5 — Migrate playbooks

Playbooks are now validated against `playbook.schema.json` (JSON Schema 2020-12).

**Check your existing playbooks:**

```bash
python3 scripts/lint_playbooks.py
```

**Common breaking changes in playbook format:**

| v3 field | v4 field | Notes |
|----------|----------|-------|
| `type: "action"` | `type: "action"` | Unchanged |
| `on_error: "stop"` | `on_failure: { policy: "abort" }` | Renamed |
| `retry: 3` | `retry: { max_attempts: 3, backoff: "exponential" }` | Expanded |
| `condition: "..."` | `condition: { expr: "...", language: "jmespath" }` | Structured |
| `timeout: 60` | `timeout_seconds: 60` | Renamed |

**Auto-upgrade playbooks:**

```bash
python3 scripts/upgrade_playbooks.py --dir playbooks/
```

---

### Step 6 — Pull and restart

```bash
# Pull the latest images
docker compose pull

# Recreate all containers with the new images
docker compose up -d --remove-orphans

# Watch logs until healthy
docker compose logs -f api agents web | head -200
```

---

### Step 7 — Verify

Run the built-in health check suite:

```bash
# All services healthy?
curl http://localhost:8000/api/v1/health | jq .

# GraphQL endpoint available?
curl -s -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' | jq .

# Plugin manager loaded?
curl http://localhost:8000/api/v1/plugins | jq .[].id

# Run the public eval harness against the bundled 200-incident dataset
# (offline, no LLM call required). The dataset size is fixed — there is no
# --count flag, and the output flag is --out, not --report.
python3 scripts/run_evals.py --out eval_report.json
```

Expected output:
```
{"status":"ok","version":"4.0.0","services":{"db":"ok","redis":"ok","kafka":"ok"}}
{"data":{"__typename":"Query"}}
["okta-connector","yara-enricher","slack-quarantine","mttr-widget"]
ALL GATES PASSED (alert reduction + 3 substrate self-consistency gates)
```

The eval harness runs deterministic substrate code (extractors, fusion,
templates, judges) against synthetic incidents. It does not call the live LLM
agent. See [`apps/docs/docs/benchmark.md`](apps/docs/docs/benchmark.md) for
what each suite measures.

---

## Breaking API Changes

### Authentication

`Authorization: Bearer <jwt>` continues to work. New scoped API tokens:

```bash
# Create a read-only token
POST /api/v1/api-keys
{ "name": "ci-reader", "scopes": ["cases:read", "alerts:read"] }

# Use it
curl -H "X-API-Key: aisoc_..." http://localhost:8000/api/v1/cases
```

### Endpoint changes

| v3 endpoint | v4 endpoint | Change |
|-------------|-------------|--------|
| `POST /api/v1/investigate` | `POST /api/v1/investigations` | Renamed |
| `GET /api/v1/investigate/{id}` | `GET /api/v1/investigations/{id}` | Renamed |
| `POST /api/v1/playbooks/execute` | `POST /api/v1/playbooks/{id}/run` | Renamed + ID in path |
| `GET /api/v1/plugins/list` | `GET /api/v1/plugins` | Simplified |
| N/A | `POST /graphql` | New |
| N/A | `GET /api/v1/api-keys` | New |

### Response shape changes

Investigation responses now include `audit_log` and `iteration` fields:

```json
{
  "case_id": "...",
  "status": "completed",
  "iteration": 4,
  "report_md": "...",
  "audit_log": [...]
}
```

---

## Removed Features

| Feature | Reason | Alternative |
|---------|---------|-------------|
| Legacy rule engine (`SOAR_LEGACY_MODE`) | Replaced by LangGraph | Multi-agent investigator |
| Plugin sandboxing (`PLUGIN_SANDBOX`) | Too restrictive for LLM tools | OCI-isolated plugins |
| CSV alert ingestion endpoint | Low usage | Use the REST API or Kafka topic |
| Built-in SMTP notifier | Replaced by plugin | `slack-quarantine` plugin or custom responder |

---

## FAQ

Q: Do I need an OpenAI key for v4?
A: Only for the multi-agent investigator. Other features (playbooks, plugins,
detections) work without an LLM key. Set `LLM_PROVIDER=none` to disable the
investigator entirely.

Q: Can I run v3 and v4 side by side?
A: Yes. Use a different Docker Compose project name:
`docker compose -p aisoc-v4 up -d`

Q: Will my v3 playbooks still run?
A: After `python3 scripts/upgrade_playbooks.py`, yes. The v4 engine is
backward-compatible for the core `action` step type.

Q: How do I roll back to v3 if something goes wrong?
A: Restore the PostgreSQL backup from Step 1, then `docker compose pull` with
the v3 image tags pinned in your `docker-compose.yml`.

Q: Where do I get help?
A: Open an issue at https://github.com/beenuar/AiSOC/issues.
