---
sidebar_position: 1
---

# Development Setup

This guide walks through getting a full AiSOC dev environment on your
laptop. If you only need a working demo (no code changes), prefer the
one-shot path described in the [Quickstart](../quickstart) — it pulls
prebuilt GHCR images and is ready in under five minutes.

## Prerequisites

| Tool | Minimum | Notes |
|------|---------|-------|
| Node.js | 20 LTS | We test against 20.x |
| pnpm | 8 | `corepack enable` is fine |
| Python | 3.11+ | Used by `services/api`, `services/agents`, `services/fusion`, `services/actions`, `services/threatintel`, `services/ueba`, `services/honeytokens`, `services/purple-team` |
| Go | 1.21+ | Used by `services/ingest`, `services/enrichment`, `packages/plugin-sdk-go`, `packages/sdk-go`, and the first-party Go plugins |
| Docker | 24+ | Compose v2 is required |
| Make | optional | A `Makefile` wraps the most common targets |

> **Tip:** the `pnpm aisoc:doctor` command verifies that all of the
> above are installed at compatible versions before you spin up the
> stack.

## 1. Clone & install

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC
pnpm install
```

`pnpm install` walks the `pnpm-workspace.yaml` and bootstraps every
TypeScript package — including the Next.js console (`apps/web`), the
Docusaurus docs site (`apps/docs`), the realtime gateway
(`services/realtime`), the MCP server (`services/mcp`), the TS SDK
(`packages/sdk-ts`), and the orchestration scripts under `scripts/`.

## 2. Python services

Each Python service has its own `pyproject.toml`. The most common
workflow is to create one virtualenv per service you want to hack on.

```bash
# Core API gateway (FastAPI)
cd services/api
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# AI investigator (LangGraph)
cd ../agents
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Repeat for `services/fusion`, `services/actions`, `services/threatintel`,
`services/ueba`, `services/honeytokens`, and `services/purple-team` as
needed.

## 3. Go services and plugins

```bash
# Ingest + enrichment
( cd services/ingest && go mod download )
( cd services/enrichment && go mod download )

# SDKs
( cd packages/plugin-sdk-go && go test ./... )
( cd packages/sdk-go && go test ./... )

# All first-party plugins live under plugins/
ls plugins/
```

## 4. Environment

```bash
cp .env.example .env
```

At minimum, set:

- `OPENAI_API_KEY` — for the AI investigator (or wire any LangChain-
  compatible model provider).
- `JWT_SECRET` and `ENCRYPTION_KEY` — generate with
  `openssl rand -hex 32` each.
- `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` — needed for Web Push in the
  Responder PWA. Generate with `npx web-push generate-vapid-keys`.

## 5. Start the data tier

The simplest path is to bring up the data services from the full
compose stack and run application services on the host:

```bash
docker compose up -d postgres redis kafka clickhouse opensearch qdrant neo4j
```

Then apply migrations:

```bash
cd services/api
alembic upgrade head
# Or, if you prefer raw SQL, the migration files live in
# services/api/migrations/ — including:
#   008_investigation_ledger.sql
#   009_responder_pwa.sql
```

Seed demo data:

```bash
pnpm seed:demo
```

## 6. Run services individually

In separate terminals (with the right virtualenv activated where
applicable):

```bash
# Frontend (Next.js console + Responder PWA route group)
pnpm --filter @aisoc/web dev                 # http://localhost:3000

# API gateway
cd services/api
uvicorn app.main:app --reload --port 8000    # http://localhost:8000

# AI investigator (LangGraph)
cd services/agents
uvicorn app.main:app --reload --port 8001    # http://localhost:8001

# Realtime gateway (WebSocket + Web Push)
cd services/realtime
pnpm dev                                     # ws://localhost:8086

# Ingest (Go)
cd services/ingest
go run ./cmd/server                          # http://localhost:8081

# Enrichment (Go)
cd services/enrichment
go run ./cmd/server                          # http://localhost:8080

# MCP server (TypeScript, stdio)
pnpm --filter @aisoc/mcp dev
```

The other Python services (`fusion`, `actions`, `threatintel`, `ueba`,
`honeytokens`, `purple-team`) follow the same pattern: activate the
virtualenv and run `uvicorn app.main:app --reload --port <port>`.
The canonical port mapping is in
[`docker-compose.yml`](https://github.com/beenuar/AiSOC/blob/main/docker-compose.yml)
and the [Architecture](../architecture#service-responsibilities) page.

## 7. Run tests

```bash
# Python (per-service)
pytest services/api/tests/
pytest services/agents/tests/

# Go
( cd services/ingest && go test ./... )
( cd services/enrichment && go test ./... )
( cd packages/plugin-sdk-go && go test ./... )
( cd packages/sdk-go && go test ./... )

# Frontend (Next.js + Responder PWA)
pnpm --filter @aisoc/web lint
pnpm --filter @aisoc/web test

# Public eval harness (substrate self-consistency + one real measurement)
pnpm eval:run
```

The eval harness writes its results to `eval_report.json` and
`eval_mitre_accuracy_report.json` (both `.gitignore`d). The same harness
runs in CI on every PR — see the [eval harness page](../benchmark) for what
each suite actually measures and which numbers are real measurements vs.
substrate self-consistency gates.

## 8. Useful scripts

| Script | Description |
|--------|-------------|
| `pnpm aisoc:doctor` | Verify Node / pnpm / Python / Go / Docker versions |
| `pnpm aisoc:demo` | One-shot demo using prebuilt GHCR images |
| `pnpm aisoc:demo:logs` | Tail logs from the demo stack |
| `pnpm aisoc:demo:down` | Tear the demo stack down |
| `pnpm seed:demo` | Seed demo tenants, alerts, cases, and playbooks |
| `pnpm marketplace:build` | Build `marketplace/index.json` from `detections/`, `playbooks/`, `plugins/` |
| `pnpm marketplace:check` | Validate the marketplace index against the schema |
| `pnpm marketplace:sync` | Push the marketplace index to `apps/web/public/marketplace/index.json` |
| `pnpm eval:run` | Run the public eval harness |
| `python3 scripts/validate_detections.py detections/` | Validate detection rules |
| `python3 scripts/validate_playbooks.py playbooks/` | Validate playbooks |
| `python3 scripts/lint_playbooks.py playbooks/` | Lint playbooks for style |

## 9. Hacking on content

AiSOC ships a curated marketplace at
[`marketplace/index.json`](https://github.com/beenuar/AiSOC/blob/main/marketplace/index.json)
that aggregates 6,900+ detections (filtered by tier), 50+ playbooks, and
15 first-party plugins. To add to the catalog:

1. Drop your YAML into `detections/<vendor>/` or `playbooks/<vendor>/`.
2. Add or update the plugin under `plugins/<vendor>/`.
3. Run `pnpm marketplace:build && pnpm marketplace:check`.
4. Run `pnpm marketplace:sync` to publish the index into the web app.
5. Add an entry to `CHANGELOG.md` under the `Unreleased` section.

The `validate-detections.yml` and `validate-playbooks.yml` GitHub
Actions enforce the schema on every PR.
