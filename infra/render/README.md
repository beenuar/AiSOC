# AiSOC on Render

One-click deploy of the full AiSOC demo stack to [Render](https://render.com)
via Render's [Blueprint](https://render.com/docs/blueprint-spec) feature.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/beenuar/AiSOC)

## What this deploys

The lean demo profile — same shape as the [Fly demo](../fly/), without
the heavy storage tier:

| Service | Plan | Role |
|---|---|---|
| `aisoc-api` | starter ($7/mo) | FastAPI core + investigation ledger |
| `aisoc-agents` | standard ($25/mo) | LangGraph orchestrator (needs 2GB RAM) |
| `aisoc-realtime` | starter ($7/mo) | WebSocket fanout |
| `aisoc-web` | starter ($7/mo) | Next.js console + marketing |
| `aisoc-postgres` | starter ($7/mo) | Managed Postgres (1GB) |
| `aisoc-redis` | starter ($10/mo) | Managed Redis (25MB) |

**Total: ~$63/mo** for an always-on, public-facing demo. Significantly
cheaper than running the full storage tier (Kafka + ClickHouse + OpenSearch
+ Neo4j + Qdrant) which Render doesn't offer managed versions of.

## What's disabled (and why it's fine)

The Blueprint sets these flags on the api and agents services:

```yaml
AISOC_DISABLE_KAFKA: "true"
AISOC_DISABLE_CLICKHOUSE: "true"
AISOC_DISABLE_NEO4J: "true"
AISOC_DISABLE_QDRANT: "true"
```

The demo profile uses **Postgres + Redis** for everything — alerts, cases,
investigations, the agent ledger, the cache layer. ClickHouse-backed event
search and Neo4j-backed attack graphs are *hidden in the UI* when the
backing store is absent, so the demo never shows a broken page.

If you need the full storage tier in production, use:

- **Self-hosted on Render**: not recommended — single-instance Kafka and
  ClickHouse on Render's plans is more expensive than running them on a
  dedicated VM.
- **Kubernetes / Helm**: see [`infra/helm/`](../helm/) — production-grade,
  brings its own Kafka/ClickHouse/OpenSearch.
- **Terraform / AWS**: see [`infra/terraform/`](../terraform/) — uses MSK,
  RDS, ElastiCache, OpenSearch Service, ECS for the application tier.

## Deploy walkthrough

### Option A: one-click (recommended)

1. Click the **Deploy to Render** button above.
2. Render asks for permission to read your fork of `beenuar/AiSOC`. Grant it.
3. Render parses [`render.yaml`](../../render.yaml) at the repo root, shows
   the service plan, and asks you to confirm.
4. Click **Apply**. Render provisions Postgres + Redis first (~2 min),
   then deploys the four web services in dependency order (~6-8 min for
   the first build because Docker layers aren't cached yet).
5. Once `aisoc-web` is green, open `https://aisoc-web-<hash>.onrender.com`.
   The demo banner shows; the deeplink lands on a pre-seeded incident.

### Option B: manual

If you've forked the repo and changed things:

```bash
# From the repo root, after pushing your fork to GitHub:
gh repo view --web
# Then in Render: New + → Blueprint → Connect repo → select fork.
# Render auto-detects render.yaml at the repo root → Apply.
```

## Post-deploy: pre-warm the demo

The blueprint wires `preDeployCommand: alembic upgrade head && python -m
app.scripts.seed_demo` onto the `aisoc-api` service, so every Render deploy
runs migrations and seeds the demo tenant before the new instance accepts
traffic. The seeder is idempotent — re-running against an already-seeded
database is a cheap no-op that refreshes `INC-RT-001` (the in-flight
LockBit 3.0 ransomware investigation the demo deeplink targets) plus the
14 other canonical incidents.

If you ever need to re-seed manually (e.g. local recovery, or after a
database reset), use Render's Shell tab on the `aisoc-api` service and run:

```bash
python -m app.scripts.seed_demo
```

## Daily reset (optional)

The Fly demo wipes and re-seeds the demo tenant daily via a scheduled
machine. Render doesn't have native cron, so the options are:

1. **Render Cron Job service** (~$1/mo) — add a 7th service of type `cron`
   to `render.yaml` that runs the seed script on a schedule. Skipped from
   the Blueprint by default to keep the cost story simple.
2. **GitHub Actions workflow** — `.github/workflows/render-demo-reset.yml`
   that hits the deployed api on a schedule. Free, but tied to your GH Actions
   minutes budget.
3. **Skip it** — for a personal evaluation deploy, the demo data will drift
   over time but won't break.

## Troubleshooting

### "Web service failed health check"

The web service's health check hits `/`, which requires the api to be up
(it server-side renders the case list). If the api is still booting,
Render marks web as failed. Wait 60s and retry — Render auto-redeploys
on failed health checks up to 3 times.

### "Out of memory on aisoc-agents"

The starter plan (512MB) is not enough for LangGraph + the LLM client
buffers. The Blueprint defaults agents to `standard` (2GB) for this
reason. If you downgraded it, bump back up.

### Demo banner not showing

Check that `NEXT_PUBLIC_AISOC_DEMO_MODE=true` is set on the `aisoc-web`
service. The variable is baked into the JS bundle at build time, so
flipping it requires a redeploy (not just a restart).

### Slow first investigation

First boot does Alembic migrations + creates the ledger schema, which
can take 20-30s on cold Postgres. Subsequent investigations land in
&lt;5s once the schema is in place.

## Files

```
infra/render/
└── README.md       — this file (Render-specific walkthrough + cost notes)

<repo root>/
└── render.yaml     — Render Blueprint manifest (the source of truth).
                     Lives at the root because Render's "Deploy to Render"
                     button only auto-detects blueprints at the root of
                     the repo, not in subdirectories.
```

For the full deployment philosophy and platform comparison, see the
[main README](../../README.md#-deploy-in-one-click).
