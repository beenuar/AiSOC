# AiSOC on Railway

Deploy AiSOC to [Railway](https://railway.com) with one click — the lean
demo profile, 4 services, plus Postgres + Redis plugins.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https%3A%2F%2Fgithub.com%2Fbeenuar%2FAiSOC&plugins=postgresql%2Credis)

## What this deploys

The same lean profile that the [Fly demo](../fly/) and the
[Render Blueprint](../render/) use, with Railway-specific wiring:

| Service | Why |
|---|---|
| `api` | FastAPI core. Configured by `railway.toml` at the repo root level. |
| `agents` | LangGraph orchestrator. Added as a second service after the initial deploy. |
| `realtime` | WebSocket fanout. Added as a third service. |
| `web` | Next.js console. Added as the fourth service. |
| Postgres plugin | Auto-provisioned by the deploy button (`&plugins=postgresql`). |
| Redis plugin | Auto-provisioned by the deploy button (`&plugins=redis`). |

**Cost**: ~$5-15/mo for casual evaluation traffic on Railway's
pay-as-you-go pricing. Way cheaper than Render for low-traffic demos
because idle services don't accrue charges.

## Why Railway is multi-step (vs Render's one-shot)

Render has [Blueprints](https://render.com/docs/blueprint-spec) which
declare an entire stack in one YAML file. Railway's `railway.toml` is
**per-service** — its multi-service story goes through *Templates*
(published artifacts, not in-repo config) or the dashboard's "+ New
service" button.

We chose to ship `railway.toml` (configures the api) + this README
(walks through adding the other three) rather than:

- **Publishing a Railway Template**: requires a Railway team account and
  ties the template's lifecycle to a single owner. Forks would all share
  one template.
- **Shipping a `railway-template.json`**: undocumented format, fragile
  across Railway's UI redesigns.

The deploy button below provisions the api + Postgres + Redis. The other
services take ~3 minutes to add via the dashboard.

## Deploy walkthrough

### Step 1: Click the deploy button

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https%3A%2F%2Fgithub.com%2Fbeenuar%2FAiSOC&plugins=postgresql%2Credis)

This:

1. Forks `beenuar/AiSOC` to your GitHub account (or uses an existing fork).
2. Creates a new Railway project.
3. Provisions a Postgres plugin (named `Postgres`).
4. Provisions a Redis plugin (named `Redis`).
5. Reads [`railway.toml`](railway.toml) and deploys the api service from
   `services/api/Dockerfile`.

Wait ~3 min for the api to go green.

### Step 2: Wire database URLs into the api

In the Railway dashboard, click the **api** service → **Variables**, and
add:

```
DATABASE_URL=${{ Postgres.DATABASE_URL }}
REDIS_URL=${{ Redis.REDIS_URL }}
JWT_SECRET=<generate a random 32-char string>
```

Railway auto-redeploys when variables change. The api will run Alembic
migrations on the next boot and become healthy.

### Step 3: Add the agents service

1. **+ New** → **GitHub Repo** → select your fork.
2. **Settings** → **Root Directory**: `services/agents`
3. **Settings** → **Build** → **Builder**: Dockerfile (auto-detected).
4. **Variables**:

```
ENVIRONMENT=demo
PORT=8084
AISOC_AGENT_MODE=deterministic
AISOC_DISABLE_KAFKA=true
AISOC_DISABLE_QDRANT=true
AISOC_DISABLE_NEO4J=true
DATABASE_URL=${{ Postgres.DATABASE_URL }}
REDIS_URL=${{ Redis.REDIS_URL }}
CORE_API_URL=http://${{ api.RAILWAY_PRIVATE_DOMAIN }}:8000
```

The `RAILWAY_PRIVATE_DOMAIN` reference resolves to
`api.railway.internal` — Railway's free internal networking.

### Step 4: Add the realtime service

1. **+ New** → **GitHub Repo** → select your fork.
2. **Settings** → **Root Directory**: `services/realtime`
3. **Variables**:

```
NODE_ENV=production
PORT=8086
REDIS_URL=${{ Redis.REDIS_URL }}
AISOC_DISABLE_KAFKA=true
```

4. **Settings** → **Networking** → **Generate Domain** (the realtime
   service needs to be reachable from the browser for WebSocket
   connections, so it gets a public domain).

### Step 5: Add the web service

1. **+ New** → **GitHub Repo** → select your fork.
2. **Settings** → **Root Directory**: `.` (the monorepo root — the web
   Dockerfile copies `pnpm-workspace.yaml` and `packages/`).
3. **Settings** → **Build** → **Dockerfile Path**: `apps/web/Dockerfile`
4. **Variables**:

```
NODE_ENV=production
PORT=3000
NEXT_PUBLIC_API_URL=https://${{ api.RAILWAY_PUBLIC_DOMAIN }}
NEXT_PUBLIC_WS_URL=wss://${{ realtime.RAILWAY_PUBLIC_DOMAIN }}
NEXT_PUBLIC_AISOC_DEMO_MODE=true
NEXT_PUBLIC_AISOC_DEMO_DEEPLINK=/cases/INC-001?tab=ledger
NEXT_PUBLIC_AISOC_DEMO_BANNER=Demo data resets daily. All write actions are disabled.
```

5. **Settings** → **Networking** → **Generate Domain**.
6. Generate domains for `api` too (so the browser can reach it directly):
   **api** → **Settings** → **Networking** → **Generate Domain**.

### Step 6: Pre-warm the demo

```bash
# From your local machine:
CORE_API_URL=https://api-<hash>.up.railway.app \
AGENTS_API_URL=https://agents-<hash>.up.railway.app \
  python scripts/demo_seed.py --reset --kickoff-investigation
```

Open the web service's URL — you should land on the demo banner with the
INC-001 deeplink primed.

## Why this isn't a one-click experience

The Railway deploy button is one-click for the **api + Postgres + Redis**.
The remaining three services are ~3 minutes of clicking, but they cannot
be one-clicked because Railway's template system requires a published
template artifact owned by a single account, which fragments badly when
users fork the repo.

If you want fully zero-touch multi-service deploys:
- [**Render**](../render/) — Blueprints handle this natively.
- [**Fly.io**](../fly/) — single shell script provisions everything.
- [**Self-hosted via Coolify**](../coolify/) — drop in the docker-compose
  and click Deploy.

## Daily reset (optional)

Railway has [Cron jobs](https://docs.railway.com/reference/cron-jobs) as
a feature on services with a `[deploy.cronSchedule]` config. To rotate
the demo daily, add a 5th service running the seed script:

```toml
# In a copy of railway.toml under a new service "demo-seed":
[deploy]
cronSchedule = "0 0 * * *"  # daily at 00:00 UTC
startCommand = "python scripts/demo_seed.py --reset --kickoff-investigation"
```

Or skip it for personal evaluation deploys.

## Troubleshooting

### "Web service can't reach api"

Make sure `NEXT_PUBLIC_API_URL` points to the **public** Railway domain
(`*.up.railway.app`), not the private one. The browser can't resolve
`*.railway.internal`.

### "Out of memory on agents service"

The default Railway memory limit is 512MB. Bump it to 2GB in
**Settings** → **Resources** → **Memory**.

### "Database connection refused"

The `${{ Postgres.DATABASE_URL }}` reference only works if the Postgres
plugin is named exactly `Postgres` (case-sensitive). If you renamed it,
update the variable references on each service.

## Files

```
infra/railway/
├── README.md         — this file (multi-service walkthrough)
└── railway.toml      — api service config (consumed by the deploy button)
```

For the full deployment philosophy and platform comparison, see the
[main README](../../README.md#-deploy-in-one-click).
