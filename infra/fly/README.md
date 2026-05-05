# AiSOC Hosted Demo (Fly.io)

This directory contains the infrastructure-as-code for the public demo at
**[tryaisoc.com](https://tryaisoc.com)**, deployed on Fly.io.

Three public hostnames front the stack:

| Hostname             | Fly app                | Purpose                          |
|----------------------|------------------------|----------------------------------|
| `tryaisoc.com`       | `aisoc-demo-web`       | Next.js UI (apex/root domain)    |
| `api.tryaisoc.com`   | `aisoc-demo-api`       | FastAPI: `/health`, `/api/v1/*`  |
| `ws.tryaisoc.com`    | `aisoc-demo-realtime`  | WebSocket fanout (`wss://`)      |

Why three hostnames instead of routing everything through `tryaisoc.com`:
the realtime service speaks raw WebSocket which Next.js rewrites can't
proxy in production, and sending all `/api/v1/*` through the web app's
machine would double latency. Splitting api/ws onto their own Fly certs
is the standard pattern and keeps the browser's CORS/CSP boundary explicit.

## Goal

> A visitor clicks the README's "Live Demo" button and sees an AiSOC agent
> mid-investigation in **under 60 seconds**, with the full agent decision
> ledger streaming live — no signup, no install.

That sub-60s **time-to-first-investigation (TTFI)** is the headline number
this stack is engineered for.

## Architecture

```
    tryaisoc.com         api.tryaisoc.com      ws.tryaisoc.com
        │                       │                     │
        ▼                       ▼                     ▼
  ┌──────────────┐     ┌──────────────────┐   ┌──────────────────────┐
  │ aisoc-demo-  │     │ aisoc-demo-api   │   │ aisoc-demo-realtime  │
  │ web (Next.js)│     │ (FastAPI)        │   │ (WebSocket)          │
  │ shared-cpu-1x│     │ shared-cpu-1x    │   │ shared-cpu-1x · 0.5GB│
  │ 1GB · min=1  │     │ 1GB · min=1      │   │ auto_stop=off (WS)   │
  └──────────────┘     └──────────────────┘   └──────────────────────┘
        │                       │                     │
        └───── 6PN internal ────┴─────────────────────┘
                                │
                                ▼
                       │                │
                       └───────┬────────┘
                               ▼
              ┌──────────────────────────────────┐
              │  aisoc-demo-agents (LangGraph)   │
              │  shared-cpu-2x · 2GB · min=1     │
              │  AISOC_AGENT_MODE=deterministic  │
              └──────────────────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
   ┌────────────────────────┐   ┌──────────────────────┐
   │ Fly Postgres            │   │ Upstash Redis        │
   │ aisoc-demo-postgres     │   │ aisoc-demo-redis     │
   │ dev plan, 3GB volume    │   │ Free plan            │
   └────────────────────────┘   └──────────────────────┘

   ┌──────────────────────────────────────────────┐
   │  aisoc-demo-seed-cron (scheduled machine)    │  no public traffic
   │  Lives on the aisoc-demo-api app, runs       │
   │  daily at 00:00 UTC using the api image:     │
   │   1. wipe demo tenant                        │
   │   2. seed canonical alerts/cases             │
   │   3. POST /investigate INC-001               │
   └──────────────────────────────────────────────┘
```

What's intentionally **not** here, to keep the demo lean:

| Component   | Status        | Why                                                 |
|-------------|---------------|-----------------------------------------------------|
| Kafka       | disabled      | Realtime uses Redis pub/sub on the demo path        |
| ClickHouse  | disabled      | No analytics queries in the demo flow               |
| OpenSearch  | disabled      | Detection rules ship with synthetic match payloads  |
| Neo4j       | disabled      | Attack graph isn't on the canonical demo path       |
| Qdrant      | disabled      | KB lookup uses the in-image Postgres + pg_trgm path |

These get re-enabled the moment a self-hoster wants the full stack — see
the root `docker-compose.yml` and `services/*/Dockerfile`.

## Files

```
infra/fly/
├── README.md           — this file
├── fly-demo-deploy.sh  — orchestrator: provisions DB, deploys 4 apps, runs seed
├── api/fly.toml        — FastAPI core API (also hosts the seeder process)
├── agents/fly.toml     — LangGraph orchestrator + investigator agents
├── web/fly.toml        — Next.js console (public)
└── realtime/fly.toml   — WebSocket fanout
```

The seeder is **not** a separate app. It ships inside the api image as
`python -m app.scripts.demo_seed`, which lets us run it two ways without
maintaining a fifth Dockerfile or Fly app:

| When                     | How                                                                                  |
|--------------------------|--------------------------------------------------------------------------------------|
| Post-deploy (bootstrap)  | `flyctl ssh console -a aisoc-demo-api -C "python -m app.scripts.demo_seed --reset --kickoff-investigation"` runs once on a live api machine, populating Postgres and starting the canonical investigation in ~30s. |
| Daily refresh (00:00 UTC)| A scheduled Fly machine on the `aisoc-demo-api` app, named `aisoc-demo-seed-cron`, boots from the same api image, runs the same command, and exits. |
| Local recovery           | `python scripts/demo_seed.py --reset` from the repo root — the shim re-execs the canonical module against your `docker-compose` stack. |

The canonical implementation lives in
[`services/api/app/scripts/demo_seed.py`](../../services/api/app/scripts/demo_seed.py);
[`scripts/demo_seed.py`](../../scripts/demo_seed.py) is a thin shim for repo-root invocation.

The seed flow is the secret sauce for the TTFI budget:

```
00:00 UTC  ┌────────────────────────────────────────────────────┐
           │ 1. scheduled machine boots from api image          │
           │ 2. runs `python -m app.scripts.demo_seed --reset   │
           │    --kickoff-investigation`                        │
           │ 3. POSTs /api/v1/cases/INC-001/investigate         │
           │ 4. agents.internal streams events → realtime       │
           │ 5. realtime broadcasts → web WS connections        │
           │ Investigation completes within 30-90s.             │
           └────────────────────────────────────────────────────┘

T+anytime  ┌────────────────────────────────────────────────────┐
           │ Visitor lands at /cases/INC-001?tab=ledger         │
           │   - case is already CREATED                        │
           │   - investigation_run is COMPLETED or RUNNING      │
           │   - ledger has 20-50 events ready to stream        │
           │ Time-to-first-investigation: 0s (already running). │
           └────────────────────────────────────────────────────┘
```

## First-time setup

```bash
# 1. Install flyctl + auth
brew install flyctl
flyctl auth login

# 2. Pick the org. The deploy script defaults to `personal` (each Fly user's
#    default org). Override with FLY_ORG=… if you're deploying under a team org.
export FLY_ORG=personal

# 3. Reserve app names (one-time, idempotent)
for app in aisoc-demo-api aisoc-demo-agents aisoc-demo-web \
           aisoc-demo-realtime; do
  flyctl apps create "$app" --org "$FLY_ORG" 2>/dev/null || true
done

# 4. Provision Postgres + Upstash + deploy everything + request TLS certs
./infra/fly/fly-demo-deploy.sh --provision

# 5. Add DNS at your provider (the deploy script prints the exact records):
#    tryaisoc.com.       CNAME  aisoc-demo-web.fly.dev.
#    api.tryaisoc.com.   CNAME  aisoc-demo-api.fly.dev.
#    ws.tryaisoc.com.    CNAME  aisoc-demo-realtime.fly.dev.
#
#    tryaisoc.com is an apex/root record. If your DNS provider doesn't support
#    CNAME at apex, use ALIAS/ANAME, or run
#      flyctl certs show tryaisoc.com --app aisoc-demo-web
#    to get the A/AAAA records to use instead.
```

## Routine deploy

```bash
# Push your branch, then:
./infra/fly/fly-demo-deploy.sh
```

Re-running is idempotent. Already-provisioned Postgres / Redis / cert add
calls fail-soft.

## Demo mode at runtime

The `AISOC_DEMO_MODE` flag is set on every Fly app's `[env]` block. This
flag drives two pieces of behavior:

1. **API middleware (`services/api/app/middleware/demo_mode.py`)**
   Returns 403 for non-allowlisted writes (POST/PUT/PATCH/DELETE) and stamps
   `X-AiSOC-Demo: true` plus `X-AiSOC-Demo-Banner` headers on every response.
   Allowlisted writes: auth flows, `/cases/INC-001/investigate`, alert ack.

2. **Web banner (`apps/web/src/components/demo/DemoBanner.tsx`)**
   Renders a fixed amber strip at the top of every authenticated page with
   the daily-reset notice and a "Self-host AiSOC →" link.

Both layers read from environment variables surfaced through the
`fly.toml` `[env]` blocks, so flipping any AiSOC self-hoster into demo
mode (e.g., for a customer presentation) is a one-flag operation.

## Smoke checks

```bash
# API liveness
curl -sf https://aisoc-demo-api.fly.dev/health

# Demo headers visible
curl -sI https://aisoc-demo-api.fly.dev/api/v1/cases | grep -i x-aisoc

# Mutating writes blocked
curl -si -X POST https://aisoc-demo-api.fly.dev/api/v1/cases | head -3
# expect: HTTP/2 403 …

# Public domain (after DNS propagates)
curl -sf https://api.tryaisoc.com/health

# Visitor flow
open https://tryaisoc.com/cases/INC-001?tab=ledger
```

## Troubleshooting

| Symptom                                     | Likely cause / fix                                 |
|---------------------------------------------|----------------------------------------------------|
| `flyctl deploy` hangs on builder            | Nuke remote builder: `flyctl builders destroy`     |
| API 503 on first hit                        | Cold start; `min_machines_running=1` should fix    |
| Web shows "demo data resets" but writes work| API's `AISOC_DEMO_MODE` not set; redeploy api       |
| INC-001 case missing                         | Re-run seed: `flyctl ssh console -a aisoc-demo-api -C "python -m app.scripts.demo_seed --reset --kickoff-investigation"` |
| Daily seed cron not firing                   | Verify the scheduled machine: `flyctl machine list -a aisoc-demo-api` (look for `aisoc-demo-seed-cron`) |
| WS disconnects in 30s                        | Realtime `auto_stop_machines = "off"` — verify fly.toml |
| Cert pending                                 | `flyctl certs show tryaisoc.com --app aisoc-demo-web` (and same for `api.` / `ws.` subdomains) |

## Cost envelope

Target: **<$30/mo** for the running demo so it's sustainable on a single
maintainer's budget.

| Resource                                  | Monthly cost (est.)         |
|-------------------------------------------|-----------------------------|
| 3 × shared-cpu-1x machines (api, web, rt) | ~$6 (with auto_stop=stop)   |
| 1 × shared-cpu-2x agents                  | ~$5                         |
| 1 × scheduled seed machine (~1min/day)    | <$0.10                      |
| Fly Postgres (dev, 3GB)                   | ~$2                         |
| Upstash Redis (Free)                      | $0                          |
| Outbound bandwidth (~50GB)                | ~$1                         |
| **Total**                                 | **~$14/mo**                 |

If demo traffic exceeds 50GB/mo we'll cache the seed snapshot on Cloudflare R2.
