#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# fly-demo-deploy.sh
#
# Deploys the full AiSOC live demo stack to Fly.io behind demo.aisoc.dev.
# Idempotent: safe to re-run after partial failures.
#
# Usage:
#   ./infra/fly/fly-demo-deploy.sh             # full deploy
#   ./infra/fly/fly-demo-deploy.sh --provision # also creates Postgres + Upstash
#   ./infra/fly/fly-demo-deploy.sh --skip-seed # don't run seeder after deploy
#
# Prereqs:
#   - flyctl installed and authed   (https://fly.io/docs/hands-on/install-flyctl/)
#   - fly org "aisoc" exists        (fly orgs list)
#   - DNS for demo.aisoc.dev pointed at aisoc-demo-web (CNAME or A record)
#
# Architecture:
#
#   ┌────────────────┐     ┌────────────────┐    ┌────────────────┐
#   │ demo.aisoc.dev │──→  │  web (Next.js) │──→ │  api (FastAPI) │
#   └────────────────┘     └────────────────┘    └────────────────┘
#                                  │                       │
#                                  ▼                       ▼
#                          ┌────────────────┐    ┌────────────────┐
#                          │ realtime (WS)  │    │ agents (LangG) │
#                          └────────────────┘    └────────────────┘
#                                  │                       │
#                                  └─────────┬─────────────┘
#                                            ▼
#                              ┌────────────────────────────┐
#                              │ Fly Postgres + Upstash Redis│
#                              └────────────────────────────┘
#
# Time-to-first-investigation budget: <60s from the demo.aisoc.dev click.
# The seed job pre-warms a running investigation so the deeplink lands
# inside its TTFI budget regardless of cold-start.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

PROVISION=false
SKIP_SEED=false
ORG="${FLY_ORG:-aisoc}"
REGION="${FLY_REGION:-iad}"

for arg in "$@"; do
  case "$arg" in
    --provision)  PROVISION=true ;;
    --skip-seed)  SKIP_SEED=true ;;
    -h|--help)
      grep '^#' "$0" | head -n 50
      exit 0
      ;;
  esac
done

# Resolve repo root and infra paths up front so all build contexts are absolute.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INFRA_DIR="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

log() { printf "\033[1;36m[fly-demo]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[fly-demo]\033[0m %s\n" "$*" >&2; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "required command not found: $1"
    exit 1
  fi
}

require flyctl
require git

# ───────────────────────────────── provision ─────────────────────────────────

if $PROVISION; then
  log "provisioning aisoc-demo-postgres (Fly managed Postgres, dev plan)…"
  flyctl postgres create \
    --name aisoc-demo-postgres \
    --org "$ORG" \
    --region "$REGION" \
    --vm-size shared-cpu-1x \
    --volume-size 3 \
    --initial-cluster-size 1 || log "(already provisioned)"

  log "provisioning Upstash Redis (free tier)…"
  flyctl redis create \
    --name aisoc-demo-redis \
    --org "$ORG" \
    --region "$REGION" \
    --no-replicas \
    --plan Free || log "(already provisioned)"
fi

# ─────────────────────────────── deploy stack ────────────────────────────────
# Order matters:
#   1. api      — others depend on it via .internal DNS
#   2. agents   — api caller
#   3. realtime — web caller
#   4. web      — last; serves traffic at demo.aisoc.dev
#
# The seeder is *not* a separate app — it ships inside the api image as
# `python -m app.scripts.demo_seed`, and we invoke it via `flyctl ssh
# console` post-deploy + a scheduled machine on the api app for the daily
# cron. This avoids a duplicate Dockerfile + the cost of a fifth Fly app
# whose only job is to run a 30-second script.

# deploy_app <fly-app-name> <fly.toml subdir under infra/fly/> <build-context dir>
#
# Why we cd into the build context: the existing service Dockerfiles (api,
# agents, web, realtime) were written assuming the build context is the
# service source dir (they do `COPY pyproject.toml ./` and `COPY . .`).
# Fly's build context defaults to the *current working directory* of `flyctl
# deploy`, so we cd there before invoking it. The fly.toml is referenced by
# absolute path so flyctl still finds it.
deploy_app() {
  local name="$1" toml_subdir="$2" build_ctx="$3"
  local toml="$INFRA_DIR/$toml_subdir/fly.toml"
  log "deploying $name (context=$build_ctx, config=$toml)…"
  if [[ ! -f "$toml" ]]; then
    err "fly.toml not found: $toml"
    exit 1
  fi
  if [[ ! -d "$REPO_ROOT/$build_ctx" ]]; then
    err "build context dir not found: $build_ctx"
    exit 1
  fi
  ( cd "$REPO_ROOT/$build_ctx" && \
      flyctl deploy --remote-only --config "$toml" --app "$name" )
}

attach_pg() {
  local name="$1"
  log "attaching aisoc-demo-postgres → $name (sets DATABASE_URL secret)…"
  flyctl postgres attach aisoc-demo-postgres --app "$name" 2>/dev/null || log "($name already attached)"
}

attach_redis() {
  local name="$1"
  log "attaching aisoc-demo-redis → $name (sets REDIS_URL secret)…"
  # Upstash flow exports REDIS_URL on attach
  flyctl redis attach aisoc-demo-redis --app "$name" 2>/dev/null || log "($name already attached)"
}

# 1. api  — build context = services/api/
attach_pg    aisoc-demo-api
attach_redis aisoc-demo-api
deploy_app   aisoc-demo-api       api       services/api

# 2. agents — build context = services/agents/
attach_pg    aisoc-demo-agents
attach_redis aisoc-demo-agents
deploy_app   aisoc-demo-agents    agents    services/agents

# 3. realtime — build context = services/realtime/
attach_redis aisoc-demo-realtime
deploy_app   aisoc-demo-realtime  realtime  services/realtime

# 4. web (public) — build context = repo root (Next.js Dockerfile pulls
#    pnpm-workspace.yaml + packages/* from there).
deploy_app   aisoc-demo-web       web       .

# 4b. attach demo.aisoc.dev cert
log "ensuring TLS cert for demo.aisoc.dev…"
flyctl certs add demo.aisoc.dev --app aisoc-demo-web 2>/dev/null || log "(cert already issued)"

# 5. seed (in-process on the api app)
#
# Two execution paths:
#   - post-deploy bootstrap (now): SSH into a running api machine and run
#     the seeder once so the demo lands hot for the very next visitor.
#   - daily refresh (cron):        a scheduled Fly machine on aisoc-demo-api
#     boots from the same image, runs the seeder, exits.
#
# Both paths execute `python -m app.scripts.demo_seed`; the canonical
# implementation lives in services/api/app/scripts/demo_seed.py.
if ! $SKIP_SEED; then
  log "running seed bootstrap inside aisoc-demo-api (one-shot via ssh)…"
  # `ssh console -C` runs a single command on a live machine and exits. We
  # accept the slight CPU cost on the traffic-serving machine because (a)
  # the seed is mostly I/O-bound, (b) it's a 30s burst, and (c) it lets us
  # reuse a fully-warm container instead of cold-booting another machine.
  flyctl ssh console \
    --app aisoc-demo-api \
    --command "python -m app.scripts.demo_seed --reset --kickoff-investigation" \
    || err "(seed bootstrap failed; demo will be cold until daily cron runs)"

  log "ensuring daily seed cron at 00:00 UTC on aisoc-demo-api…"
  # Fly scheduled machines fire on the chosen interval and exit cleanly.
  # `--schedule daily` runs once per UTC day. Without an explicit image arg
  # flyctl resolves to the app's currently-deployed image (i.e. the api
  # image we just shipped above), so the seeder always runs against the
  # same code as the live API. Re-running the deploy is safe: if a daily
  # machine already exists, we silently skip (Fly returns non-zero on a
  # name collision).
  flyctl machine run \
    --app aisoc-demo-api \
    --region "$REGION" \
    --schedule daily \
    --vm-size shared-cpu-1x \
    --vm-memory 512 \
    --name aisoc-demo-seed-cron \
    -- python -m app.scripts.demo_seed --reset --kickoff-investigation \
    2>/dev/null || log "(daily seed cron already configured)"
fi

log "deploy complete."
log ""
log "  Public:   https://demo.aisoc.dev"
log "  Web:      https://aisoc-demo-web.fly.dev"
log "  API:      https://aisoc-demo-api.fly.dev/docs"
log "  Realtime: wss://aisoc-demo-realtime.fly.dev"
log ""
log "Smoke test:"
log "  curl -sf https://aisoc-demo-api.fly.dev/health"
log "  open https://demo.aisoc.dev/cases/INC-001?tab=ledger"
