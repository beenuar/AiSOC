#!/usr/bin/env bash
# 
# fly-demo-deploy.sh
#
# Deploys the full AiSOC live demo stack to Fly.io behind tryaisoc.com.
# Idempotent: safe to re-run after partial failures.
#
# Usage:
#   ./infra/fly/fly-demo-deploy.sh             # full deploy
#   ./infra/fly/fly-demo-deploy.sh --provision # also creates Postgres + Upstash
#   ./infra/fly/fly-demo-deploy.sh --skip-seed # don't run seeder after deploy
#
# Prereqs:
#   - flyctl installed and authed   (https://fly.io/docs/hands-on/install-flyctl/)
#   - FLY_ORG env var set, or override with --org=
#   - DNS for tryaisoc.com (and api., ws.) pointed at the Fly apps via CNAME.
#     The deploy script issues certs but DNS must be live for them to validate.
#
# Architecture:
#
#   tryaisoc.com       aisoc-demo-web      (Next.js UI)
#   api.tryaisoc.com   aisoc-demo-api      (FastAPI; /health, /docs, /api/v1/*)
#   ws.tryaisoc.com    aisoc-demo-realtime (WebSocket fanout)
#
#   web  api, agents, realtime (over Fly's *.internal 6PN DNS)
#   api  agents, realtime, Postgres, Redis
#
#   Postgres = Fly managed (aisoc-demo-postgres)
#   Redis    = Upstash via Fly (aisoc-demo-redis)
#
# Time-to-first-investigation budget: <60s from the tryaisoc.com click.
# The seed job pre-warms a running investigation so the deeplink lands
# inside its TTFI budget regardless of cold-start.
# 

set -euo pipefail

PROVISION=false
SKIP_SEED=false
# `personal` is the canonical name Fly uses for a user's default org. We default
# to it so the script works out of the box for the owner; CI or anyone deploying
# to a different org can override via FLY_ORG= or by editing this default.
ORG="${FLY_ORG:-personal}"
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

#  provision 

REDIS_URL_CAPTURED=""

if $PROVISION; then
  log "provisioning aisoc-demo-postgres (Fly managed Postgres, dev plan)"
  flyctl postgres create \
    --name aisoc-demo-postgres \
    --org "$ORG" \
    --region "$REGION" \
    --vm-size shared-cpu-1x \
    --volume-size 3 \
    --initial-cluster-size 1 || log "(already provisioned)"

  # Upstash Redis on Fly.
  #
  # `flyctl redis create` is the *only* place Fly exposes the connection URL.
  # There's no `redis attach` subcommand and `redis status` doesn't print the
  # URL either, so we capture stdout and grep out the redis:// string. The
  # URL is then propagated to each consuming app via `flyctl secrets set`
  # (see attach_redis below).
  #
  # Plan choice: "Pay-as-you-go" is the cheapest tier ($0.2 / 100K cmds);
  # the older "Free" plan was retired in flyctl 0.4.x. Plan names are
  # case-sensitive: `flyctl redis plans` prints them with a capital P, and
  # passing the lowercase "pay-as-you-go" form returns
  # `Error: plan "pay-as-you-go" not found`.
  #
  # --enable-eviction picks the eviction policy non-interactively. Without
  # this, flyctl prompts ("Would you like to enable eviction?") and dies with
  # "Error: prompt: non interactive" inside scripted runs. We want eviction ON
  # for a demo cache: Upstash will drop old keys instead of refusing writes
  # when the tier fills up.
  #
  # ProdPack: flyctl 0.4.x added a new interactive prompt asking whether you
  # want the ProdPack add-on ($200/mo for enhanced production features).
  # There is no `--no-prodpack` flag (only `--enable-prodpack` to opt in),
  # so the prompt fires unconditionally in scripted runs and dies with
  # "Error: prompt: non interactive". We feed `n\n` on stdin to decline.
  # This is a "default no" prompt so a single newline would also work, but
  # being explicit makes the intent obvious to anyone reading the script.
  log "provisioning Upstash Redis (Pay-as-you-go, eviction enabled)"
  REDIS_CREATE_OUT="$(printf 'n\n' | flyctl redis create \
    --name aisoc-demo-redis \
    --org "$ORG" \
    --region "$REGION" \
    --no-replicas \
    --enable-eviction \
    --plan "Pay-as-you-go" 2>&1 || true)"
  printf '%s\n' "$REDIS_CREATE_OUT"
  REDIS_URL_CAPTURED="$(printf '%s\n' "$REDIS_CREATE_OUT" \
    | grep -oE 'redis://[^[:space:]]+' \
    | head -n1 || true)"
  if [[ -n "$REDIS_URL_CAPTURED" ]]; then
    log "captured REDIS_URL from create output (will be staged on each app)"
  else
    log "(redis already provisioned or URL not in output; will skip secret"
    log " propagation this run  assume REDIS_URL was set on a prior run)"
    log "If this is a fresh redis with no secrets set yet, run:"
    log "  flyctl redis status aisoc-demo-redis  # then copy the redis:// URL"
    log "  flyctl secrets set REDIS_URL= --app aisoc-demo-{api,agents,realtime}"
  fi
fi

#  deploy stack 
# Order matters:
#   1. api       others depend on it via .internal DNS
#   2. agents    api caller
#   3. realtime  web caller
#   4. web       last; serves traffic at tryaisoc.com
#
# The seeder is *not* a separate app  it ships inside the api image as
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
# ensure_app creates a Fly app if it doesn't already exist. Required because
# `flyctl postgres attach` and `flyctl secrets set` both need the target app
# to exist *before* the secret can be written. Our flow stages secrets before
# the first deploy so the app boots with DATABASE_URL/REDIS_URL already
# populated, avoiding the cold-start path where the app comes up, fails to
# connect, and only gets the secret on a redeploy.
ensure_app() {
  local name="$1"
  if flyctl apps list --org "$ORG" 2>/dev/null | awk '{print $1}' | grep -qx "$name"; then
    log "  app $name already exists"
  else
    log "creating Fly app $name in org $ORG"
    flyctl apps create "$name" --org "$ORG"
  fi
}

deploy_app() {
  local name="$1" toml_subdir="$2" build_ctx="$3"
  local toml="$INFRA_DIR/$toml_subdir/fly.toml"
  log "deploying $name (context=$build_ctx, config=$toml)"
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

# `--yes` skips the interactive "Overwrite existing user/secret?" prompt that
# would otherwise hang the script on a re-run. Attach is idempotent on success
# but returns non-zero on the second call (already attached), which we swallow.
attach_pg() {
  local name="$1"
  log "attaching aisoc-demo-postgres  $name (sets DATABASE_URL secret)"
  flyctl postgres attach aisoc-demo-postgres --app "$name" --yes 2>/dev/null \
    || log "($name already attached to postgres)"
}

attach_redis() {
  local name="$1"
  if [[ -z "$REDIS_URL_CAPTURED" ]]; then
    log "skipping redis secret on $name (no REDIS_URL captured this run;"
    log "  assuming a prior --provision run already set it)"
    return 0
  fi
  log "staging REDIS_URL secret on $name (applied on next deploy)"
  # `--stage` writes the secret without triggering a deploy. The deploy_app
  # call directly after will pick it up, so the machine boots with REDIS_URL
  # already populated. Without --stage, flyctl would deploy twice.
  flyctl secrets set "REDIS_URL=$REDIS_URL_CAPTURED" --app "$name" --stage \
    || log "($name secret set failed  will retry on deploy)"
}

# 1. api   build context = services/api/
ensure_app   aisoc-demo-api
attach_pg    aisoc-demo-api
attach_redis aisoc-demo-api
deploy_app   aisoc-demo-api       api       services/api

# 2. agents  build context = services/agents/
ensure_app   aisoc-demo-agents
attach_pg    aisoc-demo-agents
attach_redis aisoc-demo-agents
deploy_app   aisoc-demo-agents    agents    services/agents

# 3. realtime  build context = services/realtime/
ensure_app   aisoc-demo-realtime
attach_redis aisoc-demo-realtime
deploy_app   aisoc-demo-realtime  realtime  services/realtime

# 4. web (public)  build context = repo root (Next.js Dockerfile pulls
#    pnpm-workspace.yaml + packages/* from there).
ensure_app   aisoc-demo-web
deploy_app   aisoc-demo-web       web       .

# 4b. attach tryaisoc.com certs across the three public hostnames.
#
# Why three certs instead of routing everything through tryaisoc.com:
#   - The realtime service speaks raw WebSocket. Next.js rewrites can't
#     proxy WS in production, so the browser opens wss://ws.tryaisoc.com
#     directly.
#   - Sending /api/v1/* through Next rewrites would force every API call
#     through the web app's machine, doubling latency and limiting horizontal
#     scaling. api.tryaisoc.com goes straight to the FastAPI app.
#
# `flyctl certs add` is idempotent: a duplicate add returns non-zero, so we
# swallow it. Cert *issuance* still requires the matching CNAME to be live 
# Fly retries validation in the background and reports status via
# `flyctl certs show <hostname> --app <app>`.
ensure_cert() {
  local hostname="$1" app="$2"
  log "ensuring TLS cert for $hostname (app=$app)"
  flyctl certs add "$hostname" --app "$app" 2>/dev/null \
    || log "  (cert already requested for $hostname)"
}
ensure_cert tryaisoc.com     aisoc-demo-web
ensure_cert api.tryaisoc.com aisoc-demo-api
ensure_cert ws.tryaisoc.com  aisoc-demo-realtime

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
  log "running seed bootstrap inside aisoc-demo-api (one-shot via ssh)"
  # `ssh console -C` runs a single command on a live machine and exits. We
  # accept the slight CPU cost on the traffic-serving machine because (a)
  # the seed is mostly I/O-bound, (b) it's a 30s burst, and (c) it lets us
  # reuse a fully-warm container instead of cold-booting another machine.
  flyctl ssh console \
    --app aisoc-demo-api \
    --command "python -m app.scripts.demo_seed --reset --kickoff-investigation" \
    || err "(seed bootstrap failed; demo will be cold until daily cron runs)"

  log "ensuring daily seed cron at 00:00 UTC on aisoc-demo-api"
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
log "  Public UI:    https://tryaisoc.com           (CNAME  aisoc-demo-web.fly.dev)"
log "  Public API:   https://api.tryaisoc.com       (CNAME  aisoc-demo-api.fly.dev)"
log "  Public WS:    wss://ws.tryaisoc.com          (CNAME  aisoc-demo-realtime.fly.dev)"
log ""
log "  Direct (Fly):"
log "    Web:        https://aisoc-demo-web.fly.dev"
log "    API:        https://aisoc-demo-api.fly.dev/docs"
log "    Realtime:   wss://aisoc-demo-realtime.fly.dev"
log ""
log "DNS setup (add these CNAMEs at your DNS provider before certs validate):"
log "  tryaisoc.com.       CNAME  aisoc-demo-web.fly.dev."
log "  api.tryaisoc.com.   CNAME  aisoc-demo-api.fly.dev."
log "  ws.tryaisoc.com.    CNAME  aisoc-demo-realtime.fly.dev."
log ""
log "  Note: tryaisoc.com is an apex/root record. If your provider doesn't"
log "  support CNAME at apex, use ALIAS/ANAME, or follow Fly's instructions"
log "  from \`flyctl certs show tryaisoc.com --app aisoc-demo-web\` (returns"
log "  the A/AAAA records to use instead)."
log ""
log "Smoke test:"
log "  curl -sf https://aisoc-demo-api.fly.dev/health"
log "  curl -sf https://api.tryaisoc.com/health     # after DNS propagates"
log "  open https://tryaisoc.com/cases/INC-001?tab=ledger"
log ""
log "Cert status (run after DNS is live):"
log "  flyctl certs show tryaisoc.com     --app aisoc-demo-web"
log "  flyctl certs show api.tryaisoc.com --app aisoc-demo-api"
log "  flyctl certs show ws.tryaisoc.com  --app aisoc-demo-realtime"
