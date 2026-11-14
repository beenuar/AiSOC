#!/usr/bin/env bash
#
# provision.sh — bootstrap (or reconcile) a managed-mode AiSOC tenant on Fly.
#
# Usage:
#   ./infra/fly/managed/provision.sh infra/fly/managed/tenants/acme.yaml
#
# What it does (idempotent — each step is `|| true` after the first run):
#
#   1. Render the manifest into per-component fly.toml files.
#   2. `flyctl apps create` for api / agents / web / realtime (no-op if
#      already created).
#   3. `flyctl postgres create` (no-op if already exists).
#   4. Attach Postgres to the api app so DATABASE_URL is injected.
#   5. Provision Upstash Redis via `flyctl redis create` and pipe the URL
#      into REDIS_URL on every app.
#   6. Allocate a Fernet key for AISOC_CREDENTIAL_KEY (only on first run —
#      reusing existing secrets is critical because rotating the Fernet
#      key invalidates all stored connector credentials).
#   7. Deploy api, agents, realtime, then web (web depends on others).
#   8. Add custom hostnames + request certs for the three public hosts.
#
# Required env vars:
#   FLY_API_TOKEN  — `flyctl auth token` of a user with org access.
#   FLY_ORG        — Fly org slug; defaults to `aisoc-managed`.
#
# This script makes no assumptions about the local working directory; it
# resolves the repo root from its own location.

set -euo pipefail

MANIFEST="${1:?usage: provision.sh <tenant-manifest.yaml>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

ORG="${FLY_ORG:-aisoc-managed}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "provision.sh: required command not found: $1" >&2
    exit 1
  }
}
require flyctl
require yq
require envsubst
require python3

log() { printf "\033[1;36m[fly-managed]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[fly-managed]\033[0m %s\n" "$*" >&2; }

# ---------- read manifest ----------
TENANT_SLUG=$(yq -r '.slug' "$MANIFEST")
TENANT_DISPLAY_NAME=$(yq -r '.display_name' "$MANIFEST")
REGION=$(yq -r '.region // "iad"' "$MANIFEST")
BASE_DOMAIN=$(yq -r '.base_domain' "$MANIFEST")
PLAN=$(yq -r '.plan // "standard"' "$MANIFEST")
CONTACT_EMAIL=$(yq -r '.contact_email' "$MANIFEST")
POSTGRES_PLAN=$(yq -r '.postgres_plan // "development"' "$MANIFEST")

log "provisioning tenant slug=$TENANT_SLUG plan=$PLAN region=$REGION base_domain=$BASE_DOMAIN"

API_APP="aisoc-$TENANT_SLUG-api"
AGENTS_APP="aisoc-$TENANT_SLUG-agents"
WEB_APP="aisoc-$TENANT_SLUG-web"
RT_APP="aisoc-$TENANT_SLUG-realtime"
PG_APP="aisoc-$TENANT_SLUG-postgres"
REDIS_APP="aisoc-$TENANT_SLUG-redis"

# ---------- 1. render templates ----------
RENDER_DIR=$("$SCRIPT_DIR/render.sh" "$MANIFEST")
log "rendered templates -> $RENDER_DIR"

# ---------- 2. create apps (idempotent) ----------
for app in "$API_APP" "$AGENTS_APP" "$WEB_APP" "$RT_APP"; do
  flyctl apps create "$app" --org "$ORG" >/dev/null 2>&1 \
    || log "  app exists: $app (skipping create)"
done

# ---------- 3. provision Postgres ----------
if ! flyctl apps show "$PG_APP" >/dev/null 2>&1; then
  log "provisioning Postgres ($POSTGRES_PLAN)"
  flyctl postgres create \
    --name "$PG_APP" \
    --org "$ORG" \
    --region "$REGION" \
    --vm-size shared-cpu-1x \
    --initial-cluster-size 1 \
    --volume-size 3 \
    --password "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
    || err "postgres create failed (already exists? check Fly dashboard)"
else
  log "  Postgres exists: $PG_APP (skipping create)"
fi

# Attach Postgres to api app — injects DATABASE_URL automatically.
flyctl postgres attach "$PG_APP" \
  --app "$API_APP" >/dev/null 2>&1 \
  || log "  Postgres already attached to $API_APP"

# ---------- 4. provision Redis ----------
if ! flyctl redis status "$REDIS_APP" >/dev/null 2>&1; then
  log "provisioning Upstash Redis"
  REDIS_URL=$(flyctl redis create \
    --name "$REDIS_APP" \
    --org "$ORG" \
    --region "$REGION" \
    --no-replicas \
    --plan "free" \
    --enable-eviction 2>&1 | tee /tmp/redis-$TENANT_SLUG.log \
    | awk '/redis:\/\//{print $NF}' | tail -n1)
  if [[ -z "$REDIS_URL" ]]; then
    err "could not extract REDIS_URL from flyctl output; see /tmp/redis-$TENANT_SLUG.log"
    exit 1
  fi
else
  log "  Redis exists: $REDIS_APP — reading URL"
  REDIS_URL=$(flyctl redis status "$REDIS_APP" --json | yq -r '.url')
fi

# ---------- 5. seed shared secrets ----------
# Fernet key — only ever generated once. We probe the api app first;
# if the secret is already set we do nothing.
if ! flyctl secrets list -a "$API_APP" 2>/dev/null | grep -q AISOC_CREDENTIAL_KEY; then
  log "minting fresh AISOC_CREDENTIAL_KEY"
  KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
  flyctl secrets set -a "$API_APP" AISOC_CREDENTIAL_KEY="$KEY" >/dev/null
  flyctl secrets set -a "$AGENTS_APP" AISOC_CREDENTIAL_KEY="$KEY" >/dev/null
fi

# Redis URL is the same across all four apps.
for app in "$API_APP" "$AGENTS_APP" "$RT_APP"; do
  flyctl secrets set -a "$app" REDIS_URL="$REDIS_URL" >/dev/null \
    || log "  could not set REDIS_URL on $app"
done

# Contact email for cert renewal notices.
flyctl secrets set -a "$API_APP" AISOC_OPERATOR_EMAIL="$CONTACT_EMAIL" >/dev/null

# ---------- 6. deploy ----------
deploy_app() {
  local component="$1"
  local app="$2"
  local context="$3"
  local config="$RENDER_DIR/$component/fly.toml"
  log "deploying $app from $context (config=$config)"
  ( cd "$REPO_ROOT/$context" && flyctl deploy \
      --remote-only \
      --config "$config" \
      --app "$app" )
}

deploy_app api      "$API_APP"     "services/api"
deploy_app agents   "$AGENTS_APP"  "services/agents"
deploy_app realtime "$RT_APP"      "services/realtime"
deploy_app web      "$WEB_APP"     "apps/web"

# ---------- 7. public hostnames + certs ----------
issue_cert() {
  local app="$1" host="$2"
  flyctl certs create "$host" --app "$app" >/dev/null 2>&1 || true
  flyctl certs show "$host" --app "$app" 2>/dev/null \
    || log "  cert pending verification: $host"
}
issue_cert "$WEB_APP" "$BASE_DOMAIN"
issue_cert "$API_APP" "api.$BASE_DOMAIN"
issue_cert "$RT_APP"  "ws.$BASE_DOMAIN"

log "tenant $TENANT_SLUG provisioned. DNS records to add (one-time):"
cat <<EOF
  $BASE_DOMAIN.       CNAME  $WEB_APP.fly.dev.
  api.$BASE_DOMAIN.   CNAME  $API_APP.fly.dev.
  ws.$BASE_DOMAIN.    CNAME  $RT_APP.fly.dev.
EOF
