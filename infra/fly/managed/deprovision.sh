#!/usr/bin/env bash
#
# deprovision.sh — tear down a managed-mode AiSOC tenant.
#
# Usage:
#   ./infra/fly/managed/deprovision.sh acme [--keep-postgres]
#
# By default we destroy every Fly resource we own for that slug:
#   * aisoc-{slug}-api / agents / web / realtime
#   * aisoc-{slug}-postgres (unless --keep-postgres is passed)
#   * aisoc-{slug}-redis
#
# Always idempotent — missing resources are silently skipped.
#
# Why --keep-postgres exists: customer churn sometimes ends with a
# legal-hold or "export-then-purge" requirement on the data; the
# operator can keep the Postgres app warm, take a final dump, then
# run `flyctl postgres destroy aisoc-{slug}-postgres` once they've
# verified the export.

set -euo pipefail

SLUG="${1:?usage: deprovision.sh <slug> [--keep-postgres]}"
KEEP_PG=false
shift
for arg in "$@"; do
  case "$arg" in
    --keep-postgres) KEEP_PG=true ;;
    *) echo "deprovision.sh: unknown flag: $arg" >&2; exit 1 ;;
  esac
done

# Slug validation matches render.sh — we don't want this destroying
# everything in the org if someone types `*` by accident.
if [[ ! "$SLUG" =~ ^[a-z0-9-]{2,32}$ ]]; then
  echo "deprovision.sh: invalid slug '$SLUG'" >&2
  exit 1
fi

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "deprovision.sh: required command not found: $1" >&2
    exit 1
  }
}
require flyctl

log() { printf "\033[1;36m[fly-managed]\033[0m %s\n" "$*"; }

destroy_app() {
  local app="$1"
  if flyctl apps show "$app" >/dev/null 2>&1; then
    log "destroying $app"
    flyctl apps destroy "$app" --yes
  else
    log "  $app does not exist (skipping)"
  fi
}

# Tear down user-facing apps before Postgres so any in-flight write is
# cut off before the DB disappears (Fly's volume detach order matters).
destroy_app "aisoc-$SLUG-web"
destroy_app "aisoc-$SLUG-realtime"
destroy_app "aisoc-$SLUG-agents"
destroy_app "aisoc-$SLUG-api"

if [[ "$KEEP_PG" == "true" ]]; then
  log "keeping Postgres for tenant $SLUG (legal-hold / export workflow)"
else
  destroy_app "aisoc-$SLUG-postgres"
fi

if flyctl redis status "aisoc-$SLUG-redis" >/dev/null 2>&1; then
  log "destroying aisoc-$SLUG-redis"
  flyctl redis destroy "aisoc-$SLUG-redis" --yes || true
else
  log "  aisoc-$SLUG-redis does not exist (skipping)"
fi

log "deprovisioned $SLUG."
