#!/usr/bin/env bash
#
# list.sh — show every managed-mode tenant + the rollout status of its apps.
#
# Output columns:
#   SLUG  DISPLAY  REGION  API  AGENTS  WEB  REALTIME
#
# Status values:
#   ok       — at least one machine running and the last release succeeded
#   pending  — app exists but no machine running yet
#   missing  — app does not exist for that slug

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "list.sh: required command not found: $1" >&2
    exit 1
  }
}
require flyctl
require yq

app_status() {
  local app="$1"
  if ! flyctl apps show "$app" >/dev/null 2>&1; then
    echo "missing"
    return
  fi
  local count
  count=$(flyctl machine list -a "$app" --json 2>/dev/null \
    | yq -r '[.[] | select(.state == "started")] | length' 2>/dev/null || echo 0)
  if [[ "${count:-0}" -gt 0 ]]; then
    echo "ok"
  else
    echo "pending"
  fi
}

printf "%-16s %-24s %-8s %-9s %-9s %-9s %-9s\n" \
  SLUG DISPLAY REGION API AGENTS WEB REALTIME

shopt -s nullglob
for manifest in "$SCRIPT_DIR/tenants"/*.yaml; do
  slug=$(yq -r '.slug' "$manifest")
  display=$(yq -r '.display_name' "$manifest")
  region=$(yq -r '.region // "iad"' "$manifest")
  printf "%-16s %-24s %-8s %-9s %-9s %-9s %-9s\n" \
    "$slug" "$display" "$region" \
    "$(app_status "aisoc-$slug-api")" \
    "$(app_status "aisoc-$slug-agents")" \
    "$(app_status "aisoc-$slug-web")" \
    "$(app_status "aisoc-$slug-realtime")"
done
