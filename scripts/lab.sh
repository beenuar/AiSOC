#!/usr/bin/env bash
# =============================================================================
# AiSOC Demo Lab — one-command full-stack setup
# =============================================================================
# Usage:
#   pnpm aisoc:lab              # start the full lab (default)
#   pnpm aisoc:lab -- --reset   # wipe volumes and start fresh
#   pnpm aisoc:lab -- --down    # tear down everything
#   pnpm aisoc:lab -- --logs    # follow logs after startup
#
# What it does:
#   1. Starts the full Docker Compose stack (infra + API + agents + web)
#   2. Waits for all health checks to pass
#   3. Seeds the database with demo data (cases, alerts, playbooks)
#   4. Injects a Conti-style ransomware scenario into the alert stream
#   5. Prints service URLs to the console
#
# Prerequisites:
#   - Docker Desktop (or Docker Engine + Compose v2)
#   - pnpm (for the web app build step, optional)
# =============================================================================
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/../docker-compose.yml"
SCENARIO_SCRIPT="$(dirname "$0")/inject_scenario.py"

# Parse flags
RESET=false
DOWN=false
FOLLOW_LOGS=false
for arg in "$@"; do
  case "$arg" in
    --reset)  RESET=true  ;;
    --down)   DOWN=true   ;;
    --logs)   FOLLOW_LOGS=true ;;
  esac
done

# ── Colours ────────────────────────────────────────────────────────────────────
BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}▶  $*${NC}"; }
ok()     { echo -e "  ${GREEN}✓${NC}  $*"; }
warn()   { echo -e "  ${YELLOW}⚠${NC}  $*"; }
fail()   { echo -e "  ${RED}✗${NC}  $*"; exit 1; }

# ── Tear-down ──────────────────────────────────────────────────────────────────
if $DOWN; then
  banner "Tearing down AiSOC Demo Lab..."
  docker compose -f "$COMPOSE_FILE" down --remove-orphans
  ok "All containers stopped"
  exit 0
fi

# ── Reset (wipe volumes) ───────────────────────────────────────────────────────
if $RESET; then
  banner "Resetting AiSOC Demo Lab (wiping volumes)..."
  docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans || true
  ok "Volumes wiped"
fi

# ── Pre-flight checks ──────────────────────────────────────────────────────────
banner "Pre-flight checks"
command -v docker &>/dev/null     || fail "Docker not found. Install Docker Desktop."
docker info &>/dev/null           || fail "Docker daemon not running."
command -v docker compose &>/dev/null 2>&1 || \
  docker compose version &>/dev/null 2>&1  || \
  fail "Docker Compose v2 not found. Update Docker Desktop."
ok "Docker OK"

# ── Start the stack ────────────────────────────────────────────────────────────
banner "Starting AiSOC Demo Lab..."
echo -e "  Compose file: ${CYAN}${COMPOSE_FILE}${NC}\n"

docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

# ── Wait for core services ─────────────────────────────────────────────────────
banner "Waiting for services to become healthy..."

wait_healthy() {
  local name="$1"
  local max="${2:-60}"
  local i=0
  printf "  Waiting for %-20s" "$name..."
  while [ $i -lt $max ]; do
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' "aisoc-${name}" 2>/dev/null || true)
    if [[ "$health" == "healthy" ]]; then
      echo -e " ${GREEN}healthy${NC}"
      return 0
    fi
    sleep 2; ((i+=2))
    printf "."
  done
  echo -e " ${RED}timeout${NC}"
  warn "$name did not become healthy within ${max}s — continuing anyway"
  return 0
}

wait_healthy "postgres"   90
wait_healthy "redis"      30
wait_healthy "kafka"      60

# Also wait for the API (HTTP health endpoint)
wait_api() {
  local url="http://localhost:8000/api/v1/health"
  local max=120; local i=0
  printf "  Waiting for %-20s" "api..."
  while [ $i -lt $max ]; do
    if curl -sf "$url" &>/dev/null; then
      echo -e " ${GREEN}ready${NC}"
      return 0
    fi
    sleep 3; ((i+=3)); printf "."
  done
  echo -e " ${YELLOW}not ready${NC}"
  warn "API health check timed out — services may still be starting"
  return 0
}
wait_api

# ── Seed demo data ─────────────────────────────────────────────────────────────
banner "Seeding demo data..."
if docker compose -f "$COMPOSE_FILE" exec -T api \
     python -m app.scripts.seed_demo 2>/dev/null; then
  ok "Demo cases, alerts, and playbooks seeded"
else
  warn "Seed script failed or not found — you can seed manually later with:"
  echo  "    docker compose exec api python -m app.scripts.seed_demo"
fi

# ── Inject Conti ransomware scenario ──────────────────────────────────────────
banner "Injecting Conti-style ransomware scenario..."
if [ -f "$SCENARIO_SCRIPT" ]; then
  python3 "$SCENARIO_SCRIPT" --api-url http://localhost:8000 2>/dev/null && \
    ok "Conti ransomware scenario injected — check the Cases dashboard" || \
    warn "Scenario injection failed — you can run it manually: python3 scripts/inject_scenario.py"
else
  warn "inject_scenario.py not found — skipping (will be auto-generated on first run)"
fi

# ── Print service URLs ─────────────────────────────────────────────────────────
banner "AiSOC Demo Lab is ready! 🚀"
echo ""
echo -e "  ${BOLD}Service URLs${NC}"
echo -e "  ${CYAN}Web App          ${NC}→  http://localhost:3000"
echo -e "  ${CYAN}API (REST)       ${NC}→  http://localhost:8000/docs"
echo -e "  ${CYAN}API (GraphQL)    ${NC}→  http://localhost:8000/graphql"
echo -e "  ${CYAN}Agent Orchestrator${NC}→  http://localhost:8001/docs"
echo -e "  ${CYAN}Jaeger Tracing   ${NC}→  http://localhost:16686"
echo -e "  ${CYAN}Kafka UI         ${NC}→  http://localhost:8080"
echo -e "  ${CYAN}OpenSearch       ${NC}→  http://localhost:9200"
echo ""
echo -e "  ${BOLD}Quick commands${NC}"
echo -e "  ${YELLOW}pnpm aisoc:lab -- --logs${NC}   Follow all container logs"
echo -e "  ${YELLOW}pnpm aisoc:lab -- --reset${NC}  Wipe volumes and restart"
echo -e "  ${YELLOW}pnpm aisoc:lab -- --down${NC}   Stop everything"
echo ""

# ── Optional: follow logs ──────────────────────────────────────────────────────
if $FOLLOW_LOGS; then
  docker compose -f "$COMPOSE_FILE" logs -f
fi
