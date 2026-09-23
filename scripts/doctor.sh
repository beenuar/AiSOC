#!/usr/bin/env bash
#
# AiSOC doctor — diagnose a deployment and say what to do next.
#
# Every check answers one question an engineer would actually ask, and a
# failure prints the command that investigates it. The rule here is that a
# check must probe the thing it names: "the container is running" is not
# evidence that the service works, and this script does not report it as such.
#
#   ./scripts/doctor.sh            # diagnose the default (CORE) profile
#   ./scripts/doctor.sh --full     # also check the full-profile stores
#   ./scripts/doctor.sh --quiet    # only print problems
#
# Exit code is 0 only when every required check passes.
set -uo pipefail

PROFILE_FULL=0
QUIET=0
for arg in "$@"; do
  case "$arg" in
    --full)  PROFILE_FULL=1 ;;
    --quiet) QUIET=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; X=$'\033[0m'
else
  G=""; R=""; Y=""; D=""; B=""; X=""
fi

FAILURES=0
WARNINGS=0

# `fail() { ((N++)); }` returns the pre-increment value, which is 0 the first
# time — under `set -e` that kills the script before it prints why. The
# arithmetic is written as an assignment for that reason.
pass() { [ "$QUIET" = "1" ] || printf '%s✓%s %s\n' "$G" "$X" "$1"; }
warn() { WARNINGS=$((WARNINGS + 1)); printf '%s!%s %s\n' "$Y" "$X" "$1"; [ -n "${2:-}" ] && printf '  %sfix:%s %s\n' "$D" "$X" "$2"; return 0; }
fail() { FAILURES=$((FAILURES + 1)); printf '%s✗%s %s\n' "$R" "$X" "$1"; [ -n "${2:-}" ] && printf '  %sfix:%s %s\n' "$D" "$X" "$2"; return 0; }
head2() { [ "$QUIET" = "1" ] || printf '\n%s%s%s\n' "$B" "$1" "$X"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Resolve the compose command once. Everything below runs through it so the
# checks apply to whatever project the caller actually started.
COMPOSE=""
if have docker && docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
fi

# `docker compose exec` needs -T when stdin is not a TTY (CI).
dc_exec() { $COMPOSE exec -T "$@" 2>/dev/null; }

svc_running() { [ -n "$($COMPOSE ps -q "$1" 2>/dev/null)" ]; }

http_ok() {
  # $1 url, $2 timeout. Prints the status code.
  curl -s -o /dev/null -m "${2:-5}" -w '%{http_code}' "$1" 2>/dev/null || echo "000"
}

# ── 1. Host prerequisites ───────────────────────────────────────────────────
head2 "Host"

if ! have docker; then
  fail "docker is not installed" "https://docs.docker.com/get-docker/"
elif ! docker info >/dev/null 2>&1; then
  fail "docker is installed but the daemon is not responding" "start Docker Desktop, or: sudo systemctl start docker"
else
  pass "docker daemon responding"
fi

if [ -z "$COMPOSE" ]; then
  fail "docker compose v2 is not available" "install Docker Compose v2 (docker compose version)"
else
  pass "docker compose v2 available"
fi

if docker info >/dev/null 2>&1; then
  # Disk exhaustion inside the Docker VM corrupts Kafka's log dir and the
  # broker then reports healthy while refusing every request. That exact
  # failure cost hours, so it is checked before anything else.
  avail_raw="$(docker run --rm --entrypoint sh alpine:3 -c 'df -P /' 2>/dev/null | awk 'NR==2{print $4}')"
  if [ -n "${avail_raw:-}" ]; then
    avail_gb=$((avail_raw / 1024 / 1024))
    if [ "$avail_gb" -lt 5 ]; then
      fail "docker has ${avail_gb}GB free — Kafka will corrupt its log dir below ~2GB" "docker system prune -af && docker volume prune -f"
    elif [ "$avail_gb" -lt 15 ]; then
      warn "docker has ${avail_gb}GB free (15GB+ recommended for the full profile)" "docker system prune -af"
    else
      pass "docker disk space: ${avail_gb}GB free"
    fi
  fi

  mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
  if [ "$mem_gb" -gt 0 ] && [ "$mem_gb" -lt 6 ]; then
    fail "docker has ${mem_gb}GB RAM — CORE needs 6GB, full needs 12GB" "raise the memory limit in Docker Desktop → Settings → Resources"
  elif [ "$mem_gb" -gt 0 ]; then
    pass "docker memory: ${mem_gb}GB"
  fi
fi

# ── 2. Ports ────────────────────────────────────────────────────────────────
head2 "Ports"
port_busy() {
  if have lsof; then lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif have ss;   then ss -ltn 2>/dev/null | grep -q ":$1 "
  else return 1; fi
}
# Only flags a port held by something that is NOT our own stack.
for spec in "5432 postgres" "6379 redis" "9092 kafka" "8000 api" "8081 ingest-worker" "3000 web"; do
  port="${spec%% *}"; owner="${spec##* }"
  if port_busy "$port"; then
    if [ -n "$COMPOSE" ] && svc_running "$owner"; then
      pass "port $port in use by aisoc $owner"
    else
      fail "port $port is held by another process (needed by $owner)" "lsof -nP -iTCP:$port -sTCP:LISTEN   # then stop it, or change the host port in docker-compose.yml"
    fi
  else
    [ "$QUIET" = "1" ] || printf '%s·%s port %s free\n' "$D" "$X" "$port"
  fi
done

[ -z "$COMPOSE" ] && { printf '\n%sCannot check services without docker compose.%s\n' "$R" "$X"; exit 1; }

# ── 3. Configuration ────────────────────────────────────────────────────────
head2 "Configuration"
if [ -f .env ]; then
  pass ".env present"
  if grep -qE '^[A-Z_]*(SECRET|PASSWORD|KEY)=(change_me|changeme|)$' .env 2>/dev/null; then
    warn ".env has unset or placeholder secrets" "./install.sh regenerates them, or edit .env by hand"
  fi
else
  warn ".env not found — compose will fall back to built-in dev defaults" "cp .env.example .env"
fi

# ── 4. Datastores — probed, not just 'running' ──────────────────────────────
head2 "Datastores"

if svc_running postgres; then
  if dc_exec postgres pg_isready -U aisoc -d aisoc >/dev/null; then
    pass "postgres accepting connections"
    tables="$(dc_exec postgres psql -U aisoc -d aisoc -tAc "select count(*) from information_schema.tables where table_schema='public'" | tr -d '[:space:]')"
    if [ "${tables:-0}" -gt 0 ] 2>/dev/null; then
      pass "postgres schema present (${tables} tables)"
    else
      fail "postgres has no tables — migrations did not run" "docker compose logs api | grep -i migrat"
    fi
  else
    fail "postgres container is up but not accepting connections" "docker compose logs postgres | tail -40"
  fi
else
  fail "postgres is not running" "docker compose up -d postgres"
fi

if svc_running redis; then
  # The compose default starts redis with --requirepass, so an
  # unauthenticated PING answers NOAUTH. That is still proof the server is
  # alive and serving, which is what this check is for — treating it as a
  # failure reported a healthy redis as broken.
  redis_reply="$(dc_exec redis redis-cli ping)"
  if printf '%s' "$redis_reply" | grep -q 'PONG'; then
    pass "redis responding to PING"
  elif printf '%s' "$redis_reply" | grep -qi 'NOAUTH\|WRONGPASS'; then
    pass "redis responding (authentication required, as configured)"
  else
    fail "redis is up but not responding to PING" "docker compose logs redis | tail -20"
  fi
else
  fail "redis is not running" "docker compose up -d redis"
fi

if svc_running kafka; then
  # `kafka-topics --list` is the check that matters: the container healthcheck
  # passes on a broker whose log dir has failed, which is how a disk-full
  # broker reported healthy while refusing every produce.
  if topics="$(dc_exec kafka kafka-topics --bootstrap-server localhost:29092 --list)"; then
    count="$(printf '%s\n' "$topics" | grep -c . || true)"
    pass "kafka broker answering admin requests (${count} topics)"
    if printf '%s\n' "$topics" | grep -q '^aisoc\.raw_events$'; then
      pass "topic aisoc.raw_events exists"
    else
      warn "topic aisoc.raw_events does not exist yet" "it is auto-created on the first ingested event; send one with: make smoke"
    fi
  else
    fail "kafka is up but not answering admin requests" "docker compose logs kafka | grep -iE 'no space|error' | tail -20"
  fi
else
  fail "kafka is not running" "docker compose up -d kafka"
fi

if [ "$PROFILE_FULL" = "1" ]; then
  head2 "Full-profile stores"
  for spec in "clickhouse 8123 /ping" "neo4j 7474 /" "qdrant 6333 /readyz" "opensearch 9200 /"; do
    set -- $spec; name="$1"; port="$2"; path="$3"
    if svc_running "$name"; then
      code="$(dc_exec "$name" sh -c "wget -qO- -T 3 http://localhost:${port}${path} >/dev/null 2>&1 && echo 200 || echo 000")"
      if [ "$code" = "200" ]; then pass "$name responding on $port"
      else warn "$name is running but did not answer http://localhost:${port}${path}" "docker compose logs $name | tail -20"; fi
    else
      warn "$name is not running (full profile)" "docker compose --profile full up -d $name"
    fi
  done
fi

# ── 5. Services ─────────────────────────────────────────────────────────────
head2 "Services"

check_http_service() {
  local name="$1" url="$2" hint="$3"
  if ! svc_running "$name"; then
    fail "$name is not running" "docker compose up -d $name"
    return
  fi
  local code; code="$(http_ok "$url" 6)"
  case "$code" in
    200|204) pass "$name healthy ($url)" ;;
    000)     fail "$name is running but $url did not respond" "$hint" ;;
    *)       fail "$name returned HTTP $code from $url" "$hint" ;;
  esac
}

check_http_service api          "${AISOC_API_URL:-http://localhost:8000}/health"   "docker compose logs api | tail -40"
check_http_service ingest-worker "${AISOC_INGEST_URL:-http://localhost:8081}/health" "docker compose logs ingest-worker | tail -40"

# Fusion has no HTTP health route in every build, so it is checked by whether
# its consumer actually joined the group — the thing that matters.
if svc_running fusion; then
  # Probe the service rather than grepping its log. A log line scrolls out of
  # retention and a restart loses it, so log-grep reported a working fusion as
  # broken. The HTTP probe answers the same question durably.
  fusion_code="$(http_ok "${AISOC_FUSION_URL:-http://localhost:8003}/health" 6)"
  if [ "$fusion_code" = "200" ]; then
    pass "fusion healthy"
  elif $COMPOSE logs fusion 2>/dev/null | grep -q 'Fusion worker started'; then
    warn "fusion started but its HTTP health route did not answer" "docker compose logs fusion | tail -40"
  else
    fail "fusion is running but neither healthy nor started" "docker compose logs fusion | tail -60"
  fi
  if $COMPOSE logs fusion 2>/dev/null | grep -qi 'GroupCoordinatorNotAvailable\|Unable to update metadata'; then
    warn "fusion reported Kafka metadata errors (may be transient at boot)" "docker compose logs fusion | grep -i kafka | tail -20"
  fi
else
  fail "fusion is not running — events will never become alerts" "docker compose up -d fusion"
fi

for spec in "web 3000 /" "realtime 8086 /health" "agents 8001 /health"; do
  set -- $spec; name="$1"; port="$2"; path="$3"
  if svc_running "$name"; then
    code="$(http_ok "http://localhost:${port}${path}" 6)"
    if [ "$code" = "200" ] || [ "$code" = "204" ]; then pass "$name healthy"
    else warn "$name is running but http://localhost:${port}${path} returned $code" "docker compose logs $name | tail -30"; fi
  else
    warn "$name is not running" "docker compose up -d $name"
  fi
done

# ── 6. Pipeline ─────────────────────────────────────────────────────────────
head2 "Pipeline"
alerts="$(dc_exec postgres psql -U aisoc -d aisoc -tAc 'select count(*) from alerts' | tr -d '[:space:]')"
if [ -n "${alerts:-}" ]; then
  if [ "${alerts:-0}" -gt 0 ] 2>/dev/null; then
    pass "alerts table has ${alerts} row(s)"
  else
    warn "no alerts yet — the pipeline has not produced one" "prove it end to end: make smoke"
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n'
if [ "$FAILURES" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  printf '%sAll checks passed.%s Prove the pipeline with: %smake smoke%s\n\n' "$G$B" "$X" "$B" "$X"
  exit 0
fi
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%d warning(s), no failures.%s AiSOC should work; see the notes above.\n\n' "$Y" "$WARNINGS" "$X"
  exit 0
fi
printf '%s%d check(s) failed%s, %d warning(s).\n' "$R$B" "$FAILURES" "$X" "$WARNINGS"
printf 'Fix the failures above, then re-run: %s./scripts/doctor.sh%s\n\n' "$B" "$X"
exit 1
