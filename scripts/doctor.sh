#!/usr/bin/env bash
#
# AiSOC doctor — diagnose a deployment and say what to do next.
#
# Every check answers one question an engineer would actually ask, and a
# failure prints the command that investigates it. The rule here is that a
# check must probe the thing it names: "the container is running" is not
# evidence that the service works, and this script does not report it as such.
#
#   ./scripts/doctor.sh              # diagnose the default (CORE) profile
#   ./scripts/doctor.sh --full       # also check the full-profile stores
#   ./scripts/doctor.sh --quiet      # only print problems
#   ./scripts/doctor.sh --ports-only # just the port check (what `make up` runs first)
#
# Exit code is 0 only when every required check passes.
set -uo pipefail

PROFILE_FULL=0
QUIET=0
PORTS_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --full)  PROFILE_FULL=1 ;;
    --quiet) QUIET=1 ;;
    --ports-only) PORTS_ONLY=1 ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
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

# Docker is not the only host requirement and the other two were undocumented.
# `make smoke` — the README's headline proof — is a Python script run on the
# host, not in a container, and `make up` generates `.env` with another one. An
# operator without python3 gets a traceback from the command the quick start
# tells them to trust.
if have python3; then
  pass "python3 available ($(python3 --version 2>&1 | awk '{print $2}'))"
else
  fail "python3 is not installed — make smoke and make env run on the host" "https://www.python.org/downloads/ (3.9+; CI uses 3.11)"
fi

# Every script under scripts/ has a bash shebang and uses bash-only syntax.
# macOS ships bash 3.2, which is enough for all of them.
if have bash; then
  pass "bash available"
else
  fail "bash is not installed — every script under scripts/ needs it" "install bash from your package manager"
fi

# Skipped under --ports-only: `make up` runs that mode as a pre-flight, and the
# disk probe starts a container. Advisories about free space do not belong in
# the path between typing `make up` and the stack starting.
if [ "$PORTS_ONLY" = "0" ] && docker info >/dev/null 2>&1; then
  # Disk exhaustion inside the Docker VM corrupts Kafka's log dir and the
  # broker then reports healthy while refusing every request. That exact
  # failure cost hours, so it is checked before anything else.
  #
  # The thresholds are measured, not guessed: CORE is 16.5GB of unique image
  # layers plus a 2GB model volume, so 20GB is the floor at which a first
  # `make up` completes with room for Postgres, Kafka and Qdrant to grow.
  avail_raw="$(docker run --rm --entrypoint sh alpine:3 -c 'df -P /' 2>/dev/null | awk 'NR==2{print $4}')"
  if [ -n "${avail_raw:-}" ]; then
    avail_gb=$((avail_raw / 1024 / 1024))
    if [ "$avail_gb" -lt 5 ]; then
      fail "docker has ${avail_gb}GB free — Kafka will corrupt its log dir below ~2GB" "docker system prune -af && docker volume prune -f"
    elif [ "$avail_gb" -lt 20 ]; then
      warn "docker has ${avail_gb}GB free — CORE needs ~20GB (16.5GB of images plus a 2GB model)" "docker system prune -af"
    else
      pass "docker disk space: ${avail_gb}GB free"
    fi
  fi

  # CORE measured 4.84GiB resident with the local model loaded, so 8GB is the
  # floor rather than the old 6: the model is mapped in on first inference and
  # the ollama container grows to roughly the model size while serving.
  mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  mem_gb=$((mem_bytes / 1024 / 1024 / 1024))
  if [ "$mem_gb" -gt 0 ] && [ "$mem_gb" -lt 8 ]; then
    fail "docker has ${mem_gb}GB RAM — CORE needs 8GB (the bundled local model reaches ~3GB while answering), full needs 12GB" "raise the memory limit in Docker Desktop → Settings → Resources"
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

# Names whatever is holding a port. "Something else has it" is only actionable
# if the operator can tell what, so this reports a container name when Docker
# published the port and the listening process otherwise.
port_holder() {
  _ph_port="$1"
  if have docker; then
    _ph_name="$(docker ps --filter "publish=${_ph_port}" --format '{{.Names}}' 2>/dev/null | head -n1)"
    [ -n "${_ph_name:-}" ] && { printf 'container %s' "$_ph_name"; return 0; }
  fi
  if have lsof; then
    _ph_pid="$(lsof -nP -iTCP:"${_ph_port}" -sTCP:LISTEN -t 2>/dev/null | head -n1)"
    if [ -n "${_ph_pid:-}" ]; then
      _ph_cmd="$(ps -o comm= -p "${_ph_pid}" 2>/dev/null | sed 's#.*/##')"
      printf '%s (pid %s)' "${_ph_cmd:-unknown process}" "${_ph_pid}"
      return 0
    fi
  fi
  printf 'an unidentified process'
}

# Prints the host port this deployment's own container publishes for a
# service, or nothing.
#
# The old test was `docker compose ps -q <svc>`, which answers a different
# question: it lists containers in *any* state. A postgres that exited because
# the port was already taken still counted, so the port was reported as ours
# while a foreign process held it — a green tick on the one line that needed to
# be red, and the two remedies are opposites (leave it alone, versus stop the
# other process). Observed against a live stack: an ssh tunnel held 5432, this
# deployment's postgres was published on 55432, and the doctor said
# "port 5432 in use by aisoc postgres".
svc_published_port() {
  [ -n "$COMPOSE" ] || return 1
  _sp_mapped="$($COMPOSE port "$1" "$2" 2>/dev/null | tail -n1)"
  [ -n "${_sp_mapped:-}" ] || return 1
  printf '%s' "${_sp_mapped##*:}"
}

# Base URL for one of this deployment's own services, on whatever host port it
# actually published.
#
# The port section below already derives that from `docker compose port`. The
# service probes did not: they dialled the canonical port, so on a host running
# a second AiSOC project they reported the *other* deployment's health as this
# one's. Observed here — a remapped stack was told "ingest-worker is alive but
# NOT ready, it cannot reach Kafka" while its own /readyz answered 200 with
# kafka reachable, and four services were reported healthy that the probe never
# touched. A diagnostic that names the wrong deployment is worse than a vague
# one: it sends the operator to debug something that is not theirs.
#
# Falls back to the canonical port when compose cannot answer (nothing started
# yet), and an explicit AISOC_*_URL still wins over both.
svc_base_url() { # <service> <container-port> <fallback-url>
  _bu_port="$(svc_published_port "$1" "$2" || true)"
  if [ -n "${_bu_port:-}" ]; then printf 'http://localhost:%s' "$_bu_port"; else printf '%s' "$3"; fi
}

# host-port service container-port
for spec in "5432 postgres 5432" "6379 redis 6379" "9092 kafka 9092" \
            "8000 api 8000" "8081 ingest-worker 8080" "3000 web 3000"; do
  # shellcheck disable=SC2086 # deliberate word splitting of a fixed 3-field spec
  set -- $spec; port="$1"; owner="$2"; cport="$3"
  ours="$(svc_published_port "$owner" "$cport" || true)"

  if [ "${ours:-}" = "$port" ]; then
    pass "port $port in use by aisoc $owner"
  elif [ -n "${ours:-}" ]; then
    # Already remapped. The canonical port being busy is then irrelevant, and
    # failing on it would send the operator to fix something that is working.
    pass "aisoc $owner is published on $ours (not the default $port)"
  elif port_busy "$port"; then
    fail "port $port is held by $(port_holder "$port") — aisoc $owner needs it" \
         "stop it, or change the host port in docker-compose.yml. A docker-compose.override.yml must use 'ports: !override' — a plain override appends and leaves $port published."
  else
    [ "$QUIET" = "1" ] || printf '%s·%s port %s free\n' "$D" "$X" "$port"
  fi
done

if [ "$PORTS_ONLY" = "1" ]; then
  [ "$FAILURES" -eq 0 ] && exit 0
  exit 1
fi

[ -z "$COMPOSE" ] && { printf '\n%sCannot check services without docker compose.%s\n' "$R" "$X"; exit 1; }

# ── 3. Configuration ────────────────────────────────────────────────────────
head2 "Configuration"
if [ -f .env ]; then
  pass ".env present"
  # Delegated to scripts/check_env_placeholders.py rather than grepped here.
  # The grep this replaced was
  #   ^[A-Z_]*(SECRET|PASSWORD|KEY)=(change_me|changeme|)$
  # which matched neither placeholder the repository actually shipped, so the
  # one check built to catch them reported clean on the exact .env that broke
  # the vault. A detector and the file it inspects cannot be two hand-kept
  # lists; tests/test_env_placeholder_gate.py now compares them.
  if have python3; then
    if placeholders="$(python3 scripts/check_env_placeholders.py .env 2>/dev/null)" && [ -z "${placeholders##*OK*}" ]; then
      pass ".env has no placeholder values"
    else
      fail ".env still contains template placeholders:"$'\n'"$(printf '%s\n' "$placeholders" | sed 's/^/    /')" \
           "make env   # generates real values for the secrets that need them"
    fi
  else
    warn "cannot check .env for placeholders: python3 is not installed" "install python3 — make smoke and make env need it too"
  fi
  # A generated secret that is still empty is not fatal (the vault falls back
  # to an ephemeral development key) but it does mean saved connector
  # credentials will not survive a restart, which is worth saying out loud.
  if have python3 && ! python3 scripts/ensure_env.py --check >/dev/null 2>&1; then
    warn ".env has generated secrets that are still unset — connector credentials will not survive a restart" \
         "make env"
  fi
else
  warn ".env not found — compose will fall back to built-in dev defaults" "make env"
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
  # Probed over the published host port, the same way every other HTTP service
  # in this script is checked. The previous spelling shelled into the container
  # and ran `wget`, which answers "is wget installed" as much as "is the store
  # up": the opensearch image ships curl and no wget, and the qdrant image
  # ships neither. Both reported "running but did not answer" while serving
  # 200 on every request — a false alarm on two of the four stores, which is
  # worse than no check, because it teaches the operator to ignore this one.
  store_probe() {
    # $1 service, $2 container port, $3 path. Prints 200 or 000.
    _sb_host_port="$(svc_published_port "$1" "$2" || true)"
    if [ -n "${_sb_host_port:-}" ]; then
      http_ok "http://localhost:${_sb_host_port}$3" 6
      return
    fi
    # Not published on the host (a compose override may have dropped the
    # mapping). Fall back to whichever client the image actually has.
    dc_exec "$1" sh -c "
      if command -v curl >/dev/null 2>&1; then
        curl -fsS -m 3 -o /dev/null http://localhost:$2$3 && echo 200 || echo 000
      elif command -v wget >/dev/null 2>&1; then
        wget -qO- -T 3 http://localhost:$2$3 >/dev/null 2>&1 && echo 200 || echo 000
      else
        echo noclient
      fi" || echo 000
  }

  for spec in "clickhouse 8123 /ping" "neo4j 7474 /" "qdrant 6333 /readyz" "opensearch 9200 /"; do
    set -- $spec; name="$1"; port="$2"; path="$3"
    if svc_running "$name"; then
      code="$(store_probe "$name" "$port" "$path")"
      case "$code" in
        200) pass "$name responding on $port" ;;
        noclient)
          warn "$name could not be probed: no host port published and the image has no curl or wget" \
               "publish the port, or check it by hand: docker compose logs $name | tail -20" ;;
        *)   warn "$name is running but did not answer http://localhost:${port}${path}" \
                  "docker compose logs $name | tail -20" ;;
      esac
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

API_BASE="${AISOC_API_URL:-$(svc_base_url api 8000 http://localhost:8000)}"
INGEST_BASE="${AISOC_INGEST_URL:-$(svc_base_url ingest-worker 8080 http://localhost:8081)}"

check_http_service api           "${API_BASE}/health"    "docker compose logs api | tail -40"
check_http_service ingest-worker "${INGEST_BASE}/health" "docker compose logs ingest-worker | tail -40"

# Liveness says the process is up. Readiness says it can do its job. For
# ingest the difference is Kafka: without it every accepted event is dropped
# while /health keeps answering 200.
if svc_running ingest-worker; then
  ready_code="$(http_ok "${INGEST_BASE}/readyz" 8)"
  case "$ready_code" in
    200) pass "ingest-worker ready (kafka reachable)" ;;
    503) fail "ingest-worker is alive but NOT ready — it cannot reach Kafka, so ingested events are dropped" "curl -s ${INGEST_BASE}/readyz   # prints the reason" ;;
    404) warn "ingest-worker has no /readyz — running an image older than v8.2" "docker compose build ingest-worker && docker compose up -d ingest-worker" ;;
    *)   warn "ingest-worker /readyz returned $ready_code" "docker compose logs ingest-worker | tail -30" ;;
  esac
fi

# Fusion has no HTTP health route in every build, so it is checked by whether
# its consumer actually joined the group — the thing that matters.
if svc_running fusion; then
  # Probe the service rather than grepping its log. A log line scrolls out of
  # retention and a restart loses it, so log-grep reported a working fusion as
  # broken. The HTTP probe answers the same question durably.
  fusion_code="$(http_ok "${AISOC_FUSION_URL:-$(svc_base_url fusion 8003 http://localhost:8003)}/health" 6)"
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

# host-port service container-port path. The container port is what
# `docker compose port` is keyed on, and it differs from the host port for
# realtime (4000) and agents (8084) — reading the host port for both is how
# these three ended up probing another project's containers.
for spec in "3000 web 3000 /" "8086 realtime 4000 /health" "8001 agents 8084 /health"; do
  # shellcheck disable=SC2086 # deliberate word splitting of a fixed 4-field spec
  set -- $spec; port="$1"; name="$2"; cport="$3"; path="$4"
  if svc_running "$name"; then
    base="$(svc_base_url "$name" "$cport" "http://localhost:${port}")"
    code="$(http_ok "${base}${path}" 6)"
    if [ "$code" = "200" ] || [ "$code" = "204" ]; then pass "$name healthy"
    else warn "$name is running but ${base}${path} returned $code" "docker compose logs $name | tail -30"; fi
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
