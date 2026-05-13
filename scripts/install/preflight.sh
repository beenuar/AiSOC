#!/usr/bin/env bash
###############################################################################
# AiSOC — Preflight checks (Linux + macOS).
#
# This is a sourced library, not a standalone script. It's loaded by
# install.sh before any prerequisite work begins, and is also runnable on
# its own via:
#
#   bash scripts/install/preflight.sh
#
# Goal: catch the things that will make `pnpm aisoc:demo` fail four minutes
# from now — *before* we download a gigabyte of Docker images and ask the
# user to type their sudo password.
#
# We check, in order:
#
#   1. CPU architecture (must be amd64 or arm64)
#   2. Total RAM (≥ 4 GB hard fail, ≥ 8 GB recommended)
#   3. Free disk space at the install root and at $HOME/.docker
#      (≥ 10 GB hard fail, ≥ 20 GB recommended)
#   4. Internet reachability (DNS resolves + HTTPS to ghcr.io / github.com)
#   5. Required ports are free, OR already used by an AiSOC container we can
#      reuse — anything else is a conflict the user has to resolve
#   6. No leftover/conflicting AiSOC containers from a previous run that
#      would refuse to start cleanly
#   7. macOS-specific: Docker Desktop is installed *and* has at least 4 GB
#      RAM allocated to the VM (smaller and the api crashes mid-boot)
#
# Each check produces one line of output and one of three states:
#
#   PASS — silently records ok=$ok+1
#   WARN — prints a yellow line, increments warn count, but doesn't fail
#   FAIL — prints a red line, increments fail count
#
# At the end we print a summary. If any FAILs were recorded we exit 1
# *unless* the caller passed AISOC_PREFLIGHT_SOFT=1 (which install.sh sets
# when re-running preflight after a fix, so we don't bail twice).
#
# Exit codes (when run standalone):
#   0  all checks passed
#   1  at least one hard FAIL — installer would not succeed
#   2  preflight itself failed (couldn't gather data)
#
# Reads (no writes):
#   AISOC_PREFLIGHT_SOFT  if set to 1, return non-zero count instead of exit
#   AISOC_REPO_ROOT       if set, used as the install location for disk-space
#                         checks. Otherwise we use $PWD when sourced or
#                         $HOME/aisoc when run standalone.
#   AISOC_SKIP_NETWORK    if 1, skip the connectivity probes (for air-gapped
#                         testing — preflight will WARN, not FAIL).
###############################################################################

# Don't `set -e` because we need to inspect the exit code of each check and
# keep going. The caller (install.sh) sets it; we explicitly disable it on
# entry and restore it at the end so we don't surprise sourced callers.
_AISOC_PREFLIGHT_PREV_E="$(set +o | grep errexit)"
set +e

# ─── Config ──────────────────────────────────────────────────────────────────

# Hard floor / recommended floor for resources. Anything below the hard floor
# is a FAIL; anything between hard and recommended is a WARN. These numbers
# come from running the demo stack repeatedly and watching what actually
# breaks first when the system is starved (api OOM-kills around 3 GB total
# RAM, postgres + opensearch trash the disk below 8 GB free).
readonly _PF_RAM_MIN_MB=4096
readonly _PF_RAM_REC_MB=8192
readonly _PF_DISK_MIN_GB=10
readonly _PF_DISK_REC_GB=20

# Ports the demo stack exposes on the host. We probe each one and (a)
# tolerate it being free, (b) tolerate it being held by an aisoc-* container
# from a previous run, but (c) fail if it's held by anything else. The list
# is kept in lockstep with docker-compose.demo.yml — when a port is added
# there, add it here too.
#
# Using parallel arrays instead of an associative array because macOS still
# ships Bash 3.2 by default and `declare -A` only works in 4+.
readonly _PF_PORT_NUMS=(3000 5432 6379 8000 8001 8086 9092)
readonly _PF_PORT_NAMES=("web console" "postgres" "redis" "api" "agents" "realtime ws" "kafka")

# Hosts we curl during the connectivity probe. We hit specific endpoints
# that we know will return 200 (not just any path on the host), because
# ghcr.io's root replies 404 and would generate false negatives.
#
# - api.github.com/zen: a stable lightweight 200 endpoint, also confirms
#   github.com cert chain
# - ghcr.io/v2/: Docker Registry API root, returns 200 (or 401 with -f off)
# - registry.npmjs.org/: returns the registry status JSON, a 200
readonly _PF_NET_HOSTS=(
  "https://api.github.com/zen"
  "https://ghcr.io/v2/"
  "https://registry.npmjs.org/"
)

# ─── Logging (terminal-aware, mirrors install.sh) ────────────────────────────

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _PF_RED=$'\033[31m'
  _PF_GREEN=$'\033[32m'
  _PF_YELLOW=$'\033[33m'
  _PF_BLUE=$'\033[34m'
  _PF_DIM=$'\033[2m'
  _PF_BOLD=$'\033[1m'
  _PF_RESET=$'\033[0m'
else
  _PF_RED=""; _PF_GREEN=""; _PF_YELLOW=""; _PF_BLUE=""; _PF_DIM=""; _PF_BOLD=""; _PF_RESET=""
fi

_PF_OK=0
_PF_WARN=0
_PF_FAIL=0
_PF_FAIL_HINTS=()

_pf_pass() {
  printf '  %s✓%s %s\n' "$_PF_GREEN" "$_PF_RESET" "$1"
  _PF_OK=$((_PF_OK + 1))
}

_pf_warn() {
  printf '  %s!%s %s\n' "$_PF_YELLOW" "$_PF_RESET" "$1"
  if [ -n "${2:-}" ]; then
    printf '    %shint:%s %s\n' "$_PF_DIM" "$_PF_RESET" "$2"
  fi
  _PF_WARN=$((_PF_WARN + 1))
}

_pf_fail() {
  printf '  %s✗%s %s\n' "$_PF_RED" "$_PF_RESET" "$1"
  if [ -n "${2:-}" ]; then
    printf '    %sfix:%s %s\n' "$_PF_DIM" "$_PF_RESET" "$2"
    _PF_FAIL_HINTS+=("$2")
  fi
  _PF_FAIL=$((_PF_FAIL + 1))
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

_pf_have() { command -v "$1" >/dev/null 2>&1; }

# Print integer MB of RAM. Linux: parse /proc/meminfo. macOS: hw.memsize.
# Falls back to "0" if neither path works (treat as unknown — we'll WARN).
_pf_total_ram_mb() {
  if [ -r /proc/meminfo ]; then
    awk '/^MemTotal:/ { printf "%d\n", $2/1024; exit }' /proc/meminfo
  elif _pf_have sysctl; then
    # hw.memsize is bytes. Divide by 1024^2 for MB.
    sysctl -n hw.memsize 2>/dev/null | awk '{ printf "%d\n", $1/1024/1024 }'
  else
    echo 0
  fi
}

# Print integer GB of free space at the given path (rounded down). Uses
# `df -P -k` because BSD-df and GNU-df disagree on column order without -P.
_pf_free_disk_gb() {
  local path="$1"
  if [ ! -d "$path" ]; then
    # Walk up to the nearest existing parent — `df` won't report on a path
    # that doesn't exist yet, and we frequently pre-check dirs we're about
    # to create.
    while [ -n "$path" ] && [ "$path" != "/" ] && [ ! -d "$path" ]; do
      path="$(dirname "$path")"
    done
  fi
  df -P -k "$path" 2>/dev/null | awk 'NR==2 { printf "%d\n", $4/1024/1024 }'
}

# Returns 0 if a TCP listener is already bound to localhost:$1, else 1.
# We try `lsof` first (universal), `ss` second (modern Linux), then a raw
# /dev/tcp probe as a last-resort. /dev/tcp is bash-only and may be disabled
# on hardened distros, hence the cascade.
_pf_port_listener() {
  local port="$1"
  if _pf_have lsof; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    return 1
  fi
  if _pf_have ss; then
    ss -lnt "sport = :$port" 2>/dev/null | grep -q "LISTEN" && return 0
    return 1
  fi
  if (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# Print the friendly label of whatever process is holding $1, or "" if we
# can't tell. Examples: "docker (aisoc-api-1)", "postgres (system)", "node".
_pf_port_owner() {
  local port="$1" pid cmd container
  if _pf_have lsof; then
    pid="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -n1)"
    if [ -n "$pid" ]; then
      cmd="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '[:space:]')"
      if [ "$cmd" = "com.docker.backend" ] || [ "$cmd" = "com.docker.vmnetd" ] || [ "$cmd" = "docker-pr" ] || [ "$cmd" = "docker-proxy" ]; then
        # Try to find the container that opened this published port.
        if _pf_have docker; then
          container="$(docker ps --filter "publish=$port" --format '{{.Names}}' 2>/dev/null | head -n1)"
          if [ -n "$container" ]; then
            echo "docker container: $container"
            return 0
          fi
        fi
        echo "docker (unknown container)"
        return 0
      fi
      echo "${cmd:-pid $pid}"
      return 0
    fi
  fi
  echo ""
}

# Returns 0 if the given port-owner string indicates an AiSOC container —
# i.e. a previous demo run we can safely reuse / restart. The names come
# from docker-compose.demo.yml + the project's compose project name
# (defaults to the directory name, usually "aisoc").
#
# We can't use ${var,,} (bash 4+) here because macOS still ships bash 3.2
# by default. Pipe through tr instead — works everywhere.
_pf_owner_is_aisoc() {
  local lc
  lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$lc" in
    *aisoc*) return 0 ;;
    *) return 1 ;;
  esac
}

# ─── Checks ──────────────────────────────────────────────────────────────────

_pf_check_arch() {
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64)
      _pf_pass "CPU architecture: $(uname -m)"
      ;;
    armv7*|armv6*|i?86)
      _pf_fail "CPU architecture $(uname -m) is not supported." \
        "AiSOC images are amd64 + arm64 only. 32-bit ARM and i386 won't work."
      ;;
    *)
      _pf_warn "CPU architecture $(uname -m) is unrecognised — proceed at your own risk."
      ;;
  esac
}

_pf_check_ram() {
  local mb
  mb="$(_pf_total_ram_mb)"
  if [ "$mb" = "0" ] || [ -z "$mb" ]; then
    _pf_warn "Couldn't read total system RAM."
    return
  fi
  if [ "$mb" -lt "$_PF_RAM_MIN_MB" ]; then
    _pf_fail "RAM: ${mb} MB total (need ≥ ${_PF_RAM_MIN_MB} MB)." \
      "Add memory or run on a larger machine. The demo stack needs ~3 GB resident."
  elif [ "$mb" -lt "$_PF_RAM_REC_MB" ]; then
    _pf_warn "RAM: ${mb} MB total (recommended ≥ ${_PF_RAM_REC_MB} MB)." \
      "Demo will run but may swap. 8 GB is the sweet spot."
  else
    _pf_pass "RAM: ${mb} MB total"
  fi
}

_pf_check_disk() {
  local install_root="${AISOC_REPO_ROOT:-${PWD:-/}}"
  local install_gb
  install_gb="$(_pf_free_disk_gb "$install_root")"
  if [ -z "$install_gb" ]; then install_gb=0; fi

  if [ "$install_gb" -lt "$_PF_DISK_MIN_GB" ]; then
    _pf_fail "Disk: only ${install_gb} GB free at $install_root (need ≥ ${_PF_DISK_MIN_GB} GB)." \
      "Free up space or pass --clone-dir to point install.sh at a roomier disk."
  elif [ "$install_gb" -lt "$_PF_DISK_REC_GB" ]; then
    _pf_warn "Disk: ${install_gb} GB free at $install_root (recommended ≥ ${_PF_DISK_REC_GB} GB)."
  else
    _pf_pass "Disk: ${install_gb} GB free at $install_root"
  fi

  # Docker writes its image cache to /var/lib/docker on Linux and to
  # ~/Library/Containers/com.docker.docker on macOS. Probe whichever one
  # exists. We need this because /home and /var are often separate
  # filesystems and a "20 GB free in $HOME" check tells us nothing about
  # whether a 4 GB image pull will succeed.
  local docker_root=""
  if [ -d /var/lib/docker ]; then
    docker_root=/var/lib/docker
  elif [ -d "$HOME/Library/Containers/com.docker.docker" ]; then
    docker_root="$HOME/Library/Containers/com.docker.docker"
  fi
  if [ -n "$docker_root" ]; then
    local d_gb
    d_gb="$(_pf_free_disk_gb "$docker_root")"
    if [ -n "$d_gb" ] && [ "$d_gb" -lt "$_PF_DISK_MIN_GB" ]; then
      _pf_fail "Disk: only ${d_gb} GB free at Docker root ($docker_root)." \
        "Run 'docker system prune -af' to reclaim space, or move the Docker root."
    fi
  fi
}

_pf_check_network() {
  if [ "${AISOC_SKIP_NETWORK:-0}" = "1" ]; then
    _pf_warn "Skipping network checks (AISOC_SKIP_NETWORK=1)."
    return
  fi
  if ! _pf_have curl; then
    _pf_warn "curl not installed — skipping connectivity probe (will install in step 1)."
    return
  fi
  local host failed=0 http_code
  for host in "${_PF_NET_HOSTS[@]}"; do
    # -m 6: hard 6 s timeout per host. -s: silent. -L: follow redirects.
    # -o /dev/null: discard body. -w '%{http_code}': print just the status.
    # We treat anything in 2xx/3xx/401 as "host is up" — 401 is GHCR's
    # legitimate "auth required" response, not a connectivity failure.
    http_code="$(curl -s -L -m 6 -o /dev/null -w '%{http_code}' "$host" 2>/dev/null || echo "000")"
    case "$http_code" in
      2*|3*|401|403) continue ;;
      *)
        _pf_warn "Couldn't reach $host (HTTP ${http_code:-no-response})." \
          "If you're behind a corporate proxy, set https_proxy + http_proxy before continuing."
        failed=$((failed + 1))
        ;;
    esac
  done
  if [ "$failed" -eq 0 ]; then
    _pf_pass "Network: github.com, ghcr.io, npmjs.org all reachable"
  fi
}

_pf_check_ports() {
  local i port name owner conflicts=0 reused=0
  for i in "${!_PF_PORT_NUMS[@]}"; do
    port="${_PF_PORT_NUMS[$i]}"
    name="${_PF_PORT_NAMES[$i]}"
    if ! _pf_port_listener "$port"; then
      continue
    fi
    owner="$(_pf_port_owner "$port")"
    if _pf_owner_is_aisoc "$owner"; then
      _pf_warn "Port $port ($name) is held by an existing AiSOC container ($owner)." \
        "We'll reuse it — but if a previous demo crashed, run 'pnpm aisoc:demo:down' first."
      reused=$((reused + 1))
    else
      _pf_fail "Port $port ($name) is in use by ${owner:-an unknown process}." \
        "Stop that process, or set the corresponding *_PORT env var to remap. See docs/QUICK_INSTALL.md#port-conflicts."
      conflicts=$((conflicts + 1))
    fi
  done
  if [ "$conflicts" -eq 0 ] && [ "$reused" -eq 0 ]; then
    _pf_pass "All required ports (${_PF_PORT_NUMS[*]}) are free"
  fi
}

_pf_check_stale_containers() {
  if ! _pf_have docker; then
    return
  fi
  if ! docker info >/dev/null 2>&1; then
    return
  fi
  # Look for stopped/exited aisoc-* containers from a previous failed run.
  # `docker compose up` will sometimes refuse to recreate these depending on
  # the volume state, so we surface them up-front.
  local stale
  stale="$(docker ps -a --filter "name=aisoc-" --filter "status=exited" --format '{{.Names}}' 2>/dev/null | head -5)"
  if [ -n "$stale" ]; then
    _pf_warn "Stale AiSOC containers from a previous run:" \
      "Run 'pnpm aisoc:demo:down' (in the AiSOC clone) to clear them. Listed: $(echo "$stale" | tr '\n' ' ')"
  fi
}

_pf_check_macos_docker() {
  if [ "$(uname -s)" != "Darwin" ]; then return; fi
  if ! _pf_have docker; then return; fi
  # If docker CLI is installed but the daemon isn't reachable, say so
  # *clearly* — we previously printed "Docker Desktop is allocated 0 MB"
  # which sounded like a config problem when actually Docker Desktop just
  # wasn't running. install.sh will boot it on macOS, but the user needs
  # to know that's what's happening.
  if ! docker info >/dev/null 2>&1; then
    _pf_warn "Docker Desktop appears installed but the daemon isn't running." \
      "install.sh will launch it; or open Docker.app yourself and re-run."
    return
  fi
  # Daemon is up — verify it has enough RAM allocated.
  local raw mb
  raw="$(docker info --format '{{json .MemTotal}}' 2>/dev/null)"
  if [ -z "$raw" ] || [ "$raw" = "null" ] || [ "$raw" = "0" ]; then
    # Daemon answered but couldn't tell us its memory budget — odd, skip.
    return
  fi
  # MemTotal is bytes.
  mb=$((raw / 1024 / 1024))
  if [ "$mb" -lt 4000 ]; then
    _pf_fail "Docker Desktop is allocated only ${mb} MB of RAM (need ≥ 4096 MB)." \
      "Open Docker Desktop → Settings → Resources → Memory and bump to at least 4 GB."
  fi
}

# ─── Driver ──────────────────────────────────────────────────────────────────

run_aisoc_preflight() {
  printf '\n%s%sPreflight checks%s\n' "$_PF_BOLD" "$_PF_BLUE" "$_PF_RESET"

  _pf_check_arch
  _pf_check_ram
  _pf_check_disk
  _pf_check_network
  _pf_check_ports
  _pf_check_stale_containers
  _pf_check_macos_docker

  printf '\n  %sSummary:%s %s%d passed%s, %s%d warnings%s, %s%d failures%s\n\n' \
    "$_PF_BOLD" "$_PF_RESET" \
    "$_PF_GREEN" "$_PF_OK" "$_PF_RESET" \
    "$_PF_YELLOW" "$_PF_WARN" "$_PF_RESET" \
    "$_PF_RED" "$_PF_FAIL" "$_PF_RESET"

  if [ "$_PF_FAIL" -gt 0 ]; then
    printf '%s%sPreflight FAILED.%s Address the items above and re-run.\n' \
      "$_PF_BOLD" "$_PF_RED" "$_PF_RESET"
    printf '%sFull troubleshooting:%s docs/QUICK_INSTALL.md#troubleshooting\n\n' \
      "$_PF_DIM" "$_PF_RESET"
    if [ "${AISOC_PREFLIGHT_SOFT:-0}" = "1" ]; then
      return 1
    fi
    exit 1
  fi
  return 0
}

# Run automatically only when invoked as a script, not when sourced.
# BASH_SOURCE[0] == $0 means "called directly".
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  run_aisoc_preflight
  rc=$?
  # Restore the caller's errexit setting before returning.
  eval "$_AISOC_PREFLIGHT_PREV_E"
  exit $rc
fi

# Sourced — restore errexit and let the caller decide when to run.
eval "$_AISOC_PREFLIGHT_PREV_E"
