#!/usr/bin/env bash
#
# Start dockerd inside the devcontainer (issue #716).
#
# `ghcr.io/devcontainers/features/docker-in-docker` does two things, and only
# the first has a Dockerfile equivalent:
#
#   1. installs the Docker binaries — replicated by `apt install docker.io`
#      plus the Compose v2 plugin in ../Dockerfile
#   2. supplies container *runtime* options (`--privileged`, `--init`, a
#      volume at /var/lib/docker) and an entrypoint that launches dockerd
#
# Capabilities are granted at container creation and cannot be self-granted
# from an image, so (2) is impossible to bake in. The devcontainer.json now
# passes the runtime options, and this script is the missing entrypoint. Both
# halves are needed: with the options and no daemon, `docker ps` fails; with
# the daemon and no options, dockerd cannot create its network bridge.
#
# Idempotent — `postStartCommand` runs on every container start, including
# after a Codespace stop/resume, and a second dockerd must not be launched.
set -euo pipefail

readonly SOCKET=/var/run/docker.sock
readonly LOG=/tmp/dockerd.log
# Long enough for a cold overlay2 graph driver on a slow Codespaces disk,
# short enough that a genuinely broken daemon is reported rather than waited
# on forever.
readonly TIMEOUT_SECONDS="${AISOC_DOCKERD_TIMEOUT:-60}"

log() { printf '[start-docker] %s\n' "$1"; }

if docker info >/dev/null 2>&1; then
  log "daemon already reachable"
  exit 0
fi

# A missing socket is the normal first-boot state. A socket that exists but
# does not answer means a previous dockerd died, and leaving the stale file
# in place makes the new one refuse to bind.
if [ -S "$SOCKET" ]; then
  log "removing a stale socket left by a dead daemon"
  sudo rm -f "$SOCKET"
fi

if ! sudo -n true 2>/dev/null; then
  # Worth naming precisely, because the symptom ("docker: command not found"
  # is *not* what happens — the CLI is present and the daemon is not) sends
  # people looking in the wrong place.
  log "ERROR: passwordless sudo is unavailable, so dockerd cannot be started."
  log "       The container also needs --privileged; see .devcontainer/devcontainer.json."
  exit 1
fi

log "starting dockerd (log: $LOG)"
sudo sh -c "nohup dockerd >'$LOG' 2>&1 &"

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
until docker info >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    log "ERROR: dockerd did not become ready within ${TIMEOUT_SECONDS}s."
    log "       Last 40 lines of $LOG:"
    sudo tail -n 40 "$LOG" 2>/dev/null || log "       (no log written — dockerd never started)"
    exit 1
  fi
  sleep 1
done

log "daemon ready after $(( TIMEOUT_SECONDS - (deadline - $(date +%s)) ))s"
