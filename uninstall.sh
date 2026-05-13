#!/usr/bin/env bash
###############################################################################
# AiSOC — Uninstaller (Linux + macOS)
#
# Tears down whatever ./install.sh + `pnpm aisoc:demo` brought up, in
# decreasing levels of aggressiveness:
#
#   default          Stop the demo stack and delete its named volumes.
#                    (Equivalent to: pnpm aisoc:demo:down)
#   --images         Also remove the ghcr.io/beenuar/aisoc-* container images
#                    pulled by the demo (saves ~ 2-3 GB of disk).
#   --node-modules   Also delete node_modules trees inside the repo (~ 1 GB).
#   --repo           Also delete the AiSOC repo clone itself.
#   --all            Equivalent to --images --node-modules --repo.
#
# What this script DOES NOT do:
#   - Uninstall Docker, Node, pnpm, or git. Those are general-purpose tools
#     you almost certainly want for other projects. If you really want to
#     remove them, use your distro's package manager directly:
#       Ubuntu/Debian:  sudo apt-get remove docker-ce nodejs git
#       Fedora:         sudo dnf remove docker-ce nodejs git
#       Arch:           sudo pacman -R docker nodejs git
#       macOS:          brew uninstall --cask docker; brew uninstall node git
#   - Remove the user from the docker group. Your call.
#   - Touch any other Docker containers, images, or volumes outside the
#     aisoc-demo project. We're surgical here.
#
# Usage:
#   ./uninstall.sh           # stop stack + drop volumes
#   ./uninstall.sh --images  # also remove pulled images
#   ./uninstall.sh --all     # everything except shared deps
#   ./uninstall.sh --help
#
# Exit codes:
#   0  success
#   1  invalid arguments / unexpected error
#   2  not run from inside an AiSOC clone (and --repo wasn't given)
#   3  refused to delete a path for safety reasons (system dir, not an AiSOC
#      clone, etc.) — visible separately so CI scripts don't silently treat
#      a refusal as "all done"
###############################################################################

set -euo pipefail

# Match install.sh's logging style so the two feel like a pair.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

log()    { printf '%s[aisoc]%s %s\n' "$C_DIM"    "$C_RESET" "$*"; }
info()   { printf '%s[aisoc]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()     { printf '%s[aisoc]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn()   { printf '%s[aisoc]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()    { printf '%s[aisoc]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
section() { printf '\n%s%s━━━ %s ━━━%s\n\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }
die()    { err "$*"; exit 1; }

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ─── Flags ───────────────────────────────────────────────────────────────────

REMOVE_IMAGES=0
REMOVE_NODE_MODULES=0
REMOVE_REPO=0
YES=0  # skip confirmation prompts (for CI / scripted use)

# Tracks whether we refused a delete for safety reasons. We don't fail-fast
# on refusals (the user might still want volumes/images cleaned), but we exit
# non-zero at the end so CI scripts notice.
SAFETY_REFUSED=0

while [ $# -gt 0 ]; do
  case "$1" in
    --images)        REMOVE_IMAGES=1 ;;
    --node-modules)  REMOVE_NODE_MODULES=1 ;;
    --repo)          REMOVE_REPO=1 ;;
    --all)           REMOVE_IMAGES=1; REMOVE_NODE_MODULES=1; REMOVE_REPO=1 ;;
    --yes|-y)        YES=1 ;;
    --help|-h)       usage ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
  shift
done

# ─── Locate the repo ─────────────────────────────────────────────────────────
# We must be run from inside an AiSOC clone OR have access to one, since
# `docker compose` needs the compose file to resolve project resources.

REPO_ROOT=""

find_repo() {
  # The uninstaller lives at the repo root, alongside install.sh.
  local self_dir
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$self_dir/docker-compose.demo.yml" ] && grep -q '"name": "aisoc"' "$self_dir/package.json" 2>/dev/null; then
    REPO_ROOT="$self_dir"
    return 0
  fi
  # Fallback: maybe the user ran us from PATH or a copy. Try $HOME/aisoc.
  if [ -d "$HOME/aisoc" ] && [ -f "$HOME/aisoc/docker-compose.demo.yml" ]; then
    REPO_ROOT="$HOME/aisoc"
    return 0
  fi
  # Fallback 2: maybe we're run from the cwd of an aisoc clone.
  if [ -f "$PWD/docker-compose.demo.yml" ] && grep -q '"name": "aisoc"' "$PWD/package.json" 2>/dev/null; then
    REPO_ROOT="$PWD"
    return 0
  fi
  return 1
}

if ! find_repo; then
  if [ "$REMOVE_IMAGES" = "1" ] || [ "$REMOVE_REPO" = "1" ]; then
    # We can still nuke images + repo dir without the compose file. We just
    # can't do a clean `compose down`, so the user might have orphan
    # containers. Warn but proceed.
    warn "Couldn't locate AiSOC clone. Skipping 'compose down' (orphan containers may remain)."
  else
    err "Run this from inside an AiSOC clone, or pass --repo to clean up the cloned repo at \$HOME/aisoc."
    exit 2
  fi
fi

confirm() {
  # Skip confirmation in non-interactive shells or when --yes was passed.
  if [ "$YES" = "1" ] || [ ! -t 0 ]; then return 0; fi
  printf '%s%s%s [y/N]: ' "$C_YELLOW" "$1" "$C_RESET" >&2
  local ans
  read -r ans
  case "$ans" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) info "Skipped."; return 1 ;;
  esac
}

# ─── Step 1: bring the demo stack down ───────────────────────────────────────

stop_demo_stack() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker is not on PATH; skipping compose down."
    return 0
  fi
  if ! docker info >/dev/null 2>&1; then
    warn "docker daemon not reachable; skipping compose down."
    return 0
  fi
  if [ -z "$REPO_ROOT" ]; then return 0; fi

  info "Stopping AiSOC demo stack and removing its volumes..."
  ( cd "$REPO_ROOT" && docker compose -f docker-compose.demo.yml down -v --remove-orphans ) \
    || warn "compose down exited non-zero; some resources may not have been cleaned up."
  ok "Demo stack stopped, named volumes deleted."
}

# ─── Step 2: remove pulled images ────────────────────────────────────────────
# We only target images we know belong to AiSOC, namely ghcr.io/beenuar/aisoc-*.
# We deliberately leave alpine/postgres/redis/kafka/zookeeper images alone —
# they're widely shared with other projects and re-pulling them is cheap.

remove_aisoc_images() {
  if [ "$REMOVE_IMAGES" = "0" ]; then return 0; fi
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    warn "docker unreachable; skipping image removal."
    return 0
  fi
  section "Removing AiSOC container images"
  local images
  images=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^ghcr.io/beenuar/aisoc-' || true)
  if [ -z "$images" ]; then
    info "No ghcr.io/beenuar/aisoc-* images found."
    return 0
  fi
  printf '%s\n' "$images" | sed 's/^/  /'
  if confirm "Remove the images above?"; then
    printf '%s\n' "$images" | xargs -r docker rmi -f || warn "some images couldn't be removed (in use?)"
    ok "Images removed."
  fi
}

# ─── Step 3: node_modules cleanup ────────────────────────────────────────────

remove_node_modules() {
  if [ "$REMOVE_NODE_MODULES" = "0" ]; then return 0; fi
  if [ -z "$REPO_ROOT" ]; then return 0; fi
  section "Removing node_modules"
  # The monorepo has node_modules at the root and also inside each app/package.
  # `pnpm` symlinks aggressively, so a plain `rm -rf node_modules` at the root
  # leaves stragglers in apps/* and packages/*.
  local count
  count=$(find "$REPO_ROOT" -type d -name node_modules -prune 2>/dev/null | wc -l | tr -d ' ')
  info "Found $count node_modules directories under $REPO_ROOT"
  if confirm "Remove them all?"; then
    find "$REPO_ROOT" -type d -name node_modules -prune -exec rm -rf {} + 2>/dev/null || true
    ok "node_modules removed."
  fi
}

# ─── Step 4: blow away the repo clone ────────────────────────────────────────

is_dangerous_path() {
  # Refuse rm -rf on anything that looks like a system directory or the
  # user's home root. This is the "did Steam delete my home directory"
  # safety check — better paranoid than apologetic. We canonicalise via
  # realpath when available so symlinks can't dodge the blacklist.
  local p="$1"
  case "$p" in
    ""|/|/.|/..) return 0 ;;
  esac
  # Block the user's home root, common system dirs, and the FS root.
  local abs="$p"
  if command -v realpath >/dev/null 2>&1; then
    abs="$(realpath "$p" 2>/dev/null || printf '%s' "$p")"
  fi
  case "$abs" in
    /|/bin|/sbin|/usr|/usr/*|/etc|/etc/*|/var|/var/*|/opt|/opt/*) return 0 ;;
    /lib|/lib/*|/lib64|/lib64/*|/boot|/boot/*|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*) return 0 ;;
    /tmp|/private/tmp|"$HOME"|"$HOME/") return 0 ;;
    /Users|/Users/*|/home|/home/*)
      # Allow /home/<user>/something but not /home or /home/<user> itself.
      # Same for /Users.
      local depth
      depth=$(printf '%s' "$abs" | tr -cd '/' | wc -c | tr -d ' ')
      [ "$depth" -le 2 ] && return 0
      ;;
  esac
  return 1
}

remove_repo_clone() {
  if [ "$REMOVE_REPO" = "0" ]; then return 0; fi
  # Two candidate locations: $REPO_ROOT (whatever we found) and the canonical
  # $HOME/aisoc. We prefer $REPO_ROOT but warn if it's not the canonical
  # location (the user may have meant something else).
  local target="${REPO_ROOT:-$HOME/aisoc}"
  if [ ! -d "$target" ]; then
    warn "No repo found at $target; nothing to remove."
    return 0
  fi
  # Final sanity check: the path must look like an AiSOC clone (has the
  # compose file AND a package.json claiming the project name). This stops
  # us from rm -rf'ing some unrelated directory the user happened to put
  # in $HOME/aisoc.
  if [ ! -f "$target/docker-compose.demo.yml" ] || ! grep -q '"name": "aisoc"' "$target/package.json" 2>/dev/null; then
    warn "$target doesn't look like an AiSOC clone (missing compose file or package.json marker)."
    warn "Refusing to delete it — clean it up manually if you really want to."
    SAFETY_REFUSED=1
    return 0
  fi
  if is_dangerous_path "$target"; then
    err "Refusing to delete $target — looks like a system or home root directory."
    err "If you really meant to delete this path, do it by hand."
    SAFETY_REFUSED=1
    return 0
  fi
  section "Removing AiSOC repo"
  warn "About to recursively delete: $target"
  if confirm "Are you absolutely sure?"; then
    # cd somewhere safe before rm -rf'ing — if $REPO_ROOT is the cwd of
    # this shell, deleting it can confuse macOS's filesystem and leave
    # the script unable to print the final banner.
    cd /tmp 2>/dev/null || cd / || true
    rm -rf "$target"
    ok "Repo deleted."
  fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  section "AiSOC Uninstaller"
  stop_demo_stack
  remove_aisoc_images
  remove_node_modules
  remove_repo_clone

  if [ "$SAFETY_REFUSED" = "1" ]; then
    cat <<EOF

${C_YELLOW}AiSOC uninstall finished — but at least one delete was refused for safety.${C_RESET}
${C_YELLOW}See messages above. Exiting with code 3 so CI/scripts notice.${C_RESET}

EOF
  else
    cat <<EOF

${C_GREEN}AiSOC uninstall complete.${C_RESET}

EOF
  fi

  cat <<EOF
${C_DIM}Things this script intentionally did NOT remove:${C_RESET}
  - Docker, Node, pnpm, git (shared dev tools)
  - Your membership in the 'docker' group
  - Other Docker images (postgres, redis, kafka, zookeeper, alpine)
  - Cached pnpm store at ~/.local/share/pnpm/store

${C_DIM}To remove the leftover infrastructure images too:${C_RESET}
  docker image prune -a    # removes ALL dangling+unused images, not just AiSOC's

EOF

  if [ "$SAFETY_REFUSED" = "1" ]; then
    exit 3
  fi
}

main "$@"
