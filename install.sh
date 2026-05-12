#!/usr/bin/env bash
###############################################################################
# AiSOC — One-Click Installer (Linux + macOS)
#
# Goal: take a freshly-imaged machine to a running AiSOC dashboard in your
# browser, with zero assumed prerequisites, in a single command.
#
# What this script does, in order:
#   1.  Detects your OS, distribution, package manager, and architecture.
#   2.  Installs (idempotently) the four prerequisites AiSOC needs:
#         - git
#         - Docker Engine + Docker Compose v2 plugin
#         - Node.js 20 LTS
#         - pnpm 8+ (via corepack)
#   3.  Clones the AiSOC repo (if you ran the script as a one-liner) or
#       reuses it (if you ran ./install.sh from inside a clone).
#   4.  Creates a .env from .env.example so the first boot has sane defaults.
#   5.  Runs `pnpm install` to fetch the orchestrator's Node deps.
#   6.  Hands off to `pnpm aisoc:demo`, which pulls prebuilt images, brings
#       up the slim demo profile, seeds the showcase ransomware case, and
#       opens your browser at the case ledger view.
#
# Usage:
#   One-liner (no clone needed):
#     curl -fsSL https://raw.githubusercontent.com/beenuar/AiSOC/main/install.sh | bash
#
#   From inside a clone:
#     ./install.sh
#
# Flags:
#   --no-install    Skip the dependency-install phase (use what's on PATH).
#   --no-launch     Set everything up but don't run pnpm aisoc:demo at the end.
#   --no-pull       Forwarded to aisoc:demo to skip image pull.
#   --rebuild       Forwarded to aisoc:demo to build images from source.
#   --clone-dir DIR Where to clone the repo when running as a one-liner.
#                   Default: $HOME/aisoc
#   --branch BR     Git branch to clone. Default: main.
#   --help          Show this text and exit.
#
# Exit codes:
#   0  success — demo stack is up and your browser opened
#   1  prerequisite install failed
#   2  Docker daemon refused to come up
#   3  pnpm aisoc:demo failed (stack didn't boot or seed)
#
# Safe to re-run. Each install step checks "is this already present and the
# right version?" before doing anything. If everything's installed and the
# repo is cloned, a re-run completes in roughly the time `pnpm aisoc:demo`
# itself takes (≈ 3.5 minutes on a warm Docker daemon).
#
# Tested on:
#   - Ubuntu 22.04 / 24.04
#   - Debian 12
#   - Fedora 40 / 41
#   - Arch Linux (rolling)
#   - openSUSE Tumbleweed
#   - Alpine 3.20
#   - macOS 13+ (Intel + Apple Silicon)
###############################################################################

set -euo pipefail

# Bash 3.2 compatibility (default on macOS) — no associative arrays, no
# `mapfile`, no `${var,,}`. Stick to POSIX-ish constructs except where we
# explicitly need bash features (set -o pipefail, [[ ]], $'...').

# ─── Colors ──────────────────────────────────────────────────────────────────
# Skip ANSI when stdout isn't a TTY (CI logs, file redirects). Otherwise the
# escape sequences just clutter the output.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

log()    { printf '%s[aisoc]%s %s\n' "$C_DIM" "$C_RESET" "$*"; }
info()   { printf '%s[aisoc]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()     { printf '%s[aisoc]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()   { printf '%s[aisoc]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()    { printf '%s[aisoc]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
section() {
  printf '\n%s%s━━━ %s ━━━%s\n\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"
}

die() { err "$*"; exit 1; }

usage() {
  # Echo the leading comment block (everything between line 2 and the first
  # blank line after the shebang) so --help and the source stay in sync.
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ─── Flag parsing ────────────────────────────────────────────────────────────

NO_INSTALL=0
NO_LAUNCH=0
CLONE_DIR="${HOME}/aisoc"
BRANCH="main"
DEMO_FLAGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --no-install) NO_INSTALL=1 ;;
    --no-launch)  NO_LAUNCH=1 ;;
    --no-pull)    DEMO_FLAGS+=("--no-pull") ;;
    --rebuild)    DEMO_FLAGS+=("--rebuild") ;;
    --clone-dir)  CLONE_DIR="${2:?}"; shift ;;
    --branch)     BRANCH="${2:?}"; shift ;;
    --help|-h)    usage ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
  shift
done

# ─── OS / package-manager detection ──────────────────────────────────────────
# We populate four globals: OS_FAMILY (linux|macos), DISTRO_ID (ubuntu, fedora,
# arch, alpine, suse, …), PKG_MGR (apt|dnf|pacman|zypper|apk|brew), and ARCH
# (amd64|arm64). Every install step keys off these.

OS_FAMILY=""
DISTRO_ID=""
DISTRO_VERSION=""
PKG_MGR=""
ARCH=""

detect_arch() {
  local raw
  raw="$(uname -m)"
  case "$raw" in
    x86_64|amd64)        ARCH="amd64" ;;
    aarch64|arm64)       ARCH="arm64" ;;
    armv7l|armhf)        ARCH="armv7" ;;
    *) die "unsupported CPU architecture: $raw" ;;
  esac
}

detect_os() {
  local uname_s
  uname_s="$(uname -s)"
  case "$uname_s" in
    Linux)
      OS_FAMILY="linux"
      if [ -r /etc/os-release ]; then
        # /etc/os-release exports ID, ID_LIKE, VERSION_ID, etc. as shell vars.
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
      else
        DISTRO_ID="unknown"
      fi
      # Pick the package manager. Order matters — Ubuntu has both apt and
      # snap, Fedora has both dnf and yum, etc. The first hit wins and that's
      # always the canonical PM for the distro.
      if   command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
      elif command -v dnf     >/dev/null 2>&1; then PKG_MGR="dnf"
      elif command -v pacman  >/dev/null 2>&1; then PKG_MGR="pacman"
      elif command -v zypper  >/dev/null 2>&1; then PKG_MGR="zypper"
      elif command -v apk     >/dev/null 2>&1; then PKG_MGR="apk"
      elif command -v yum     >/dev/null 2>&1; then PKG_MGR="yum"
      else die "no supported package manager found (apt/dnf/pacman/zypper/apk/yum)"
      fi
      ;;
    Darwin)
      OS_FAMILY="macos"
      DISTRO_ID="macos"
      DISTRO_VERSION="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
      # On macOS we strongly prefer Homebrew because Docker Desktop and Node
      # both ship as casks/formulas. If brew isn't installed we offer to
      # install it (interactive) — the official install script is the only
      # supported way and it requires user consent for the password prompt.
      if command -v brew >/dev/null 2>&1; then
        PKG_MGR="brew"
      else
        PKG_MGR="brew-missing"
      fi
      ;;
    *)
      die "unsupported OS: $uname_s. This installer supports Linux and macOS. For Windows, use install.ps1."
      ;;
  esac
  detect_arch
  ok "Detected: ${OS_FAMILY} (${DISTRO_ID} ${DISTRO_VERSION}, ${ARCH}, pkg-mgr=${PKG_MGR})"
}

# ─── sudo bootstrap ──────────────────────────────────────────────────────────
# We never assume sudo is allowed. We ask once, up-front, whether we'll need
# it, and cache `sudo -v` so the user only types their password once. On
# systems where the user *is* root (containers, some VPS images), SUDO is
# empty and commands run directly.

SUDO=""
need_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    die "sudo is not installed. Either install sudo, or run this script as root."
  fi
  SUDO="sudo"
  info "This script needs sudo to install system packages (Docker, Node, etc.)."
  info "You'll be prompted for your password once."
  if ! sudo -v; then
    die "sudo authentication failed."
  fi
  # Keep sudo's timestamp fresh in the background so a long install doesn't
  # re-prompt mid-way through.
  ( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
  SUDO_KEEPALIVE_PID=$!
  trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null || true' EXIT
}

# ─── Generic command-version helpers ─────────────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

# Returns 0 if $1's `--version` (or whatever extractor) produces a major
# version >= $2. Tolerates leading "v", build suffixes, etc.
version_at_least() {
  local want_major="$2" version_cmd="${3:-$1 --version}"
  local raw major
  if ! raw="$(eval "$version_cmd" 2>/dev/null | head -n1)"; then
    return 1
  fi
  # Pull the first integer.major.minor we find. Handles "v20.11.1",
  # "go1.21.0", "Docker version 24.0.7, build afdd53b", etc.
  major="$(printf '%s\n' "$raw" | grep -oE '[0-9]+(\.[0-9]+)*' | head -n1 | cut -d. -f1)"
  [ -n "$major" ] && [ "$major" -ge "$want_major" ]
}

# ─── Homebrew bootstrap (macOS only) ─────────────────────────────────────────

ensure_brew() {
  if [ "$PKG_MGR" != "brew-missing" ]; then return 0; fi
  warn "Homebrew is required on macOS but isn't installed."
  info "Installing Homebrew (you'll be prompted for your password)..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
    || die "Homebrew install failed. See https://brew.sh and re-run this script."
  # The brew installer prints a hint about adding brew to PATH but does not
  # do it for you. Apple Silicon brew lives at /opt/homebrew, Intel at /usr/local.
  if   [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -x /usr/local/bin/brew    ]; then eval "$(/usr/local/bin/brew shellenv)"
  fi
  have brew || die "brew installed but not on PATH. Open a new shell and re-run."
  PKG_MGR="brew"
  ok "Homebrew installed: $(brew --version | head -n1)"
}

# ─── Step 1: git ─────────────────────────────────────────────────────────────

ensure_git() {
  if have git; then
    ok "git already installed: $(git --version)"
    return 0
  fi
  info "Installing git via $PKG_MGR..."
  case "$PKG_MGR" in
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y --no-install-recommends git ca-certificates curl ;;
    dnf)    $SUDO dnf install -y git ca-certificates curl ;;
    yum)    $SUDO yum install -y git ca-certificates curl ;;
    pacman) $SUDO pacman -Sy --noconfirm --needed git ca-certificates curl ;;
    zypper) $SUDO zypper -n install git ca-certificates curl ;;
    apk)    $SUDO apk add --no-cache git ca-certificates curl bash ;;
    brew)   brew install git ;;
    *) die "don't know how to install git on PKG_MGR=$PKG_MGR" ;;
  esac
  have git || die "git install reported success but git is still not on PATH."
  ok "git installed: $(git --version)"
}

# ─── Step 2: Docker + Compose v2 ─────────────────────────────────────────────
# Strategy:
#   - macOS: install Docker Desktop via brew cask (interactive — user must
#     launch it once after install and accept the licence). We can't start
#     Docker Desktop headlessly.
#   - Linux: use the official `get.docker.com` convenience script. It handles
#     repo setup for apt/dnf/zypper/apk/pacman, installs docker-ce + the
#     compose plugin, and starts the daemon via systemd where applicable.
#   - We then add the current user to the `docker` group on Linux so they
#     don't need sudo to talk to the daemon. The user will need to log out
#     and back in (or `newgrp docker`) for the group change to take effect —
#     we work around that for the rest of *this* run by using `sg docker -c`
#     when invoking docker.

DOCKER_NEEDS_NEWGRP=0

ensure_docker() {
  # Compose v2 ships as a docker plugin, exposed as `docker compose` (no
  # hyphen). The legacy standalone `docker-compose` binary is v1 and is no
  # longer supported by AiSOC. We only check the v2 path.
  if have docker && docker compose version >/dev/null 2>&1; then
    ok "docker + compose v2 already installed: $(docker --version)"
    ensure_docker_daemon
    return 0
  fi

  if [ "$OS_FAMILY" = "macos" ]; then
    info "Installing Docker Desktop via Homebrew..."
    brew install --cask docker || die "brew install --cask docker failed."
    cat <<EOF

${C_BOLD}${C_YELLOW}Docker Desktop installed but not running.${C_RESET}

Please:
  1. Open Docker Desktop from Applications (or Spotlight: 'Docker').
  2. Accept the licence agreement on first launch.
  3. Wait for the whale icon in the menu bar to stop animating.
  4. Re-run this installer.

EOF
    exit 2
  fi

  # Linux path: official convenience script.
  info "Installing Docker Engine via the official convenience script..."
  info "This adds the Docker apt/dnf/zypper repo and installs docker-ce + compose plugin."
  local script
  script="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$script" \
    || die "couldn't download get.docker.com (check your network)."
  $SUDO sh "$script" \
    || die "Docker install script failed. See output above and report at https://github.com/beenuar/AiSOC/issues."
  rm -f "$script"

  # Add user to docker group so we don't need sudo for `docker` commands.
  if ! id -nG "$(whoami)" | tr ' ' '\n' | grep -qx docker; then
    info "Adding $(whoami) to the docker group..."
    $SUDO usermod -aG docker "$(whoami)" || warn "couldn't add to docker group; you'll need sudo for docker commands."
    DOCKER_NEEDS_NEWGRP=1
  fi

  # Start daemon (systemd on most distros, openrc on Alpine).
  if have systemctl; then
    $SUDO systemctl enable --now docker || warn "couldn't enable+start docker via systemctl."
  elif have rc-service; then
    $SUDO rc-service docker start || warn "couldn't start docker via rc-service."
    $SUDO rc-update add docker default || true
  fi

  have docker || die "docker install reported success but docker is still not on PATH."
  ok "docker installed: $(docker --version)"
  ensure_docker_daemon
}

# Wrapper that runs `docker ...` either directly or via `sg docker -c` so
# the current shell sees the new group membership without requiring logout.
# Both branches take a single shell expression (possibly with redirects), which
# is why we eval rather than exec the array.
docker_cmd() {
  if [ "$DOCKER_NEEDS_NEWGRP" = "1" ] && have sg; then
    sg docker -c "$*"
  else
    # shellcheck disable=SC2294  # intentional: callers pass shell expressions
    eval "$@"
  fi
}

ensure_docker_daemon() {
  # Wait up to 60 s for the daemon to be reachable. On Linux this is mostly
  # instant (we just started it via systemctl). On macOS it's not — Docker
  # Desktop takes 10-30 s to bring up the VM.
  local i=0
  while [ $i -lt 30 ]; do
    if docker_cmd 'docker info >/dev/null 2>&1'; then
      ok "Docker daemon is responsive."
      return 0
    fi
    if [ $i -eq 0 ]; then
      info "Waiting for Docker daemon to come up..."
    fi
    sleep 2
    i=$((i+1))
  done
  err "Docker daemon is not responding after 60 s."
  if [ "$OS_FAMILY" = "macos" ]; then
    err "Open Docker Desktop manually, wait for the whale icon to settle, then re-run."
  else
    err "Try: sudo systemctl status docker  (or)  sudo journalctl -u docker --no-pager | tail -50"
  fi
  exit 2
}

# ─── Step 3: Node.js 20 LTS ──────────────────────────────────────────────────

ensure_node() {
  # We need Node >= 20 because tsx 4 + the workspace's "engines" field both
  # require it. Node 18 reaches LTS end-of-life in April 2025 so we don't
  # support it.
  if version_at_least node 20 "node --version"; then
    ok "node already installed: $(node --version)"
    return 0
  fi
  info "Installing Node.js 20 LTS via $PKG_MGR..."
  case "$PKG_MGR" in
    apt)
      # NodeSource is the upstream-blessed apt repo for current Node releases.
      curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash -
      $SUDO apt-get install -y nodejs
      ;;
    dnf|yum)
      curl -fsSL https://rpm.nodesource.com/setup_20.x | $SUDO bash -
      $SUDO "$PKG_MGR" install -y nodejs
      ;;
    pacman) $SUDO pacman -Sy --noconfirm --needed nodejs npm ;;
    zypper)
      $SUDO zypper -n install -y nodejs20 npm20 \
        || $SUDO zypper -n install -y nodejs npm
      ;;
    apk)    $SUDO apk add --no-cache nodejs npm ;;
    brew)   brew install node@20 && brew link --overwrite --force node@20 ;;
    *) die "don't know how to install Node on PKG_MGR=$PKG_MGR" ;;
  esac
  have node || die "node install reported success but node is still not on PATH."
  if ! version_at_least node 20 "node --version"; then
    warn "Installed Node version ($(node --version)) is older than 20; AiSOC may misbehave."
  else
    ok "node installed: $(node --version)"
  fi
}

# ─── Step 4: pnpm 8+ via corepack ────────────────────────────────────────────

ensure_pnpm() {
  if have pnpm && version_at_least pnpm 8 "pnpm --version"; then
    ok "pnpm already installed: $(pnpm --version)"
    return 0
  fi
  info "Enabling corepack and activating pnpm 8..."
  # corepack ships with Node 16.13+. It manages pnpm/yarn versions per project
  # so we don't have to mess with global npm installs (which always end in
  # tears on multi-version setups).
  $SUDO corepack enable 2>/dev/null || corepack enable || die "corepack enable failed."
  # Pin to the version package.json declares (pnpm@8.15.1). corepack reads
  # the workspace's "packageManager" field on first invocation.
  corepack prepare pnpm@8.15.1 --activate || die "corepack prepare pnpm failed."
  have pnpm || die "pnpm install reported success but pnpm is still not on PATH."
  ok "pnpm installed: $(pnpm --version)"
}

# ─── Step 5: clone or locate the repo ────────────────────────────────────────
# Two run modes:
#   A. The script lives in the repo (./install.sh from a clone). REPO_ROOT
#      is wherever this script sits.
#   B. The script was streamed via curl|bash. There's no repo on disk yet —
#      we need to clone into $CLONE_DIR.
# We tell them apart by checking whether $0 is inside a git working tree
# whose origin matches AiSOC.

REPO_ROOT=""

ensure_repo() {
  local self_dir
  # When piped through bash, $0 is "bash" (or "/usr/bin/bash"), not a path
  # to this script. BASH_SOURCE[0] is empty in that case.
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ "${BASH_SOURCE[0]}" != "bash" ]; then
    self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -d "$self_dir/.git" ] && [ -f "$self_dir/package.json" ]; then
      # Sanity-check it's actually AiSOC and not some other repo that
      # happened to ship an install.sh.
      if grep -q '"name": "aisoc"' "$self_dir/package.json" 2>/dev/null; then
        REPO_ROOT="$self_dir"
        ok "Using existing AiSOC clone at $REPO_ROOT"
        return 0
      fi
    fi
  fi

  # Mode B: clone fresh.
  if [ -d "$CLONE_DIR" ]; then
    if [ -d "$CLONE_DIR/.git" ] && grep -q '"name": "aisoc"' "$CLONE_DIR/package.json" 2>/dev/null; then
      info "Updating existing clone at $CLONE_DIR..."
      ( cd "$CLONE_DIR" && git fetch --quiet origin && git checkout --quiet "$BRANCH" && git pull --ff-only --quiet ) \
        || warn "git pull failed; using whatever's on disk."
      REPO_ROOT="$CLONE_DIR"
      ok "Updated clone at $REPO_ROOT"
      return 0
    fi
    die "$CLONE_DIR exists but isn't an AiSOC clone. Pass --clone-dir to choose a different location, or remove it first."
  fi
  info "Cloning AiSOC into $CLONE_DIR (branch: $BRANCH)..."
  git clone --branch "$BRANCH" --depth 50 https://github.com/beenuar/AiSOC.git "$CLONE_DIR" \
    || die "git clone failed."
  REPO_ROOT="$CLONE_DIR"
  ok "Cloned AiSOC to $REPO_ROOT"
}

# ─── Step 6: .env bootstrap ──────────────────────────────────────────────────

ensure_env_file() {
  # docker-compose.demo.yml hardcodes its own dev passwords (see SECURITY NOTE
  # in that file), so .env isn't actually load-bearing for the demo. But
  # several apps and scripts do read .env, so we make sure it exists with
  # the example defaults to avoid spurious "key not found" warnings.
  if [ -f "$REPO_ROOT/.env" ]; then
    ok ".env already exists at $REPO_ROOT/.env"
    return 0
  fi
  if [ -f "$REPO_ROOT/.env.example" ]; then
    cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
    ok "Created $REPO_ROOT/.env from .env.example"
    info "  (Optional: edit $REPO_ROOT/.env to add your OpenAI/Anthropic API key for richer agent runs.)"
  else
    warn "No .env.example found in repo; skipping .env creation."
  fi
}

# ─── Step 7: pnpm install + handoff to aisoc:demo ────────────────────────────

run_pnpm_install() {
  info "Installing JS workspace deps (pnpm install)..."
  ( cd "$REPO_ROOT" && pnpm install --prefer-offline --no-frozen-lockfile ) \
    || die "pnpm install failed."
  ok "pnpm dependencies installed."
}

run_demo() {
  if [ "$NO_LAUNCH" = "1" ]; then
    info "--no-launch: skipping pnpm aisoc:demo. To start the stack later:"
    info "  cd $REPO_ROOT && pnpm aisoc:demo"
    return 0
  fi
  section "Launching AiSOC demo stack"
  info "Handing off to 'pnpm aisoc:demo' — this will pull images, start the"
  info "stack, seed the showcase ransomware case, and open your browser."
  echo
  # We forward the user's --no-pull / --rebuild flags through to the demo
  # script. Run docker via `sg docker` if the user was just added to the
  # group and hasn't logged out — otherwise pnpm aisoc:demo will explode on
  # its very first `docker compose` call.
  if [ "$DOCKER_NEEDS_NEWGRP" = "1" ] && have sg; then
    sg docker -c "cd '$REPO_ROOT' && pnpm aisoc:demo ${DEMO_FLAGS[*]:-}" \
      || { err "pnpm aisoc:demo exited non-zero."; exit 3; }
  else
    ( cd "$REPO_ROOT" && pnpm aisoc:demo "${DEMO_FLAGS[@]}" ) \
      || { err "pnpm aisoc:demo exited non-zero."; exit 3; }
  fi
}

# ─── Final banner ────────────────────────────────────────────────────────────

print_success() {
  cat <<EOF

${C_BOLD}${C_GREEN}AiSOC is up and running.${C_RESET}

  ${C_BOLD}Web console:${C_RESET}     http://localhost:3000
  ${C_BOLD}Showcase case:${C_RESET}   http://localhost:3000/cases/INC-RT-001?tab=ledger
  ${C_BOLD}API + Swagger:${C_RESET}   http://localhost:8000/docs
  ${C_BOLD}Realtime WS:${C_RESET}     ws://localhost:8086

${C_DIM}Useful commands (run from $REPO_ROOT):${C_RESET}
  pnpm aisoc:doctor                          # health-check the stack
  pnpm aisoc:demo:logs                       # tail logs
  pnpm aisoc:demo:down                       # stop everything and wipe demo data
  ./scripts/install/uninstall.sh             # full uninstall (containers + images + repo)

EOF
  if [ "$DOCKER_NEEDS_NEWGRP" = "1" ]; then
    cat <<EOF
${C_YELLOW}Note:${C_RESET} You were added to the 'docker' group. Open a new terminal session
(or run 'newgrp docker') to use 'docker' commands without sudo.

EOF
  fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  section "AiSOC One-Click Installer"
  detect_os

  if [ "$NO_INSTALL" = "0" ]; then
    section "Installing prerequisites"
    if [ "$OS_FAMILY" = "macos" ]; then
      ensure_brew
    else
      need_sudo
    fi
    ensure_git
    ensure_docker
    ensure_node
    ensure_pnpm
  else
    info "--no-install: skipping prerequisite install. Verifying what's on PATH..."
    have git    || die "git missing (and --no-install was given)"
    have docker || die "docker missing (and --no-install was given)"
    docker compose version >/dev/null 2>&1 || die "docker compose v2 missing (and --no-install was given)"
    have node   || die "node missing (and --no-install was given)"
    have pnpm   || die "pnpm missing (and --no-install was given)"
    ensure_docker_daemon
  fi

  section "Setting up the AiSOC repository"
  ensure_repo
  ensure_env_file
  run_pnpm_install
  run_demo
  print_success
}

main "$@"
