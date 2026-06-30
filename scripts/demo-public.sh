#!/usr/bin/env bash
#
# demo-public.sh — public-facing demo on tryaisoc.com.
#
# Composition of two things that already exist:
#
#   1. `pnpm aisoc:demo --no-open`  — boots the slim demo profile from
#      infra/compose/docker-compose.demo.yml, waits for postgres + api + web, seeds canonical
#      data, kicks off an investigation. Defined in scripts/aisoc-demo.ts.
#
#   2. `infra/cloudflare/tunnel.sh` — creates / reuses the cloudflared tunnel
#      named $TUNNEL_NAME, wires DNS for $DOMAIN + subdomains, and runs
#      cloudflared in the foreground.
#
# When the user Ctrl+C's the tunnel, the Compose stack keeps running. Tear it
# down with `pnpm aisoc:demo:down`.
#
# Usage:
#   bash scripts/demo-public.sh                    # tryaisoc.com
#   DOMAIN=demo.example.com bash scripts/demo-public.sh
#
# All env vars from infra/cloudflare/tunnel.sh are honoured (DOMAIN,
# TUNNEL_NAME, SUBDOMAINS, SKIP_DNS, SKIP_RUN).
#
# Flags forwarded to aisoc:demo:
#   --skip-stack       skip step 1 entirely (the stack is already up)
#   --tag <tag>        passed through to aisoc:demo (sets AISOC_TAG)
#   --no-pull          passed through to aisoc:demo

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_GREEN=$'\033[32m'
  C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
  C_BOLD="" C_DIM="" C_GREEN="" C_RED="" C_YELLOW="" C_RESET=""
fi

SKIP_STACK=0
DEMO_FLAGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-stack)  SKIP_STACK=1; shift ;;
    --tag)         DEMO_FLAGS+=("--tag" "$2"); shift 2 ;;
    --no-pull)     DEMO_FLAGS+=("--no-pull"); shift ;;
    --rebuild)     DEMO_FLAGS+=("--rebuild"); shift ;;
    -h|--help)
      # Print the leading comment block only (everything from the shebang
      # up to the first blank line that follows a `#`-prefixed line).
      awk '
        NR==1 { next }                          # skip shebang
        /^#/ { sub(/^# ?/, ""); print; next }
        { exit }
      ' "$0"
      exit 0
      ;;
    *)
      printf "%sunknown flag:%s %s\n" "$C_RED" "$C_RESET" "$1" >&2
      exit 64
      ;;
  esac
done

DOMAIN="${DOMAIN:-tryaisoc.com}"

printf "%s%s── AiSOC public demo ──%s\n" "$C_BOLD" "$C_GREEN" "$C_RESET"
printf "  domain   : %s%s%s\n" "$C_BOLD" "$DOMAIN" "$C_RESET"
printf "  stack    : infra/compose/docker-compose.demo.yml (read-only profile, prebuilt images)\n"
printf "  tunnel   : cloudflared (outbound only — no inbound ports needed)\n\n"

# ---------------------------------------------------------------------------
# Step 1 — local stack (skippable if it's already up)
# ---------------------------------------------------------------------------

if [ "$SKIP_STACK" = "1" ]; then
  printf "%s[1/2] skipping local stack (--skip-stack)%s\n" "$C_DIM" "$C_RESET"
else
  printf "%s[1/2] starting local stack via aisoc:demo%s\n" "$C_BOLD" "$C_RESET"

  # Prefer pnpm if available, fall back to npx tsx so the script also works in
  # contexts where pnpm isn't installed (e.g. cloud demos that only have node).
  if command -v pnpm >/dev/null 2>&1; then
    pnpm aisoc:demo --no-open "${DEMO_FLAGS[@]}"
  elif command -v npx >/dev/null 2>&1; then
    npx tsx scripts/aisoc-demo.ts --no-open "${DEMO_FLAGS[@]}"
  else
    printf "%sneither pnpm nor npx is available; install Node.js >= 20 and corepack enable%s\n" "$C_RED" "$C_RESET" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2 — cloudflared tunnel (foreground)
# ---------------------------------------------------------------------------

printf "\n%s[2/2] bringing up Cloudflare Tunnel for %s%s%s%s\n" \
  "$C_BOLD" "$C_DIM" "$DOMAIN" "$C_RESET" "$C_RESET"
printf "%s(Ctrl+C exits the tunnel; the local stack keeps running)%s\n\n" \
  "$C_DIM" "$C_RESET"

# Hand off — exec replaces this shell with cloudflared, so signals are clean.
exec env DOMAIN="$DOMAIN" bash "$ROOT/infra/cloudflare/tunnel.sh"
