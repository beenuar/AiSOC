#!/usr/bin/env bash
#
# tunnel.sh — bring up a Cloudflare Tunnel for the AiSOC public demo.
#
# What this script does, top to bottom:
#
#   1. Verifies cloudflared is installed and the user has logged in
#      (~/.cloudflared/cert.pem must exist).
#   2. Creates a named tunnel ($TUNNEL_NAME) if it doesn't already exist.
#      If a tunnel with the same name exists, it is reused — the script
#      never deletes or recreates an existing tunnel.
#   3. Renders config.yml.example into ~/.cloudflared/$TUNNEL_NAME.yml,
#      substituting the tunnel UUID, credentials path, and domain.
#   4. Creates / updates DNS routes on the zone for the four hostnames the
#      ingress publishes (apex, api, ws, docs).
#   5. Runs `cloudflared tunnel run` in the foreground. Ctrl+C exits cleanly.
#
# Usage:
#
#   bash infra/cloudflare/tunnel.sh                # default: tryaisoc.com
#   DOMAIN=demo.example.com bash infra/cloudflare/tunnel.sh
#   TUNNEL_NAME=my-aisoc bash infra/cloudflare/tunnel.sh
#
# Env vars (all optional):
#
#   DOMAIN               Apex domain to publish (default: tryaisoc.com)
#   TUNNEL_NAME          Cloudflare Tunnel name (default: aisoc-tryaisoc)
#   SUBDOMAINS           Space-separated subdomains to wire up under DOMAIN
#                        (default: "api ws docs")
#   TUNNEL_ORIGIN_CERT   Path to the Cloudflare origin certificate
#                        (default: ~/.cloudflared/cert.pem). Set this to
#                        keep multiple Cloudflare accounts side-by-side —
#                        e.g. cert.pem for one zone and
#                        cert.tryaisoc.pem for tryaisoc.com.
#   SKIP_DNS=1           Skip the DNS-route step (useful if DNS is already
#                        set or managed outside cloudflared)
#   SKIP_RUN=1           Generate config + DNS but don't run the tunnel
#                        (useful for `cloudflared service install` flows)

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DOMAIN="${DOMAIN:-tryaisoc.com}"
TUNNEL_NAME="${TUNNEL_NAME:-aisoc-tryaisoc}"
SUBDOMAINS="${SUBDOMAINS:-api ws docs}"
CFD_DIR="${CFD_DIR:-$HOME/.cloudflared}"
# TUNNEL_ORIGIN_CERT is a recognised cloudflared env var: it points the binary
# at a non-default cert.pem. We default it to the conventional location so
# users with a single account see no behaviour change, but exporting it lets
# multi-account setups keep their certs separate.
TUNNEL_ORIGIN_CERT="${TUNNEL_ORIGIN_CERT:-$CFD_DIR/cert.pem}"
export TUNNEL_ORIGIN_CERT
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/config.yml.example"
RENDERED_CONFIG="$CFD_DIR/${TUNNEL_NAME}.yml"

# ---------------------------------------------------------------------------
# Pretty logging
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
  C_DIM=$'\033[2m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
else
  C_DIM="" C_GREEN="" C_YELLOW="" C_RED="" C_BOLD="" C_RESET=""
fi

log()    { printf "%s[tunnel]%s %s\n" "$C_DIM" "$C_RESET" "$*"; }
ok()     { printf "%s[tunnel]%s %s%s%s\n" "$C_DIM" "$C_RESET" "$C_GREEN" "$*" "$C_RESET"; }
warn()   { printf "%s[tunnel]%s %s%s%s\n" "$C_DIM" "$C_RESET" "$C_YELLOW" "$*" "$C_RESET"; }
fatal()  { printf "%s[tunnel]%s %s%s%s\n" "$C_DIM" "$C_RESET" "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

command -v cloudflared >/dev/null 2>&1 || fatal \
  "cloudflared is not installed. Install it with 'brew install cloudflared' (macOS) or follow https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/install-and-setup/installation/."

if [ ! -f "$TUNNEL_ORIGIN_CERT" ]; then
  fatal "Missing origin certificate at $TUNNEL_ORIGIN_CERT. Run 'cloudflared tunnel login' to authorise this machine for the $DOMAIN zone, or set TUNNEL_ORIGIN_CERT to point at an existing cert."
fi

if [ ! -f "$TEMPLATE" ]; then
  fatal "Template not found: $TEMPLATE"
fi

mkdir -p "$CFD_DIR"

log "domain        = ${C_BOLD}${DOMAIN}${C_RESET}"
log "tunnel name   = ${C_BOLD}${TUNNEL_NAME}${C_RESET}"
log "subdomains    = ${C_BOLD}${SUBDOMAINS}${C_RESET}"
log "config dir    = ${CFD_DIR}"
log "origin cert   = ${TUNNEL_ORIGIN_CERT}"

# ---------------------------------------------------------------------------
# Step 1 — find or create the tunnel
# ---------------------------------------------------------------------------

# `cloudflared tunnel list` output:
#   ID  NAME  CREATED  CONNECTIONS
TUNNEL_ID="$(cloudflared tunnel list --output json 2>/dev/null \
  | python3 -c "import json,sys
data=json.load(sys.stdin)
for t in data:
    if t.get('name')=='$TUNNEL_NAME':
        print(t['id']); break" || true)"

if [ -z "${TUNNEL_ID:-}" ]; then
  log "creating tunnel '$TUNNEL_NAME'..."
  cloudflared tunnel create "$TUNNEL_NAME" >/dev/null
  TUNNEL_ID="$(cloudflared tunnel list --output json 2>/dev/null \
    | python3 -c "import json,sys
data=json.load(sys.stdin)
for t in data:
    if t.get('name')=='$TUNNEL_NAME':
        print(t['id']); break")"
  ok "created tunnel ${TUNNEL_NAME} (id ${TUNNEL_ID})"
else
  ok "reusing existing tunnel ${TUNNEL_NAME} (id ${TUNNEL_ID})"
fi

CREDENTIALS="$CFD_DIR/${TUNNEL_ID}.json"
if [ ! -f "$CREDENTIALS" ]; then
  fatal "Expected credentials file at $CREDENTIALS but it doesn't exist. Try recreating the tunnel: 'cloudflared tunnel delete $TUNNEL_NAME' then re-run this script."
fi

# ---------------------------------------------------------------------------
# Step 2 — render config.yml from the template
# ---------------------------------------------------------------------------

log "rendering ingress config to ${RENDERED_CONFIG}"

# Use a tempfile so a partial render never lands at the destination.
TMP_CONFIG="$(mktemp)"
trap 'rm -f "$TMP_CONFIG"' EXIT

# Substitute placeholders. We use sed with a delimiter that won't appear in
# the substituted values (| for paths, ~ for the UUID — both safe).
sed \
  -e "s|__TUNNEL_ID__|${TUNNEL_ID}|g" \
  -e "s|__CREDENTIALS__|${CREDENTIALS}|g" \
  -e "s|__DOMAIN__|${DOMAIN}|g" \
  "$TEMPLATE" > "$TMP_CONFIG"

# Validate the rendered yaml by asking cloudflared to parse it.
if ! cloudflared tunnel --config "$TMP_CONFIG" ingress validate >/dev/null 2>&1; then
  warn "rendered config failed cloudflared's ingress validate — dumping to help debug:"
  cat "$TMP_CONFIG" >&2
  fatal "ingress validation failed; aborting before writing $RENDERED_CONFIG"
fi

mv "$TMP_CONFIG" "$RENDERED_CONFIG"
trap - EXIT
ok "config rendered (${TUNNEL_ID} → $DOMAIN)"

# ---------------------------------------------------------------------------
# Step 3 — DNS routes
# ---------------------------------------------------------------------------

if [ "${SKIP_DNS:-0}" = "1" ]; then
  warn "SKIP_DNS=1 — leaving DNS untouched."
else
  log "wiring DNS routes for ${DOMAIN} and subdomains: ${SUBDOMAINS}"

  # cloudflared tunnel route dns is idempotent: if the CNAME already points
  # at this tunnel, it succeeds silently. If it points at *another* tunnel,
  # it fails with a clear error. We treat that as fatal because silently
  # repointing someone else's record would be a footgun.
  #
  # SUBTLE FOOTGUN: if the active cert.pem belongs to a different Cloudflare
  # account/zone than $DOMAIN, cloudflared "succeeds" by creating a CNAME on
  # the *cert's* zone with $DOMAIN as a label — e.g. asked to route
  # tryaisoc.com it will create `tryaisoc.com.intel.nexus`. We detect that
  # pattern explicitly and abort with guidance.
  route_dns() {
    local host="$1"
    local log="/tmp/cfd-route-${TUNNEL_NAME}.log"
    cloudflared tunnel route dns "$TUNNEL_NAME" "$host" >"$log" 2>&1 || true

    # Misroute detection: cloudflared logs lines like
    #   "INF Added CNAME <fqdn> which will route to ..."
    # If <fqdn> doesn't end with the host we asked for, the cert is wrong.
    local added_cname
    added_cname="$(grep -oE 'Added CNAME [^ ]+' "$log" | awk '{print $3}' | head -n1 || true)"
    if [ -n "$added_cname" ] && [ "$added_cname" != "$host" ]; then
      cat "$log" >&2
      fatal "DNS misroute detected for ${host}: cloudflared created '${added_cname}' instead. The active origin certificate at ${TUNNEL_ORIGIN_CERT} is authorised for a *different* Cloudflare zone, not ${DOMAIN}.

To fix:
  1. Back up the current cert if you want to keep it:
       mv ${TUNNEL_ORIGIN_CERT} ${TUNNEL_ORIGIN_CERT}.$(date +%Y%m%d).bak
  2. Log in with the Cloudflare account that owns ${DOMAIN}:
       cloudflared tunnel login
     (this writes a fresh ${TUNNEL_ORIGIN_CERT})
  3. (Optional) save it under a per-account name and export:
       mv ${TUNNEL_ORIGIN_CERT} ${CFD_DIR}/cert.${DOMAIN}.pem
       export TUNNEL_ORIGIN_CERT=${CFD_DIR}/cert.${DOMAIN}.pem
  4. Re-run this script. You may also want to delete the misrouted CNAME
     ('${added_cname}') from the wrong zone in the Cloudflare dashboard."
    fi

    if grep -q "successfully\|already exists\|Added CNAME" "$log"; then
      ok "  $host → $TUNNEL_NAME"
    else
      cat "$log" >&2
      fatal "failed to route DNS for $host (see log above)"
    fi
  }

  route_dns "$DOMAIN"
  for sub in $SUBDOMAINS; do
    route_dns "${sub}.${DOMAIN}"
  done
fi

# ---------------------------------------------------------------------------
# Step 4 — run the tunnel (or stop here if SKIP_RUN=1)
# ---------------------------------------------------------------------------

if [ "${SKIP_RUN:-0}" = "1" ]; then
  ok "SKIP_RUN=1 — config + DNS are ready. Run manually with:"
  log "  cloudflared tunnel --config $RENDERED_CONFIG run"
  exit 0
fi

cat <<EOF

${C_BOLD}AiSOC public demo is now reachable at:${C_RESET}
  • https://${DOMAIN}
  • https://api.${DOMAIN}
  • https://ws.${DOMAIN}
  • https://docs.${DOMAIN}

${C_DIM}Press Ctrl+C to stop the tunnel. The Compose stack will keep running.${C_RESET}

EOF

exec cloudflared tunnel --config "$RENDERED_CONFIG" run
