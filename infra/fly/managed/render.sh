#!/usr/bin/env bash
#
# render.sh — render every Fly app template against a tenant manifest.
#
# Usage:
#   ./infra/fly/managed/render.sh infra/fly/managed/tenants/acme.yaml [output_dir]
#
# Produces:
#   <output_dir>/api/fly.toml
#   <output_dir>/agents/fly.toml
#   <output_dir>/web/fly.toml
#   <output_dir>/realtime/fly.toml
#
# When output_dir is omitted we render into a per-tenant cache under
# .render-cache/<slug>/. The provisioner script reads from there.
#
# Why a hand-rolled renderer rather than a templating engine: the
# substitution surface is tiny (six placeholders), every Fly-toml line
# stays human-readable in `git diff`, and we get to avoid jinja2 as a
# CI dependency. envsubst is POSIX-portable and ships on every Linux
# runner; on macOS it's part of gettext which `brew install gettext`
# provides.

set -euo pipefail

MANIFEST="${1:?usage: render.sh <tenant-manifest.yaml> [output_dir]}"
OUTPUT_ROOT="${2:-}"

if ! command -v envsubst >/dev/null 2>&1; then
  echo "render.sh: envsubst not found (brew install gettext / apt-get install -y gettext)" >&2
  exit 1
fi

if ! command -v yq >/dev/null 2>&1; then
  echo "render.sh: yq not found (brew install yq / sudo apt-get install -y yq)" >&2
  exit 1
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "render.sh: manifest file not found: $MANIFEST" >&2
  exit 1
fi

# Read tenant fields. yq's `// "default"` operator handles missing keys.
TENANT_SLUG=$(yq -r '.slug' "$MANIFEST")
TENANT_DISPLAY_NAME=$(yq -r '.display_name' "$MANIFEST")
REGION=$(yq -r '.region // "iad"' "$MANIFEST")
BASE_DOMAIN=$(yq -r '.base_domain' "$MANIFEST")
API_VM_SIZE=$(yq -r '.api_vm_size // "shared-cpu-1x"' "$MANIFEST")
AGENTS_VM_SIZE=$(yq -r '.agents_vm_size // "shared-cpu-2x"' "$MANIFEST")
REALTIME_MIN_MACHINES=$(yq -r '.realtime_min_machines // 1' "$MANIFEST")

# Validate slug shape — Fly app names accept [a-z0-9-]{2,32}; if we let
# bad characters through they'd break `flyctl apps create`.
if [[ ! "$TENANT_SLUG" =~ ^[a-z0-9-]{2,32}$ ]]; then
  echo "render.sh: invalid slug '$TENANT_SLUG' (must match [a-z0-9-]{2,32})" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE_DIR="$SCRIPT_DIR/template"

if [[ -z "$OUTPUT_ROOT" ]]; then
  OUTPUT_ROOT="$SCRIPT_DIR/.render-cache/$TENANT_SLUG"
fi
mkdir -p "$OUTPUT_ROOT"/{api,agents,web,realtime}

export TENANT_SLUG TENANT_DISPLAY_NAME REGION BASE_DOMAIN \
       API_VM_SIZE AGENTS_VM_SIZE REALTIME_MIN_MACHINES

for component in api agents web realtime; do
  src="$TEMPLATE_DIR/$component/fly.toml.tpl"
  dst="$OUTPUT_ROOT/$component/fly.toml"
  if [[ ! -f "$src" ]]; then
    echo "render.sh: template missing: $src" >&2
    exit 1
  fi
  envsubst < "$src" > "$dst"
done

echo "$OUTPUT_ROOT"
