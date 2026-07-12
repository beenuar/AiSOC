#!/usr/bin/env bash
# restore.sh — AiSOC full-stack restore from S3/R2
#
# Restores:
#   1. PostgreSQL (download + gunzip + psql)
#   2. ClickHouse (download + gunzip + clickhouse-client INSERT)
#   3. Plugin store (download + extract artifacts)
#
# Required environment variables (same as backup.sh):
#   BACKUP_S3_BUCKET      — s3://your-bucket or r2://your-bucket
#   BACKUP_S3_PREFIX      — key prefix inside bucket
#   POSTGRES_URL          — postgresql://user:pass@host:5432/dbname
#   CLICKHOUSE_HOST       — ClickHouse HTTP endpoint host
#   CLICKHOUSE_PORT       — ClickHouse HTTP port (default: 8123)
#   CLICKHOUSE_USER       — ClickHouse user
#   CLICKHOUSE_PASSWORD   — ClickHouse password
#   CLICKHOUSE_DATABASE   — ClickHouse database to restore
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_ENDPOINT_URL
#
# Usage:
#   ./scripts/restore.sh --timestamp 20260503T120000Z [--component postgres|clickhouse|plugins|all]
#   ./scripts/restore.sh --latest [--component all]
#   ./scripts/restore.sh --list   # show available backups

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
BACKUP_S3_BUCKET="${BACKUP_S3_BUCKET:-}"
BACKUP_S3_PREFIX="${BACKUP_S3_PREFIX:-aisoc-backups}"
POSTGRES_URL="${POSTGRES_URL:-}"
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-aisoc}"
TIMESTAMP=""
COMPONENT="all"
DO_LIST=false
USE_LATEST=false
RESTORE_DIR="/tmp/aisoc-restore-$$"

# ── arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timestamp)  TIMESTAMP="$2"; shift ;;
    --component)  COMPONENT="$2"; shift ;;
    --latest)     USE_LATEST=true ;;
    --list)       DO_LIST=true ;;
    *)            echo "Unknown arg: $1"; exit 1 ;;
  esac
  shift
done

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[$(date -u +%T)] $*"; }

require() {
  command -v "$1" &>/dev/null || { echo "Missing required command: $1" >&2; exit 1; }
}

s3_args() {
  local args=()
  [[ -n "${AWS_ENDPOINT_URL:-}" ]] && args+=(--endpoint-url "$AWS_ENDPOINT_URL")
  echo "${args[@]}"
}

s3_ls() {
  local prefix="$1"
  # shellcheck disable=SC2046
  aws s3 ls $(s3_args) "${prefix}/" 2>/dev/null | awk '{print $4}' | sort
}

s3_download() {
  local src="$1" dest="$2"
  # shellcheck disable=SC2046
  aws s3 cp $(s3_args) "$src" "$dest"
}

# ── list backups ──────────────────────────────────────────────────────────────
list_backups() {
  [[ -z "$BACKUP_S3_BUCKET" ]] && { echo "BACKUP_S3_BUCKET is required" >&2; exit 1; }
  echo "=== Available PostgreSQL backups ==="
  s3_ls "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres" | sed 's/^/  /'
  echo ""
  echo "=== Available ClickHouse backup timestamps (first table) ==="
  # shellcheck disable=SC2046
  aws s3 ls $(s3_args) "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse/" 2>/dev/null \
    | awk '{print $2}' | sed 's|/$||' | head -1 \
    | xargs -I{} aws s3 ls $(s3_args) "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse/{}/" 2>/dev/null \
    | awk '{print $4}' | sed 's/^/  /' || echo "  (none)"
  echo ""
  echo "=== Available plugin store backups ==="
  s3_ls "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins" | sed 's/^/  /'
}

if [[ "$DO_LIST" == "true" ]]; then
  list_backups
  exit 0
fi

# ── resolve timestamp ─────────────────────────────────────────────────────────
resolve_timestamp() {
  if [[ "$USE_LATEST" == "true" ]]; then
    log "Resolving latest backup timestamp…"
    TIMESTAMP=$(s3_ls "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres" \
      | grep -oP '\d{8}T\d{6}Z' | sort | tail -1 || true)
    if [[ -z "$TIMESTAMP" ]]; then
      echo "No postgres backups found to determine latest timestamp" >&2
      exit 1
    fi
    log "Latest timestamp: $TIMESTAMP"
  fi
  if [[ -z "$TIMESTAMP" ]]; then
    echo "--timestamp or --latest is required" >&2
    exit 1
  fi
  # Return explicit success: with the previous `[[ -z … ]] && { … }` form, the
  # test evaluates false (exit 1) once a timestamp is resolved, and as the
  # function's last command that non-zero status propagated out and tripped
  # `set -e` in the caller — aborting every restore before it began.
  return 0
}

# ── pre-flight ─────────────────────────────────────────────────────────────────
require aws
require psql
require gzip
require curl

[[ -z "$BACKUP_S3_BUCKET" ]] && { echo "BACKUP_S3_BUCKET is required" >&2; exit 1; }

resolve_timestamp

mkdir -p "$RESTORE_DIR"
trap 'rm -rf "$RESTORE_DIR"' EXIT

log "=== AiSOC Restore started: timestamp=${TIMESTAMP} ==="
log "Component: ${COMPONENT}"

# ── confirmation prompt ────────────────────────────────────────────────────────
if [[ -t 0 ]]; then
  echo ""
  echo "WARNING: This will OVERWRITE the target database / files."
  read -r -p "Are you sure you want to restore from ${TIMESTAMP}? [yes/N] " confirm
  [[ "$confirm" != "yes" ]] && { log "Restore cancelled."; exit 0; }
fi

# ── 1. PostgreSQL restore ──────────────────────────────────────────────────────
restore_postgres() {
  [[ -z "$POSTGRES_URL" ]] && { echo "POSTGRES_URL is not set; skipping postgres restore" >&2; return; }
  log "--- PostgreSQL restore ---"
  local s3src="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres/postgres-${TIMESTAMP}.sql.gz"
  local local_file="${RESTORE_DIR}/postgres-${TIMESTAMP}.sql.gz"

  log "Downloading $s3src…"
  s3_download "$s3src" "$local_file"
  log "Download complete ($(du -sh "$local_file" | cut -f1))"

  log "Restoring to ${POSTGRES_URL}…"
  gunzip -c "$local_file" | psql "$POSTGRES_URL" --single-transaction
  log "PostgreSQL restore complete"
}

# ── 2. ClickHouse restore ──────────────────────────────────────────────────────
restore_clickhouse() {
  log "--- ClickHouse restore ---"
  local ch_url="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
  local auth_args=()
  [[ -n "$CLICKHOUSE_USER" ]]     && auth_args+=(--user "${CLICKHOUSE_USER}")
  [[ -n "$CLICKHOUSE_PASSWORD" ]] && auth_args+=(--password "${CLICKHOUSE_PASSWORD}")

  # List tables available in this backup
  local ch_s3_prefix="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse"
  # shellcheck disable=SC2046
  local tables
  tables=$(aws s3 ls $(s3_args) "${ch_s3_prefix}/" 2>/dev/null \
    | awk '{print $2}' | sed 's|/$||' || echo "")

  if [[ -z "$tables" ]]; then
    log "No ClickHouse backup directories found; skipping"
    return
  fi

  while IFS= read -r table; do
    [[ -z "$table" ]] && continue
    local s3src="${ch_s3_prefix}/${table}/${table}-${TIMESTAMP}.tsv.gz"
    local local_file="${RESTORE_DIR}/ch-${table}-${TIMESTAMP}.tsv.gz"

    log "  Restoring table: ${CLICKHOUSE_DATABASE}.${table}"
    if ! aws s3 ls $(s3_args) "$s3src" &>/dev/null; then
      log "  Skipping ${table}: file not found at ${s3src}"
      continue
    fi

    s3_download "$s3src" "$local_file"

    gunzip -c "$local_file" | curl -sf "${ch_url}/" \
      ${auth_args[@]+"${auth_args[@]}"} \
      --data-binary @- \
      --get \
      --data-urlencode "query=INSERT INTO ${CLICKHOUSE_DATABASE}.${table} FORMAT TabSeparatedWithNames"

    log "  Table ${table} restored"
  done <<< "$tables"

  log "ClickHouse restore complete"
}

# ── 3. Plugin store restore ─────────────────────────────────────────────────────
restore_plugins() {
  log "--- Plugin store restore ---"
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local s3prefix="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins"
  local outdir="${RESTORE_DIR}/plugins"
  mkdir -p "$outdir"

  # Download marketplace index
  local mkt_src="${s3prefix}/marketplace-index-${TIMESTAMP}.json"
  if aws s3 ls $(s3_args) "$mkt_src" &>/dev/null; then
    s3_download "$mkt_src" "${outdir}/marketplace-index.json"
    cp "${outdir}/marketplace-index.json" "${repo_root}/marketplace/index.json"
    cp "${outdir}/marketplace-index.json" "${repo_root}/apps/web/public/marketplace/index.json"
    log "  Marketplace index restored"
  fi

  # Restore detections archive
  local det_src="${s3prefix}/detections-${TIMESTAMP}.tar.gz"
  if aws s3 ls $(s3_args) "$det_src" &>/dev/null; then
    s3_download "$det_src" "${outdir}/detections.tar.gz"
    log "  Extracting detections archive…"
    tar -xzf "${outdir}/detections.tar.gz" -C "$repo_root"
    log "  Detections restored"
  fi

  # Restore plugin SDK packages
  for pkg in plugin-sdk-go plugin-sdk-py; do
    local pkg_src="${s3prefix}/${pkg}-${TIMESTAMP}.tar.gz"
    if aws s3 ls $(s3_args) "$pkg_src" &>/dev/null; then
      s3_download "$pkg_src" "${outdir}/${pkg}.tar.gz"
      log "  Extracting ${pkg}…"
      tar -xzf "${outdir}/${pkg}.tar.gz" -C "${repo_root}/packages"
      log "  ${pkg} restored"
    fi
  done

  log "Plugin store restore complete"
}

# ── run selected components ───────────────────────────────────────────────────
case "$COMPONENT" in
  postgres)   restore_postgres ;;
  clickhouse) restore_clickhouse ;;
  plugins)    restore_plugins ;;
  all)
    restore_postgres
    restore_clickhouse
    restore_plugins
    ;;
  *)
    echo "Unknown component: $COMPONENT (choose: postgres|clickhouse|plugins|all)" >&2
    exit 1
    ;;
esac

log "=== Restore completed successfully ==="
