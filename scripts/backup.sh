#!/usr/bin/env bash
# backup.sh — AiSOC full-stack backup to S3/R2
#
# Backs up:
#   1. PostgreSQL (pg_dump → gzip → upload)
#   2. ClickHouse (BACKUP TABLE/DATABASE via HTTP API → upload)
#   3. Plugin store (marketplace/index.json + community plugin artifacts → upload)
#
# Required environment variables:
#   BACKUP_S3_BUCKET      — s3://your-bucket or r2://your-bucket (s3-compatible)
#   BACKUP_S3_PREFIX      — key prefix inside bucket, e.g. "aisoc-backups"
#   POSTGRES_URL          — postgresql://user:pass@host:5432/dbname
#   CLICKHOUSE_HOST       — ClickHouse HTTP endpoint host (default: localhost)
#   CLICKHOUSE_PORT       — ClickHouse HTTP port (default: 8123)
#   CLICKHOUSE_USER       — ClickHouse user (default: default)
#   CLICKHOUSE_PASSWORD   — ClickHouse password
#   CLICKHOUSE_DATABASE   — ClickHouse database to back up (default: aisoc)
#   AWS_ACCESS_KEY_ID     — S3/R2 access key
#   AWS_SECRET_ACCESS_KEY — S3/R2 secret key
#   AWS_ENDPOINT_URL      — R2 or custom S3 endpoint (optional)
#   BACKUP_RETENTION_DAYS — how many days to keep backups (default: 30)
#   SLACK_WEBHOOK_URL     — notify on completion/failure (optional)
#
# Usage:
#   ./scripts/backup.sh [--dry-run] [--component postgres|clickhouse|plugins|all]

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
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
DRY_RUN=false
COMPONENT="all"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_DIR="/tmp/aisoc-backup-${TIMESTAMP}"
ERRORS=0

# ── arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=true ;;
    --component)  COMPONENT="$2"; shift ;;
    *)            echo "Unknown arg: $1"; exit 1 ;;
  esac
  shift
done

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[$(date -u +%T)] $*"; }
fail() { echo "[ERROR] $*" >&2; ((ERRORS++)); }

require() {
  command -v "$1" &>/dev/null || { echo "Missing required command: $1" >&2; exit 1; }
}

s3_upload() {
  local src="$1" dest="$2"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would upload $src → $dest"
    return
  fi
  local args=()
  [[ -n "${AWS_ENDPOINT_URL:-}" ]] && args+=(--endpoint-url "$AWS_ENDPOINT_URL")
  aws s3 cp "${args[@]}" "$src" "$dest"
}

s3_delete_old() {
  local prefix="$1"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would prune objects older than ${BACKUP_RETENTION_DAYS}d in $prefix"
    return
  fi
  local args=()
  [[ -n "${AWS_ENDPOINT_URL:-}" ]] && args+=(--endpoint-url "$AWS_ENDPOINT_URL")
  local cutoff
  cutoff=$(date -u -d "${BACKUP_RETENTION_DAYS} days ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
           || date -u -v"-${BACKUP_RETENTION_DAYS}d" +"%Y-%m-%dT%H:%M:%SZ")
  log "Pruning backups older than $cutoff in $prefix"
  aws s3 ls "${args[@]}" "$prefix/" \
    | awk '{print $4}' \
    | while read -r key; do
        local ts
        ts=$(aws s3api head-object "${args[@]}" \
          --bucket "${BACKUP_S3_BUCKET#s3://}" \
          --key "${prefix#"${BACKUP_S3_BUCKET}/"}/${key}" \
          --query 'LastModified' --output text 2>/dev/null || echo "")
        if [[ -n "$ts" ]] && [[ "$ts" < "$cutoff" ]]; then
          aws s3 rm "${args[@]}" "${prefix}/${key}"
          log "Deleted old backup: $key"
        fi
      done
}

notify_slack() {
  local status="$1" message="$2"
  [[ -z "$SLACK_WEBHOOK_URL" ]] && return
  local emoji="✅"
  [[ "$status" != "success" ]] && emoji="🚨"
  curl -s -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"${emoji} AiSOC Backup [${TIMESTAMP}]: ${message}\"}" \
    || true
}

# ── pre-flight ────────────────────────────────────────────────────────────────
require aws
require pg_dump
require gzip
require curl

[[ -z "$BACKUP_S3_BUCKET" ]] && { echo "BACKUP_S3_BUCKET is required" >&2; exit 1; }

mkdir -p "$BACKUP_DIR"
trap 'rm -rf "$BACKUP_DIR"' EXIT

log "=== AiSOC Backup started: ${TIMESTAMP} ==="
log "Component: ${COMPONENT} | Dry-run: ${DRY_RUN}"

# ── 1. PostgreSQL ─────────────────────────────────────────────────────────────
backup_postgres() {
  [[ -z "$POSTGRES_URL" ]] && { fail "POSTGRES_URL is not set; skipping postgres backup"; return; }
  log "--- PostgreSQL backup ---"
  local outfile="${BACKUP_DIR}/postgres-${TIMESTAMP}.sql.gz"
  local s3dest="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres/postgres-${TIMESTAMP}.sql.gz"

  log "Dumping database…"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] pg_dump $POSTGRES_URL | gzip > $outfile"
  else
    pg_dump "$POSTGRES_URL" \
      --format=plain \
      --no-owner \
      --no-acl \
      --verbose \
      2>/dev/null \
      | gzip > "$outfile"
    log "Dump size: $(du -sh "$outfile" | cut -f1)"
  fi

  s3_upload "$outfile" "$s3dest"
  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres"
  log "PostgreSQL backup complete → $s3dest"
}

# ── 2. ClickHouse ─────────────────────────────────────────────────────────────
backup_clickhouse() {
  log "--- ClickHouse backup ---"
  local ch_url="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
  local auth_args=()
  [[ -n "$CLICKHOUSE_USER" ]]     && auth_args+=(--user "${CLICKHOUSE_USER}")
  [[ -n "$CLICKHOUSE_PASSWORD" ]] && auth_args+=(--password "${CLICKHOUSE_PASSWORD}")

  # Get list of tables
  local tables
  tables=$(curl -sf "${ch_url}/?query=SHOW+TABLES+FROM+${CLICKHOUSE_DATABASE}+FORMAT+TabSeparated" \
    ${auth_args[@]+"${auth_args[@]}"} \
    2>/dev/null || echo "")

  if [[ -z "$tables" ]]; then
    fail "Could not connect to ClickHouse at ${ch_url}; skipping"
    return
  fi

  local outdir="${BACKUP_DIR}/clickhouse"
  mkdir -p "$outdir"

  log "Backing up ClickHouse database: ${CLICKHOUSE_DATABASE}"

  while IFS= read -r table; do
    [[ -z "$table" ]] && continue
    local outfile="${outdir}/${table}-${TIMESTAMP}.tsv.gz"
    log "  Exporting table: ${CLICKHOUSE_DATABASE}.${table}"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "  [dry-run] Would export ${table}"
    else
      curl -sf "${ch_url}/?query=SELECT+*+FROM+${CLICKHOUSE_DATABASE}.${table}+FORMAT+TabSeparatedWithNames" \
        ${auth_args[@]+"${auth_args[@]}"} \
        | gzip > "$outfile"
      log "    Size: $(du -sh "$outfile" | cut -f1)"
      s3_upload "$outfile" \
        "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse/${table}/${table}-${TIMESTAMP}.tsv.gz"
    fi
  done <<< "$tables"

  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse"
  log "ClickHouse backup complete"
}

# ── 3. Plugin store ────────────────────────────────────────────────────────────
backup_plugins() {
  log "--- Plugin store backup ---"
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local marketplace_index="${repo_root}/marketplace/index.json"
  local web_marketplace="${repo_root}/apps/web/public/marketplace/index.json"

  local outdir="${BACKUP_DIR}/plugins"
  mkdir -p "$outdir"

  # Copy marketplace indexes
  if [[ -f "$marketplace_index" ]]; then
    cp "$marketplace_index" "${outdir}/marketplace-index-${TIMESTAMP}.json"
  fi
  if [[ -f "$web_marketplace" ]]; then
    cp "$web_marketplace" "${outdir}/web-marketplace-index-${TIMESTAMP}.json"
  fi

  # Archive detections directory
  local detections_dir="${repo_root}/detections"
  if [[ -d "$detections_dir" ]]; then
    log "  Archiving detections…"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "  [dry-run] Would archive $detections_dir"
    else
      tar -czf "${outdir}/detections-${TIMESTAMP}.tar.gz" -C "$repo_root" detections/
    fi
  fi

  # Archive packages/plugin-sdk-*
  for pkg_dir in "${repo_root}"/packages/plugin-sdk-*; do
    [[ -d "$pkg_dir" ]] || continue
    local pkg_name
    pkg_name=$(basename "$pkg_dir")
    log "  Archiving ${pkg_name}…"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "  [dry-run] Would archive $pkg_dir"
    else
      tar -czf "${outdir}/${pkg_name}-${TIMESTAMP}.tar.gz" -C "${repo_root}/packages" "${pkg_name}/"
    fi
  done

  # Upload all artifacts
  for f in "${outdir}"/*; do
    [[ -f "$f" ]] || continue
    s3_upload "$f" \
      "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins/$(basename "$f")"
  done

  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins"
  log "Plugin store backup complete"
}

# ── run selected components ───────────────────────────────────────────────────
case "$COMPONENT" in
  postgres)   backup_postgres ;;
  clickhouse) backup_clickhouse ;;
  plugins)    backup_plugins ;;
  all)
    backup_postgres
    backup_clickhouse
    backup_plugins
    ;;
  *)
    echo "Unknown component: $COMPONENT (choose: postgres|clickhouse|plugins|all)" >&2
    exit 1
    ;;
esac

# ── summary ───────────────────────────────────────────────────────────────────
if [[ "$ERRORS" -eq 0 ]]; then
  log "=== Backup completed successfully ==="
  notify_slack "success" "All components backed up to ${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/${TIMESTAMP}"
  exit 0
else
  log "=== Backup completed with ${ERRORS} error(s) ==="
  notify_slack "failure" "${ERRORS} component(s) failed. Check logs."
  exit 1
fi
