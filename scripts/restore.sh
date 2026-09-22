#!/usr/bin/env bash
# restore.sh — AiSOC full-stack restore from S3/R2
#
# Restores:
#   1. PostgreSQL (download + verify + decrypt + gunzip + psql)
#   2. ClickHouse (download + verify + decrypt + gunzip + HTTP INSERT)
#
# Artifacts written by backup.sh are AES-256-GCM encrypted and recorded in a
# SHA-256 manifest. Restore fetches the manifest first and checks the digest of
# every artifact it downloads against it, then decrypts. A digest mismatch
# aborts: restoring a corrupted dump is worse than not restoring, because it
# looks like it worked.
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
#   BACKUP_ENCRYPTION_KEY / BACKUP_ENCRYPTION_KEY_FILE — the key the backup
#                           was written with (see scripts/backup_crypt.py)
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


# ── manifest verification + decryption ────────────────────────────────────────
# A backup you cannot verify is a backup you are guessing about. fetch_artifact
# is the only download path used below, so no component can skip the check.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_FILE=""

load_manifest() {
  local remote="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/manifests/manifest-${TIMESTAMP}.json"
  MANIFEST_FILE="${RESTORE_DIR}/manifest.json"
  if s3_download "$remote" "$MANIFEST_FILE" 2>/dev/null; then
    log "Manifest loaded: $remote"
  else
    MANIFEST_FILE=""
    log "No manifest at ${remote}."
    log "  This backup predates manifest support, so its integrity cannot be"
    log "  verified. Continuing, but treat the restore as unverified."
  fi
}

manifest_lookup() {
  # artifact name -> "<sha256_ciphertext_or_empty>\t<encrypted:true|false>"
  [[ -z "$MANIFEST_FILE" ]] && { echo -e "\t"; return; }
  python3 - "$MANIFEST_FILE" "$1" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1]))
for a in doc.get("artifacts", []):
    if a["name"] == sys.argv[2]:
        print(f"{a.get('sha256_ciphertext') or ''}\t{'true' if a.get('encrypted') else 'false'}")
        break
else:
    print("\t")
PYEOF
}

fetch_artifact() {
  # Downloads <s3 dir>/<base>[.enc], verifies, decrypts. Echoes the local
  # plaintext path. Prefers the encrypted object when both exist.
  local s3dir="$1" base="$2" dest="$3"
  local remote_enc="${s3dir}/${base}.enc"
  local local_enc="${dest}.enc"

  if aws s3 ls $(s3_args) "$remote_enc" &>/dev/null; then
    s3_download "$remote_enc" "$local_enc"
    verify_artifact "$(basename "$remote_enc")" "$local_enc"
    require python3
    python3 "${SCRIPT_DIR}/backup_crypt.py" decrypt "$local_enc" --output "$dest" >/dev/null || {
      echo "[ERROR] Could not decrypt ${remote_enc}." >&2
      echo "        Check BACKUP_ENCRYPTION_KEY / BACKUP_ENCRYPTION_KEY_FILE matches" >&2
      echo "        the key this backup was written with." >&2
      exit 1
    }
    rm -f "$local_enc"
  else
    s3_download "${s3dir}/${base}" "$dest"
    verify_artifact "$base" "$dest"
  fi
  echo "$dest"
}

verify_artifact() {
  local name="$1" path="$2"
  [[ -z "$MANIFEST_FILE" ]] && return 0
  local expected actual
  expected=$(manifest_lookup "$name" | cut -f1)
  if [[ -z "$expected" ]]; then
    log "  ${name}: not listed in the manifest; integrity unverified"
    return 0
  fi
  actual=$(python3 "${SCRIPT_DIR}/backup_crypt.py" sha256 "$path")
  if [[ "$actual" != "$expected" ]]; then
    echo "[ERROR] Integrity check failed for ${name}." >&2
    echo "        manifest: ${expected}" >&2
    echo "        actual:   ${actual}" >&2
    echo "        Refusing to restore: a corrupted dump restores as if it worked." >&2
    exit 1
  fi
  log "  ${name}: sha256 verified"
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
    # grep -oE, not -oP: BSD grep (macOS) has no -P, and the `|| true` below
    # turned that into the misleading "no postgres backups found" rather than
    # "your grep cannot do this" — on the machine someone is most likely to be
    # running a recovery from.
    local listing
    listing=$(s3_ls "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres" || true)
    TIMESTAMP=$(printf '%s\n' "$listing" \
      | grep -oE '[0-9]{8}T[0-9]{6}Z' | sort | tail -1 || true)
    if [[ -z "$TIMESTAMP" ]]; then
      echo "No postgres backups found to determine latest timestamp." >&2
      echo "  Looked in: ${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres" >&2
      if [[ -n "$listing" ]]; then
        echo "  Objects present but none matched <YYYYMMDD>T<HHMMSS>Z:" >&2
        printf '%s\n' "$listing" | sed 's/^/    /' >&2
      else
        echo "  The prefix is empty or unreadable — check credentials and endpoint." >&2
      fi
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

load_manifest

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
  local s3dir="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres"
  local base="postgres-${TIMESTAMP}.sql.gz"
  local local_file="${RESTORE_DIR}/${base}"

  log "Downloading ${s3dir}/${base}…"
  fetch_artifact "$s3dir" "$base" "$local_file" >/dev/null
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
    local s3dir="${ch_s3_prefix}/${table}"
    local base="${table}-${TIMESTAMP}.tsv.gz"
    local local_file="${RESTORE_DIR}/ch-${base}"

    log "  Restoring table: ${CLICKHOUSE_DATABASE}.${table}"
    # shellcheck disable=SC2046
    if ! aws s3 ls $(s3_args) "${s3dir}/${base}" &>/dev/null \
       && ! aws s3 ls $(s3_args) "${s3dir}/${base}.enc" &>/dev/null; then
      log "  Skipping ${table}: no object at ${s3dir}/${base}[.enc]"
      continue
    fi

    fetch_artifact "$s3dir" "$base" "$local_file" >/dev/null

    # The query goes in the URL and the data goes in the body. The previous
    # form combined --data-binary with --get, which turns the request into a
    # GET and URL-encodes the entire gzipped dump into the query string: every
    # ClickHouse restore failed, and the failure was masked because curl -sf
    # was the last command in a loop body.
    local encoded_query
    encoded_query=$(python3 -c \
      "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))" \
      "INSERT INTO ${CLICKHOUSE_DATABASE}.${table} FORMAT TabSeparatedWithNames")

    if ! gunzip -c "$local_file" | curl -sf -X POST "${ch_url}/?query=${encoded_query}" \
      ${auth_args[@]+"${auth_args[@]}"} \
      --data-binary @-; then
      echo "[ERROR] ClickHouse INSERT failed for table ${table}" >&2
      exit 1
    fi

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
