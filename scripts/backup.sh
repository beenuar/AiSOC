#!/usr/bin/env bash
# backup.sh — AiSOC full-stack backup to S3/R2
#
# Backs up:
#   1. PostgreSQL (pg_dump → gzip → encrypt → upload)
#   2. ClickHouse (SELECT … FORMAT TSV → gzip → encrypt → upload)
#   3. Plugin store (marketplace/index.json + community plugin artifacts → upload)
#   4. Neo4j entity graph (APOC cypher export → gzip → encrypt → upload)
#   5. Qdrant vector store (per-collection snapshot → encrypt → upload)
#   6. Redis (RDB → encrypt → upload)
#
# Every artifact is encrypted with AES-256-GCM before it leaves the host, and
# every artifact is recorded in a SHA-256 manifest uploaded alongside it. The
# manifest holds the digest of the plaintext and of the ciphertext, so restore
# can prove the bytes it fetched are the bytes that were written *and* that the
# dump inside them is the dump that was taken.
#
# Encryption is on by default. Set BACKUP_ENCRYPTION=off only if the bucket
# provides equivalent protection and you accept that anyone who can read the
# bucket can read every credential and event row in the dump.
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
#   BACKUP_ENCRYPTION_KEY — 64 hex chars (32 bytes) for AES-256-GCM; or
#   BACKUP_ENCRYPTION_KEY_FILE — path to a file containing the same
#                           (preferred: an env var shows up in `ps`)
#                           Generate: python3 scripts/backup_crypt.py keygen
#   BACKUP_ENCRYPTION     — 'on' (default) or 'off' to skip encryption
#   BACKUP_RETENTION_DAYS — how many days to keep backups (default: 30)
#   SLACK_WEBHOOK_URL     — notify on completion/failure (optional)
#
# Usage:
#   ./scripts/backup.sh [--dry-run]
#     [--component postgres|clickhouse|plugins|neo4j|qdrant|redis|all]

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
BACKUP_ENCRYPTION="${BACKUP_ENCRYPTION:-on}"
NEO4J_URI="${NEO4J_URI:-}"
NEO4J_HTTP_URL="${NEO4J_HTTP_URL:-http://localhost:7474}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-}"
QDRANT_URL="${QDRANT_URL:-}"
REDIS_URL="${REDIS_URL:-}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
DRY_RUN=false
COMPONENT="all"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_DIR="/tmp/aisoc-backup-${TIMESTAMP}"
ERRORS=0
SKIPS=0
MANIFEST=""          # set after BACKUP_DIR exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
# NB: ERRORS=$((...)) not ((ERRORS++)). The latter evaluates to the value
# *before* the increment, so the first call returns 0 -> exit status 1 ->
# set -e kills the script mid-handler. The whole error-accumulation design
# below (keep going, report N failures at the end) never ran because of it.
fail() { echo "[ERROR] $*" >&2; ERRORS=$((ERRORS + 1)); }

# unreachable() is fail() for live runs and a note for dry runs. A dry run
# is a configuration check — an operator validating settings from a laptop
# cannot reach the cluster's ClickHouse, and exiting 1 for that made
# --dry-run useless for the thing it exists to do. A live run still treats
# an unreachable store as a failed backup, which it is.
unreachable() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[skip] $*" >&2
    SKIPS=$((SKIPS + 1))
  else
    fail "$*"
  fi
}

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
  local prefix="[ok]"
  [[ "$status" != "success" ]] && prefix="[FAIL]"
  curl -s -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"${prefix} AiSOC Backup [${TIMESTAMP}]: ${message}\"}" \
    || true
}


# ── artifact sealing: encrypt + record ────────────────────────────────────────
# Everything that gets uploaded goes through seal_artifact first, so a new
# component cannot be added that quietly ships plaintext.

manifest_add() {
  # path, plaintext sha256, ciphertext sha256 (empty when unencrypted), bytes
  local name="$1" plain_sha="$2" cipher_sha="$3" bytes="$4"
  python3 - "$MANIFEST" "$name" "$plain_sha" "$cipher_sha" "$bytes" <<'PYEOF'
import json, pathlib, sys
path, name, plain_sha, cipher_sha, size = sys.argv[1:6]
p = pathlib.Path(path)
doc = json.loads(p.read_text()) if p.exists() else {"artifacts": []}
doc["artifacts"].append({
    "name": name,
    "sha256_plaintext": plain_sha,
    "sha256_ciphertext": cipher_sha or None,
    "encrypted": bool(cipher_sha),
    "bytes": int(size),
})
p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PYEOF
}

seal_artifact() {
  # Encrypts $1 in place (producing $1.enc) when enabled, records the digests,
  # and echoes the path that should actually be uploaded.
  local src="$1"
  local plain_sha cipher_sha out

  plain_sha=$(python3 "${SCRIPT_DIR}/backup_crypt.py" sha256 "$src")

  if [[ "$BACKUP_ENCRYPTION" == "off" ]]; then
    manifest_add "$(basename "$src")" "$plain_sha" "" "$(wc -c < "$src")"
    echo "$src"
    return
  fi

  out="${src}.enc"
  # backup_crypt prints "<plain>\t<cipher>\t<path>"
  cipher_sha=$(python3 "${SCRIPT_DIR}/backup_crypt.py" encrypt "$src" --output "$out" | cut -f2)
  rm -f "$src"
  manifest_add "$(basename "$out")" "$plain_sha" "$cipher_sha" "$(wc -c < "$out")"
  echo "$out"
}

upload_sealed() {
  # seal then upload, keeping the .enc suffix on the remote key
  local src="$1" dest_dir="$2"
  local sealed
  sealed=$(seal_artifact "$src")
  s3_upload "$sealed" "${dest_dir}/$(basename "$sealed")"
}

# ── pre-flight ────────────────────────────────────────────────────────────────
require aws
require pg_dump
require gzip
require curl

[[ -z "$BACKUP_S3_BUCKET" ]] && { echo "BACKUP_S3_BUCKET is required" >&2; exit 1; }

# Fail before dumping anything rather than after, so an operator who has not
# set a key does not discover it once the dump is already on disk.
if [[ "$BACKUP_ENCRYPTION" != "off" ]]; then
  require python3
  if ! python3 "${SCRIPT_DIR}/backup_crypt.py" keygen >/dev/null 2>&1; then
    echo "The 'cryptography' package is required for backup encryption." >&2
    echo "Install it, or set BACKUP_ENCRYPTION=off to accept plaintext backups." >&2
    exit 1
  fi
  if [[ -z "${BACKUP_ENCRYPTION_KEY:-}${BACKUP_ENCRYPTION_KEY_FILE:-}" ]]; then
    echo "BACKUP_ENCRYPTION is on but no key is set." >&2
    echo "  Generate one:  python3 scripts/backup_crypt.py keygen" >&2
    echo "  Then set BACKUP_ENCRYPTION_KEY_FILE (preferred) or BACKUP_ENCRYPTION_KEY." >&2
    echo "  To back up without encryption, set BACKUP_ENCRYPTION=off explicitly." >&2
    exit 1
  fi
fi

mkdir -p "$BACKUP_DIR"
MANIFEST="${BACKUP_DIR}/manifest-${TIMESTAMP}.json"
trap 'rm -rf "$BACKUP_DIR"' EXIT

log "=== AiSOC Backup started: ${TIMESTAMP} ==="
log "Component: ${COMPONENT} | Dry-run: ${DRY_RUN}"

# ── 1. PostgreSQL ─────────────────────────────────────────────────────────────
backup_postgres() {
  [[ -z "$POSTGRES_URL" ]] && { unreachable "POSTGRES_URL is not set"; return; }
  log "--- PostgreSQL backup ---"
  local outfile="${BACKUP_DIR}/postgres-${TIMESTAMP}.sql.gz"
  local s3dest="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres/postgres-${TIMESTAMP}.sql.gz"
  # NB: when encryption is on the uploaded key gains a .enc suffix.

  log "Dumping database…"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] pg_dump $POSTGRES_URL | gzip > $outfile"
  else
    # pg_dump's stderr carries --verbose progress *and* the reason for any
    # failure. Discarding it meant a failed backup exited non-zero with no
    # explanation at all — including the common case of a pg_dump older than
    # the server, which aborts before writing a byte. Keep it, and surface it
    # on failure.
    local dump_log="${BACKUP_DIR}/pg_dump.stderr"
    if ! pg_dump "$POSTGRES_URL" \
      --format=plain \
      --no-owner \
      --no-acl \
      --verbose \
      2>"$dump_log" \
      | gzip > "$outfile"; then
      fail "pg_dump failed:"
      sed 's/^/        /' "$dump_log" >&2
      return
    fi
    if [[ ! -s "$outfile" ]]; then
      fail "pg_dump produced an empty archive; refusing to upload it."
      sed 's/^/        /' "$dump_log" >&2
      return
    fi
    log "Dump size: $(du -sh "$outfile" | cut -f1)"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    s3_upload "$outfile" "$s3dest"
  else
    upload_sealed "$outfile" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres"
  fi
  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/postgres"
  log "PostgreSQL backup complete → ${s3dest}${BACKUP_ENCRYPTION:+.enc}"
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
    unreachable "Could not connect to ClickHouse at ${ch_url}"
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
      upload_sealed "$outfile" \
        "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/clickhouse/${table}"
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
    if [[ "$DRY_RUN" == "true" ]]; then
      s3_upload "$f" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins/$(basename "$f")"
    else
      upload_sealed "$f" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins"
    fi
  done

  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/plugins"
  log "Plugin store backup complete"
}


# ── 4. Neo4j (entity graph) ───────────────────────────────────────────────────
# The graph is not derivable from the lake: it carries relationships built at
# ingest time and enriched since, so losing it loses the blast-radius and
# attack-path surfaces even with every raw event intact.
#
# Exported as Cypher via APOC rather than neo4j-admin dump, because a dump
# needs the database stopped or an enterprise online-backup licence, and an
# export runs against a live community instance over HTTP.
backup_neo4j() {
  [[ -z "$NEO4J_URI" ]] && { log "NEO4J_URI not set; skipping Neo4j backup"; return; }
  log "--- Neo4j backup ---"
  local outfile="${BACKUP_DIR}/neo4j-${TIMESTAMP}.cypher.gz"

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would export the graph from ${NEO4J_URI}"
    return
  fi

  local auth=""
  [[ -n "$NEO4J_USER" ]] && auth="-u ${NEO4J_USER}:${NEO4J_PASSWORD}"

  # apoc.export.cypher.all with stream:true returns the script in the
  # response rather than writing to the server's import directory, which
  # we have no way to read from here.
  local query
  query=$(cat <<'CYPHER'
{"statements":[{"statement":"CALL apoc.export.cypher.all(null, {stream:true, format:'cypher-shell', useOptimizations:{type:'UNWIND_BATCH', unwindBatchSize:1000}}) YIELD cypherStatements RETURN cypherStatements"}]}
CYPHER
)
  # shellcheck disable=SC2086
  if ! curl -sf $auth -H 'Content-Type: application/json' \
       -d "$query" "${NEO4J_HTTP_URL}/db/neo4j/tx/commit" \
       | python3 -c "
import json, sys
doc = json.load(sys.stdin)
if doc.get('errors'):
    sys.stderr.write(json.dumps(doc['errors']) + '\n')
    raise SystemExit(1)
for result in doc.get('results', []):
    for row in result.get('data', []):
        for value in row.get('row', []):
            if value:
                sys.stdout.write(value)
" | gzip > "$outfile"; then
    fail "Neo4j export failed. APOC must be installed (apoc.export.cypher.all) and"
    echo "        apoc.export.file.enabled / apoc.import.file.enabled configured." >&2
    return
  fi

  if [[ ! -s "$outfile" ]]; then
    fail "Neo4j export produced an empty file; refusing to upload it."
    return
  fi

  log "Graph export size: $(du -sh "$outfile" | cut -f1)"
  upload_sealed "$outfile" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/neo4j"
  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/neo4j"
  log "Neo4j backup complete"
}

# ── 5. Qdrant (vector store) ──────────────────────────────────────────────────
# Embeddings are expensive to recompute and, for tenant-private case vectors,
# not always recomputable — the source case may have been purged by retention.
backup_qdrant() {
  [[ -z "$QDRANT_URL" ]] && { log "QDRANT_URL not set; skipping Qdrant backup"; return; }
  log "--- Qdrant backup ---"

  local collections
  collections=$(curl -sf "${QDRANT_URL}/collections" 2>/dev/null \
    | python3 -c "
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for c in doc.get('result', {}).get('collections', []):
    print(c['name'])
" || echo "")

  if [[ -z "$collections" ]]; then
    unreachable "Could not list Qdrant collections at ${QDRANT_URL}"
    return
  fi

  while IFS= read -r collection; do
    [[ -z "$collection" ]] && continue
    log "  Snapshotting collection: ${collection}"
    if [[ "$DRY_RUN" == "true" ]]; then
      log "  [dry-run] Would snapshot ${collection}"
      continue
    fi

    # Qdrant creates the snapshot server-side, then we stream it out.
    local snapshot_name
    snapshot_name=$(curl -sf -X POST "${QDRANT_URL}/collections/${collection}/snapshots" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['name'])" 2>/dev/null || echo "")
    if [[ -z "$snapshot_name" ]]; then
      fail "  Snapshot request failed for ${collection}"
      continue
    fi

    local outfile="${BACKUP_DIR}/qdrant-${collection}-${TIMESTAMP}.snapshot"
    if ! curl -sf -o "$outfile" \
         "${QDRANT_URL}/collections/${collection}/snapshots/${snapshot_name}"; then
      fail "  Snapshot download failed for ${collection}"
      continue
    fi

    # Server-side snapshots accumulate and fill the volume otherwise.
    curl -sf -X DELETE \
      "${QDRANT_URL}/collections/${collection}/snapshots/${snapshot_name}" >/dev/null || true

    log "    Size: $(du -sh "$outfile" | cut -f1)"
    upload_sealed "$outfile" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/qdrant/${collection}"
  done <<< "$collections"

  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/qdrant"
  log "Qdrant backup complete"
}

# ── 6. Redis ──────────────────────────────────────────────────────────────────
# Mostly cache, and mostly reconstructible — but it also holds scheduler leases
# and rate-limiter state, and an RDB is cheap. Backed up so a restore does not
# silently start with every scheduled job appearing due at once.
backup_redis() {
  [[ -z "$REDIS_URL" ]] && { log "REDIS_URL not set; skipping Redis backup"; return; }
  if ! command -v redis-cli &>/dev/null; then
    log "redis-cli not installed; skipping Redis backup"
    return
  fi
  log "--- Redis backup ---"
  local outfile="${BACKUP_DIR}/redis-${TIMESTAMP}.rdb"

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would run --rdb against ${REDIS_URL}"
    return
  fi

  if ! redis-cli -u "$REDIS_URL" --rdb "$outfile" >/dev/null 2>&1; then
    fail "redis-cli --rdb failed (BGSAVE may be disabled on a managed instance)"
    return
  fi
  if [[ ! -s "$outfile" ]]; then
    fail "Redis dump is empty; refusing to upload it."
    return
  fi

  log "RDB size: $(du -sh "$outfile" | cut -f1)"
  upload_sealed "$outfile" "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/redis"
  s3_delete_old "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/redis"
  log "Redis backup complete"
}

# ── run selected components ───────────────────────────────────────────────────
case "$COMPONENT" in
  postgres)   backup_postgres ;;
  clickhouse) backup_clickhouse ;;
  plugins)    backup_plugins ;;
  neo4j)      backup_neo4j ;;
  qdrant)     backup_qdrant ;;
  redis)      backup_redis ;;
  all)
    backup_postgres
    backup_clickhouse
    backup_plugins
    backup_neo4j
    backup_qdrant
    backup_redis
    ;;
  *)
    echo "Unknown component: $COMPONENT" >&2
    echo "  choose: postgres|clickhouse|plugins|neo4j|qdrant|redis|all" >&2
    exit 1
    ;;
esac

# ── manifest ──────────────────────────────────────────────────────────────────
# Uploaded last and deliberately unencrypted: it carries digests, not data, and
# restore needs to read it before it has proved it holds the right key.
if [[ "$DRY_RUN" != "true" ]] && [[ -f "$MANIFEST" ]]; then
  python3 - "$MANIFEST" "$TIMESTAMP" "$BACKUP_ENCRYPTION" <<'PYEOF'
import json, pathlib, sys
path, ts, enc = sys.argv[1:4]
p = pathlib.Path(path)
doc = json.loads(p.read_text())
doc["timestamp"] = ts
doc["encryption"] = "aes-256-gcm" if enc != "off" else "none"
doc["format_version"] = 1
p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PYEOF
  s3_upload "$MANIFEST" \
    "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/manifests/manifest-${TIMESTAMP}.json"
  log "Manifest uploaded ($(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['artifacts']))" "$MANIFEST") artifacts)"
fi

# ── summary ───────────────────────────────────────────────────────────────────
if [[ "$ERRORS" -eq 0 ]]; then
  if [[ "$SKIPS" -gt 0 ]]; then
    log "=== Backup dry-run completed; ${SKIPS} component(s) unreachable from here ==="
  fi
  log "=== Backup completed successfully ==="
  notify_slack "success" "All components backed up to ${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/${TIMESTAMP}"
  exit 0
else
  log "=== Backup completed with ${ERRORS} error(s) ==="
  notify_slack "failure" "${ERRORS} component(s) failed. Check logs."
  exit 1
fi
