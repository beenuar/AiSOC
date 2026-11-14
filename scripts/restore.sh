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
#   4. Credential key (download + verify + decrypt + reconcile with .env)
#
# (4) is what makes the rest of it usable. The Postgres dump carries
# `vault:v1:` tokens for every connector credential, and AISOC_CREDENTIAL_KEY
# is the only thing that decrypts them — a restore without it brings the
# deployment back with every connector raising CredentialVaultError.
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
#   ./scripts/restore.sh --timestamp 20260503T120000Z \
#       [--component postgres|clickhouse|plugins|neo4j|qdrant|redis|credential_key|all]
#   ./scripts/restore.sh --latest [--component all]
#   ./scripts/restore.sh --list      # show available backups
#   ./scripts/restore.sh --latest --dry-run   # rehearse: fetch, verify and
#                                    # decrypt everything, write to nothing

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
# Three functions — restore_neo4j, restore_qdrant and restore_redis — branch
# on this and nothing ever set it, so under `set -euo pipefail` each died with
# `DRY_RUN: unbound variable` at the line that decides whether the run is a
# rehearsal. They are the three wave 15 added precisely because a backup
# nobody can restore is a backup nobody has proven they can use, and the crash
# only fires once the artifact is actually present — so it arrived during a
# real recovery and never during a rehearsal. There was no `--dry-run` arm
# either, so the flag could not be set even deliberately.
DRY_RUN=false
RESTORE_DIR="/tmp/aisoc-restore-$$"

# ── arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timestamp)  TIMESTAMP="$2"; shift ;;
    --component)  COMPONENT="$2"; shift ;;
    --latest)     USE_LATEST=true ;;
    --list)       DO_LIST=true ;;
    # Rehearse: fetch, verify and decrypt every artifact, and stop short of
    # writing to any store. An unreachable store is a skip here and not a
    # failure, the same way it is in backup.sh — a rehearsal an operator
    # cannot run from a laptop is a rehearsal nobody runs.
    --dry-run)    DRY_RUN=true ;;
    *)            echo "Unknown arg: $1"; exit 1 ;;
  esac
  shift
done

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[$(date -u +%T)] $*"; }

require() {
  command -v "$1" &>/dev/null || { echo "Missing required command: $1" >&2; exit 1; }
}

# Reads one assignment out of a .env file; last one wins. Kept byte-identical
# to backup.sh's copy on purpose — the two have to agree about which value is
# "the configured key" or the comparison in restore_credential_key is between
# two different questions.
#
# python3 rather than sed: BSD sed, which is what macOS provides, does not
# accept `\+` or `\?` in a basic regex. The sed version returned empty on
# every macOS host, and empty reads as "no key configured" — the branch that
# writes. A live run overwrote a key it was supposed to refuse to touch.
env_value() {
  python3 - "$1" "$2" <<'PYEOF'
import sys
path, key = sys.argv[1:3]
found = ""
with open(path, encoding="utf-8", errors="replace") as handle:
    for raw in handle:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            found = value.strip().strip("\"'")
print(found)
PYEOF
}

s3_args() {
  local args=()
  [[ -n "${AWS_ENDPOINT_URL:-}" ]] && args+=(--endpoint-url "$AWS_ENDPOINT_URL")
  echo ${args[@]+"${args[@]}"}
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
  # ON_ERROR_STOP, because without it psql exits 0 after a failed replay.
  # Measured on 2026-11-09: a pg_dump 18 preamble (`SET transaction_timeout`)
  # aborted the whole --single-transaction replay into a 16 server, psql
  # printed hundreds of "current transaction is aborted" lines, exited 0, and
  # this function logged "restore complete" over a database that held nothing.
  # A restore that claims success must mean the replay ran to the end.
  gunzip -c "$local_file" | psql "$POSTGRES_URL" --single-transaction --set ON_ERROR_STOP=on
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
# ── Neo4j ─────────────────────────────────────────────────────────────────────
#
# Gap-closure wave 15. Neo4j, Qdrant and Redis each had a backup path
# and **no restore**, which is a backup nobody has ever proven they can
# use — and the first time anyone finds out is during the recovery.
#
# Neo4j is restored by replaying the Cypher the backup exported.
# `neo4j-admin load` is not an option here for the same reason the
# backup does not use `neo4j-admin dump`: it needs the database
# stopped, and a restore that requires downtime on a store the rest of
# the platform degrades gracefully without is a worse trade than a
# slower replay.
restore_neo4j() {
  log "--- Neo4j restore ---"
  local base="neo4j-${TIMESTAMP}.cypher.gz"
  local local_file="${RESTORE_DIR}/${base}"

  if ! fetch_artifact "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/neo4j" "$base" "$local_file"; then
    log "No Neo4j backup for ${TIMESTAMP}; skipping"
    return
  fi
  verify_artifact "$local_file" "neo4j/${base}"

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would replay $(gzip -dc "$local_file" | grep -c . || echo 0) Cypher statements"
    return
  fi

  # Statement at a time rather than one transaction: the export is
  # large, and a single failing MERGE must not discard the whole graph
  # restore. Failures are counted and reported rather than swallowed —
  # a restore that reports success having skipped half the graph is
  # the failure this whole wave is about.
  local applied=0 failed=0 stmt
  while IFS= read -r stmt; do
    [[ -z "$stmt" || "$stmt" == //* ]] && continue
    if curl -sf -u "${NEO4J_USER}:${NEO4J_PASSWORD}" \
         -H 'Content-Type: application/json' \
         -d "$(python3 -c 'import json,sys; print(json.dumps({"statements":[{"statement":sys.stdin.read()}]}))' <<<"$stmt")" \
         "${NEO4J_HTTP_URL}/db/neo4j/tx/commit" >/dev/null 2>&1; then
      applied=$((applied + 1))
    else
      failed=$((failed + 1))
    fi
  done < <(gzip -dc "$local_file")

  log "Neo4j: ${applied} statements applied, ${failed} failed"
  if [[ "$failed" -gt 0 ]]; then
    echo "ERROR: ${failed} Cypher statements failed; the graph is incomplete" >&2
    return 1
  fi
}

# ── Qdrant ────────────────────────────────────────────────────────────────────
#
# Restored per collection from the snapshot API. Collections are
# recreated by the upload rather than pre-created here: the vector
# dimension is immutable, and creating one with the wrong dimension
# would make the restore fail in a way that looks like corrupt data.
restore_qdrant() {
  log "--- Qdrant restore ---"
  local prefix="${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/qdrant"
  # shellcheck disable=SC2046
  local collections
  collections=$(aws s3 ls $(s3_args) "${prefix}/" 2>/dev/null | awk '{print $2}' | sed 's|/$||' || echo "")

  if [[ -z "$collections" ]]; then
    log "No Qdrant backup directories found; skipping"
    return
  fi

  local restored=0
  while IFS= read -r collection; do
    [[ -z "$collection" ]] && continue
    local base="${collection}-${TIMESTAMP}.snapshot"
    local local_file="${RESTORE_DIR}/qdrant-${base}"

    if ! fetch_artifact "${prefix}/${collection}" "$base" "$local_file"; then
      log "No snapshot for collection ${collection} at ${TIMESTAMP}; skipping"
      continue
    fi
    verify_artifact "$local_file" "qdrant/${collection}/${base}"

    if [[ "$DRY_RUN" == "true" ]]; then
      log "[dry-run] Would upload snapshot to collection ${collection}"
      continue
    fi

    if curl -sf -X POST \
         -H 'api-key: '"${QDRANT_API_KEY:-}" \
         -F "snapshot=@${local_file}" \
         "${QDRANT_URL}/collections/${collection}/snapshots/upload?priority=snapshot" >/dev/null; then
      restored=$((restored + 1))
    else
      echo "ERROR: Qdrant collection ${collection} failed to restore" >&2
      return 1
    fi
  done <<< "$collections"

  log "Qdrant: ${restored} collection(s) restored"
}

# ── Redis ─────────────────────────────────────────────────────────────────────
#
# Redis holds cache, the OIDC state store and rate-limit counters —
# all of which the platform rebuilds. So this restores the RDB only
# when explicitly asked, and the default guidance is to start empty:
# replacing a running cache with an hours-old one serves stale answers
# with full confidence, which is worse than a cold start.
restore_redis() {
  log "--- Redis restore ---"
  local base="redis-${TIMESTAMP}.rdb"
  local local_file="${RESTORE_DIR}/${base}"

  if ! fetch_artifact "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/redis" "$base" "$local_file"; then
    log "No Redis backup for ${TIMESTAMP}; skipping"
    return
  fi
  verify_artifact "$local_file" "redis/${base}"

  if [[ "${REDIS_RESTORE_CONFIRM:-}" != "yes" ]]; then
    log "Redis holds only rebuildable state (cache, OIDC states, rate limits)."
    log "A restored cache serves stale answers with full confidence, which is worse"
    log "than a cold start. Set REDIS_RESTORE_CONFIRM=yes to restore it anyway."
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would load ${base} into ${REDIS_URL}"
    return
  fi

  # The RDB has to be placed where the server reads it, which means
  # the restore runs against the container rather than the protocol.
  if ! command -v docker &>/dev/null; then
    echo "ERROR: Redis restore needs docker to place the RDB; none found" >&2
    return 1
  fi
  docker cp "$local_file" "${REDIS_CONTAINER:-redis}:/data/dump.rdb"
  docker restart "${REDIS_CONTAINER:-redis}" >/dev/null
  log "Redis: RDB restored and the server restarted"
}

# ── Credential key ────────────────────────────────────────────────────────────
# The key that decrypts every `vault:v1:` token the Postgres dump just
# restored. Without it the rows come back and every connector raises
# CredentialVaultError on its first poll.
#
# This deliberately does not write `.env` unconditionally. Three cases, and
# only one of them is safe to do silently:
#
#   absent or empty in .env   the recovery case. Written, so the restore
#                             actually completes.
#   byte-identical            nothing to do.
#   present and different     REFUSED. Overwriting it would orphan whatever
#                             this deployment has encrypted under the current
#                             key — the same defect as the one being fixed,
#                             pointed the other way. The decrypted key is left
#                             on disk at mode 600 and the operator decides.
restore_credential_key() {
  log "--- Credential key restore ---"
  local base="credential-key-${TIMESTAMP}.json"
  local local_file="${RESTORE_DIR}/${base}"

  if ! fetch_artifact "${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}/credential-key" "$base" "$local_file"; then
    log "No credential key in the ${TIMESTAMP} backup."
    log "  If this deployment has stored connector credentials, they will NOT"
    log "  decrypt: the vault key is not in this backup. Recover it from the"
    log "  .env of the host the backup was taken on."
    return
  fi
  chmod 600 "$local_file" 2>/dev/null || true

  local repo_root env_file restored current
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  env_file="${AISOC_ENV_FILE:-${repo_root}/.env}"

  restored=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['AISOC_CREDENTIAL_KEY'])" "$local_file" 2>/dev/null || echo "")
  if [[ -z "$restored" ]]; then
    echo "[ERROR] The credential-key artifact carries no AISOC_CREDENTIAL_KEY." >&2
    return 1
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[dry-run] Would reconcile the vault key against ${env_file}"
    return
  fi

  current=""
  if [[ -f "$env_file" ]]; then
    current=$(env_value "$env_file" AISOC_CREDENTIAL_KEY)
  fi

  if [[ -n "$current" ]] && [[ "$current" != "$restored" ]]; then
    # Never prints either value.
    echo "[ERROR] ${env_file} already has a DIFFERENT AISOC_CREDENTIAL_KEY." >&2
    echo "        Not overwriting it: anything this deployment has encrypted under" >&2
    echo "        the current key would stop decrypting, which is the same failure" >&2
    echo "        this component exists to prevent, in the other direction." >&2
    echo "        The backup's key is at ${local_file} (mode 600). Decide which" >&2
    echo "        deployment's credentials you are recovering, then set it by hand." >&2
    return 1
  fi

  if [[ "$current" == "$restored" ]]; then
    log "  ${env_file} already holds this key; nothing to do."
    return
  fi

  touch "$env_file" && chmod 600 "$env_file"
  if grep -qE '^[[:space:]]*(export[[:space:]]+)?AISOC_CREDENTIAL_KEY=' "$env_file"; then
    # In-place via python rather than sed -i, whose flag differs between
    # GNU and BSD and would silently create a `.env-e` on macOS.
    AISOC_RESTORED_KEY="$restored" python3 - "$env_file" <<'PYEOF'
import os, pathlib, re, sys
p = pathlib.Path(sys.argv[1])
pattern = re.compile(r"^(\s*(?:export\s+)?AISOC_CREDENTIAL_KEY\s*=).*$", re.MULTILINE)
p.write_text(pattern.sub(lambda m: m.group(1) + os.environ["AISOC_RESTORED_KEY"], p.read_text(), count=1))
PYEOF
  else
    printf '\n# Restored by scripts/restore.sh — the vault key the backup was taken with.\nAISOC_CREDENTIAL_KEY=%s\n' "$restored" >> "$env_file"
  fi

  local rotation
  rotation=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('AISOC_CREDENTIAL_KEY_ROTATION_FROM',''))" "$local_file" 2>/dev/null || echo "")
  if [[ -n "$rotation" ]]; then
    log "  The backup also carries a rotation key. It is at ${local_file};"
    log "  set AISOC_CREDENTIAL_KEY_ROTATION_FROM from it if tokens predate the"
    log "  last rotation."
  fi

  log "  Vault key written to ${env_file}. Restart the stack for it to take effect."
}

case "$COMPONENT" in
  postgres)       restore_postgres ;;
  clickhouse)     restore_clickhouse ;;
  plugins)        restore_plugins ;;
  neo4j)          restore_neo4j ;;
  qdrant)         restore_qdrant ;;
  redis)          restore_redis ;;
  credential_key) restore_credential_key ;;
  all)
    # The key first. Everything after it restores data encrypted under it,
    # and a run that dies part-way should not leave the tokens recovered and
    # the key that opens them still in the bucket.
    restore_credential_key
    restore_postgres
    restore_clickhouse
    restore_plugins
    # Added in wave 15. Each had a backup path and no restore, which
    # is a backup nobody has proven they can use.
    restore_neo4j
    restore_qdrant
    restore_redis
    ;;
  *)
    echo "Unknown component: $COMPONENT (choose: postgres|clickhouse|plugins|neo4j|qdrant|redis|credential_key|all)" >&2
    exit 1
    ;;
esac

log "=== Restore completed successfully ==="
