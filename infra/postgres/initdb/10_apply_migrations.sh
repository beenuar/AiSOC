#!/usr/bin/env bash
# Apply the API migration chain on a freshly initialised database.
#
# The compose stacks used to bind `services/api/migrations` straight onto
# `/docker-entrypoint-initdb.d`, letting the postgres entrypoint run the `.sql`
# files itself. That stopped being possible once a second file had to run in
# the same directory: Docker cannot create a mountpoint *inside* a bind mount,
# so `- ./a/b.sh:/docker-entrypoint-initdb.d/b.sh` fails the container at
# startup with
#
#     create mountpoint for /docker-entrypoint-initdb.d/… : read-only file system
#
# — and it fails the same way whether or not the directory mount is `:ro`.
# Found by booting it, not by reading it.
#
# So the init directory is now `infra/postgres/initdb/`, holding this script
# and the one that sets the runtime role's password, and the migrations are
# mounted read-only alongside at AISOC_MIGRATIONS_DIR. Numbered filenames keep
# the order explicit rather than leaving it to a collation accident.
#
# Same semantics the entrypoint gave: files in filename order, `ON_ERROR_STOP`
# so a broken migration fails the boot instead of leaving a half-built schema
# that looks healthy.

set -euo pipefail

MIGRATIONS_DIR="${AISOC_MIGRATIONS_DIR:-/aisoc/migrations}"

if [ ! -d "${MIGRATIONS_DIR}" ]; then
    echo "[migrations] ${MIGRATIONS_DIR} is not mounted — no schema will be created." >&2
    echo "[migrations] Mount ./services/api/migrations there, or apply the chain from the API service." >&2
    exit 0
fi

shopt -s nullglob
files=("${MIGRATIONS_DIR}"/*.sql)
shopt -u nullglob

if [ ${#files[@]} -eq 0 ]; then
    echo "[migrations] ${MIGRATIONS_DIR} contains no .sql files — nothing applied." >&2
    exit 0
fi

echo "[migrations] applying ${#files[@]} files from ${MIGRATIONS_DIR}"
for f in "${files[@]}"; do
    echo "[migrations] $(basename "${f}")"
    psql -v ON_ERROR_STOP=1 --no-psqlrc \
         --username "${POSTGRES_USER}" \
         --dbname "${POSTGRES_DB}" \
         --quiet -f "${f}"
done
echo "[migrations] chain applied"
