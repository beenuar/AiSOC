#!/usr/bin/env bash
# Give the runtime role a login credential on a freshly initialised database.
#
# `services/api/migrations/061_runtime_app_role.sql` creates `aisoc_app` with
# DML-only grants and refuses to leave it able to bypass row-level security.
# What it deliberately does not do is set a password: a migration in a public
# repository must not carry one, and it must not clobber a credential an
# operator already configured.
#
# So the credential is applied here, from the environment, at the one moment
# where doing it is unambiguous — the postgres image's own first-boot init,
# which runs before the container reports healthy and therefore before any
# service's `depends_on: service_healthy` lets it try to connect.
#
# Numbered `20_` so it runs after `10_apply_migrations.sh`, which is what
# creates the role and its grants. Setting a password on a role that does not
# exist yet would create one with no privileges at all.
#
# Two things this cannot cover, both documented in
# apps/docs/docs/operations/security.md:
#
#   * An *existing* data volume. `/docker-entrypoint-initdb.d` runs only when
#     the data directory is empty, so an upgrade in place never reaches this
#     script. `app.scripts.run_migrations` applies the same environment
#     variable on every run, which is what closes that path.
#   * A managed Postgres (RDS, Cloud SQL, a Helm-installed chart). There is no
#     init hook to attach to; the deployment provisions the role itself.

set -euo pipefail

PASSWORD="${AISOC_APP_DB_PASSWORD:-}"

if [ -z "${PASSWORD}" ]; then
    echo "[runtime-role] AISOC_APP_DB_PASSWORD is empty — leaving aisoc_app without a login." >&2
    echo "[runtime-role] Services pointed at aisoc_app will fail to authenticate until one is set." >&2
    exit 0
fi

# The password never appears in the statement text. psql's `:'name'` quotes the
# variable for the `set_config` call — and only there, because psql does not
# substitute inside a dollar-quoted block — then `quote_literal` re-quotes it
# for the ALTER, which is a utility statement and takes no parameters. A
# password containing a quote therefore cannot terminate a literal.
psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER}" \
     --dbname "${POSTGRES_DB}" \
     --set=app_password="${PASSWORD}" <<'SQL'
SELECT set_config('aisoc.app_password', :'app_password', false);

DO $$
DECLARE
    pw text := current_setting('aisoc.app_password');
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'CREATE ROLE aisoc_app LOGIN PASSWORD ' || quote_literal(pw);
    ELSE
        EXECUTE 'ALTER ROLE aisoc_app WITH LOGIN PASSWORD ' || quote_literal(pw);
    END IF;
END
$$;

SELECT set_config('aisoc.app_password', '', false);
SQL

echo "[runtime-role] aisoc_app can now log in; row-level security applies to it."
