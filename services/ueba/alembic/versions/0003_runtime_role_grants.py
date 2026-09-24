"""Give the runtime role DML on the UEBA tables, and nothing more.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-24

Companion to ``services/api/migrations/061_runtime_app_role.sql``, which split
one superuser credential into an owner that applies DDL and ``aisoc_app``, the
DML-only role every service's ``DATABASE_URL`` points at. That migration
granted ``aisoc_app`` on ``ALL TABLES IN SCHEMA public`` as they stood when it
ran, and set ``ALTER DEFAULT PRIVILEGES`` for objects the *same* role creates
afterwards.

Neither clause reaches this chain reliably:

* nothing orders the two chains against each other, so this service's tables
  may not exist when 061's ``ALL TABLES`` grant runs;
* ``ALTER DEFAULT PRIVILEGES`` is recorded against the role that issued it, so
  a deployment applying the API chain and this one under different owners — or
  pointing this service at its own database, which ``UEBA_DATABASE_URL`` exists
  to allow — gets no default privilege here at all.

The observable failure is a service that starts, connects, and answers every
query with ``permission denied for table ueba_anomalies``. So the chain grants
what its own tables need rather than depending on another chain having run.

Grants, not ownership: an owner can ``ALTER TABLE … NO FORCE ROW LEVEL
SECURITY``, which is the bypass 061 exists to close. ``aisoc_app`` therefore
gets ``SELECT, INSERT, UPDATE, DELETE`` and not ``TRUNCATE``, ``REFERENCES`` or
``TRIGGER``.

The role name is a literal because it has to match 061, the compose stack and
every deployment surface, and a role interpolated into DDL from an environment
variable is an injection site with no upside. A deployment using a different
runtime role issues the equivalent grant itself; the guard below makes this
revision a notice rather than a failure there.
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

# Spelled out one table at a time rather than derived from the mapped
# metadata: a grant covering whatever happens to be mapped today is not
# reviewable, and this list is the reviewable part of the change.
TABLES = ("ueba_entity_baselines", "ueba_anomalies", "ueba_peer_groups")

RUNTIME_ROLE = "aisoc_app"


def _statement(action: str, tables: tuple[str, ...], role: str) -> str:
    """``GRANT``/``REVOKE`` over these tables and the sequences they own.

    Sequences are included because ``nextval`` needs ``USAGE`` and ``currval``
    needs ``SELECT``, and a grant on the table alone carries neither — the
    first ``BIGSERIAL`` anybody adds to this chain would fail at insert time
    with a message about a sequence nobody went looking for.
    """
    array = "ARRAY[" + ", ".join(f"'{t}'" for t in tables) + "]"
    if action == "GRANT":
        clause = (
            "format('GRANT %s ON %s TO " + role + "', "
            "CASE obj.kind WHEN 'S' THEN 'USAGE, SELECT' ELSE 'SELECT, INSERT, UPDATE, DELETE' END, obj.ref)"
        )
        notice = (
            f"RAISE NOTICE 'role {role} does not exist; skipping runtime grants. Apply "
            f"services/api/migrations/061_runtime_app_role.sql, or grant your own runtime role "
            f"DML on these tables by hand.';"
        )
    else:
        clause = "format('REVOKE ALL ON %s FROM " + role + "', obj.ref)"
        notice = ""
    return f"""
DO $$
DECLARE
    obj record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
        {notice}
        RETURN;
    END IF;
    FOR obj IN
        SELECT c.oid::regclass::text AS ref, c.relkind AS kind
          FROM pg_class c
         WHERE pg_table_is_visible(c.oid)
           AND (
                (c.relkind IN ('r', 'p') AND c.relname = ANY ({array}))
             -- Only sequences. An index carries the same 'a' dependency on its
             -- table, and GRANT on one raises `"ix_…" is an index` — which the
             -- live round-trip caught and a review of the statement did not.
             OR (c.relkind = 'S' AND c.oid IN (
                    SELECT d.objid
                      FROM pg_depend d
                      JOIN pg_class t ON t.oid = d.refobjid
                     WHERE d.deptype = 'a' AND t.relname = ANY ({array})
                ))
           )
    LOOP
        EXECUTE {clause};
    END LOOP;
END
$$;
"""


def upgrade() -> None:
    op.execute(_statement("GRANT", TABLES, RUNTIME_ROLE))


def downgrade() -> None:
    op.execute(_statement("REVOKE", TABLES, RUNTIME_ROLE))
