"""Row-level security on the honeytoken tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24

Companion to ``services/api/migrations/060_rls_coverage.sql``. This service
shares one Postgres database with the API but manages its own schema, so its
two tenant-scoped tables were outside that chain's reach and carried no policy.

The predicate is spelled inline rather than calling ``current_tenant_id()``
(defined by the API's 002_rls.sql) because nothing orders the two chains
against each other: this revision can run against a database the API chain has
not touched yet, and a policy that fails to create is a policy nobody has.

Semantics match the API chain exactly — fail open on a session with no tenant
context, fail closed on one that set it:

    tenant_id = <context>  OR  <context> IS NULL

Honest scope: this service never calls ``set_rls_context``, so on its own
connections the context is always unset and these policies are inert by
design. They engage for any other service that reads these tables through a
tenant-scoped session, and they stop being bypassed the moment the deployment
connects as a role without BYPASSRLS. See
``apps/docs/docs/operations/security.md``.
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# Spelled out one table at a time rather than looped over a tuple:
# scripts/check_tenant_query_predicates.py derives which tables carry a
# policy by reading migration text, and a table name that only exists as
# a Python variable is a policy the gate cannot see.


def upgrade() -> None:
    op.execute("ALTER TABLE honeytokens ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE honeytokens FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS honeytokens_tenant ON honeytokens")
    op.execute(
        "CREATE POLICY honeytokens_tenant ON honeytokens "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE honeytoken_triggers ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE honeytoken_triggers FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS honeytoken_triggers_tenant ON honeytoken_triggers")
    op.execute(
        "CREATE POLICY honeytoken_triggers_tenant ON honeytoken_triggers "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS honeytokens_tenant ON honeytokens")
    op.execute("ALTER TABLE honeytokens NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE honeytokens DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS honeytoken_triggers_tenant ON honeytoken_triggers")
    op.execute("ALTER TABLE honeytoken_triggers NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE honeytoken_triggers DISABLE ROW LEVEL SECURITY")
