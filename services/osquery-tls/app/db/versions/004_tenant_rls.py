"""Row-level security on the osquery-TLS tables.

Revision ID: 004
Revises: 003
Create Date: 2026-09-24

Companion to ``services/api/migrations/060_rls_coverage.sql``. This service
shares one Postgres database with the API but manages its own schema, so its
three tenant-scoped tables were outside that chain's reach and carried no
policy.

The predicate is spelled inline rather than calling ``current_tenant_id()``
(defined by the API's 002_rls.sql) because nothing orders the two chains
against each other: this revision can run against a database the API chain has
not touched yet, and a policy that fails to create is a policy nobody has.

Semantics match the API chain — fail open on a session with no tenant context,
fail closed on one that set it:

    tenant_id = <context>  OR  <context> IS NULL

Two caveats, stated rather than left to be discovered:

* ``tenant_id`` here is ``VARCHAR(64)``, not ``uuid``, and 001_init gives it
  ``server_default='default'``. The comparison is therefore text-to-text, and
  a row carrying the literal ``'default'`` will not match a session bound to a
  UUID. That is a property of the column, not of the policy; re-typing it is a
  data migration this revision deliberately does not attempt.
* This service never calls ``set_rls_context``, so on its own connections the
  context is always unset and these policies are inert by design. They engage
  for any other service reading these tables through a tenant-scoped session,
  and they stop being bypassed the moment the deployment connects as a role
  without BYPASSRLS. See ``apps/docs/docs/operations/security.md``.

The predicate is not the control here and was never meant to be: the
node-registry lookups are keyed on the enrolment credential, and
``get_query_by_id`` joins through ``osquery_node`` to reach a tenant. This adds
the second layer under them.
"""

from __future__ import annotations

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None

# Spelled out one table at a time rather than looped over a tuple:
# scripts/check_tenant_query_predicates.py derives which tables carry a
# policy by reading migration text, and a table name that only exists as
# a Python variable is a policy the gate cannot see.


def upgrade() -> None:
    op.execute("ALTER TABLE osquery_node ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE osquery_node FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS osquery_node_tenant ON osquery_node")
    op.execute(
        "CREATE POLICY osquery_node_tenant ON osquery_node "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), '')) "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE osquery_pack_assignment ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE osquery_pack_assignment FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS osquery_pack_assignment_tenant ON osquery_pack_assignment")
    op.execute(
        "CREATE POLICY osquery_pack_assignment_tenant ON osquery_pack_assignment "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), '')) "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE fim_event ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE fim_event FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS fim_event_tenant ON fim_event")
    op.execute(
        "CREATE POLICY fim_event_tenant ON fim_event "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), '')) "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS osquery_node_tenant ON osquery_node")
    op.execute("ALTER TABLE osquery_node NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE osquery_node DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS osquery_pack_assignment_tenant ON osquery_pack_assignment")
    op.execute("ALTER TABLE osquery_pack_assignment NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE osquery_pack_assignment DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS fim_event_tenant ON fim_event")
    op.execute("ALTER TABLE fim_event NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE fim_event DISABLE ROW LEVEL SECURITY")
