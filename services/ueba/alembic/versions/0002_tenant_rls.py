"""Row-level security on the UEBA tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24

Companion to ``services/api/migrations/060_rls_coverage.sql``. This service
shares one Postgres database with the API but manages its own schema, so its
three tenant-scoped tables were outside that chain's reach and carried no
policy.

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
    op.execute("ALTER TABLE ueba_entity_baselines ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE ueba_entity_baselines FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS ueba_entity_baselines_tenant ON ueba_entity_baselines")
    op.execute(
        "CREATE POLICY ueba_entity_baselines_tenant ON ueba_entity_baselines "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE ueba_anomalies ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE ueba_anomalies FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS ueba_anomalies_tenant ON ueba_anomalies")
    op.execute(
        "CREATE POLICY ueba_anomalies_tenant ON ueba_anomalies "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE ueba_peer_groups ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE ueba_peer_groups FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS ueba_peer_groups_tenant ON ueba_peer_groups")
    op.execute(
        "CREATE POLICY ueba_peer_groups_tenant ON ueba_peer_groups "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS ueba_entity_baselines_tenant ON ueba_entity_baselines")
    op.execute("ALTER TABLE ueba_entity_baselines NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ueba_entity_baselines DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS ueba_anomalies_tenant ON ueba_anomalies")
    op.execute("ALTER TABLE ueba_anomalies NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ueba_anomalies DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS ueba_peer_groups_tenant ON ueba_peer_groups")
    op.execute("ALTER TABLE ueba_peer_groups NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ueba_peer_groups DISABLE ROW LEVEL SECURITY")
