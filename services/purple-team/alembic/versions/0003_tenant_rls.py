"""Row-level security on the purple-team tables.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-24

Companion to ``services/api/migrations/060_rls_coverage.sql``. This service
shares one Postgres database with the API but manages its own schema, so its
four tenant-scoped tables were outside that chain's reach and carried no
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

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

# Spelled out one table at a time rather than looped over a tuple:
# scripts/check_tenant_query_predicates.py derives which tables carry a
# policy by reading migration text, and a table name that only exists as
# a Python variable is a policy the gate cannot see.


def upgrade() -> None:
    op.execute("ALTER TABLE purple_team_atomic_tests ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE purple_team_atomic_tests FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS purple_team_atomic_tests_tenant ON purple_team_atomic_tests")
    op.execute(
        "CREATE POLICY purple_team_atomic_tests_tenant ON purple_team_atomic_tests "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE purple_team_executions ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE purple_team_executions FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS purple_team_executions_tenant ON purple_team_executions")
    op.execute(
        "CREATE POLICY purple_team_executions_tenant ON purple_team_executions "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE purple_team_tabletop_sessions ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE purple_team_tabletop_sessions FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS purple_team_tabletop_sessions_tenant ON purple_team_tabletop_sessions")
    op.execute(
        "CREATE POLICY purple_team_tabletop_sessions_tenant ON purple_team_tabletop_sessions "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    op.execute("ALTER TABLE purple_team_detection_drift_snapshots ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, and this
    # service owns the tables it created.
    op.execute("ALTER TABLE purple_team_detection_drift_snapshots FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS purple_team_detection_drift_snapshots_tenant ON purple_team_detection_drift_snapshots")
    op.execute(
        "CREATE POLICY purple_team_detection_drift_snapshots_tenant ON purple_team_detection_drift_snapshots "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS purple_team_atomic_tests_tenant ON purple_team_atomic_tests")
    op.execute("ALTER TABLE purple_team_atomic_tests NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE purple_team_atomic_tests DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS purple_team_executions_tenant ON purple_team_executions")
    op.execute("ALTER TABLE purple_team_executions NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE purple_team_executions DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS purple_team_tabletop_sessions_tenant ON purple_team_tabletop_sessions")
    op.execute("ALTER TABLE purple_team_tabletop_sessions NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE purple_team_tabletop_sessions DISABLE ROW LEVEL SECURITY")

    op.execute("DROP POLICY IF EXISTS purple_team_detection_drift_snapshots_tenant ON purple_team_detection_drift_snapshots")
    op.execute("ALTER TABLE purple_team_detection_drift_snapshots NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE purple_team_detection_drift_snapshots DISABLE ROW LEVEL SECURITY")
