"""Journal a honeytoken trip before acknowledging it, so a trip is never lost.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-05

GHSA-9q6p-m345-h3hj (F58). Delivery of a trip was attempted inline, once. If
the receiver was restarting, the attempt failed, ``alert_sent`` stayed false
on the trigger row and nothing ever looked at it again — the highest-
confidence signal this platform produces, lost to a thirty-second outage.

This is the same shape migration 121 uses for fusion's alert notifications: a
durable row written **before** the caller is told the trip was recorded, and
drained afterwards by an awaited path. The ordering is the whole point. A
crash between the journal write and the HTTP call costs a duplicate delivery;
a crash the other way round costs the alert, and the receiver can deduplicate
on ``trigger_id`` because every payload carries it.

Why the row carries a status and a reason
-----------------------------------------
A bare retry loop would turn a wrong URL into permanent churn and still
never tell anybody. ``status`` separates the three honest outcomes —
``pending`` (will be retried), ``delivered``, ``dead`` (no retry will help) —
and ``last_error`` records why, so "honeytoken alerts are not arriving" is a
query rather than an archaeology exercise over container logs.

``attempts`` and ``next_attempt_at`` carry the backoff. ``claimed_until`` is a
lease so two replicas draining at once do not both deliver the same row; it
is a timestamp rather than a boolean so a drainer that dies mid-attempt
releases its claim by expiry instead of stranding the row forever.

RLS mirrors the two existing tables in this chain exactly, including the
``current_setting(...) IS NULL`` arm. That arm is load-bearing rather than
lax: this service binds no tenant session anywhere, so a policy without it
would evaluate ``tenant_id = NULL``, refuse every write, and leave an outbox
that silently holds nothing — which is the defect this migration exists to
fix, reintroduced one layer down. ``WITH CHECK`` is deliberately omitted for
the same reason, and because the two sibling tables omit it too.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op  # type: ignore[attr-defined]  # re-exported at runtime, absent from the stub

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

#: Spelled as a literal at every use below. `check_orm_migration_parity`
#: reads these files statically, and a table named through a variable is
#: invisible to it -- it reported this table as created by no migration.


def upgrade() -> None:
    op.create_table(
        "honeytoken_alert_outbox",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        # One row per trip. A redelivery of the same trigger bumps the
        # attempt rather than adding a row, so a long receiver outage cannot
        # grow this table without bound.
        sa.Column("trigger_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        # The whole payload, so a drain does not have to re-derive it by
        # joining tables whose rows may have changed since the trip.
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("claimed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Added as its own statement rather than inline in `create_table`: the
    # ORM/migration parity gate reads the `create_table` argument list to
    # learn the column names, and an inline `sa.CheckConstraint` is read as a
    # column called "status IN ('pending', 'delivered', 'dead')".
    op.execute(
        "ALTER TABLE honeytoken_alert_outbox ADD CONSTRAINT honeytoken_alert_outbox_status "
        "CHECK (status IN ('pending', 'delivered', 'dead'))"
    )

    # The drain's only query: rows that are due and unclaimed. Partial,
    # because a delivered row is never read again and indexing the whole
    # table would make every successful trip pay for the failures.
    op.execute(
        "CREATE INDEX IF NOT EXISTS honeytoken_alert_outbox_claimable ON honeytoken_alert_outbox (next_attempt_at) WHERE status = 'pending'"
    )

    op.execute("ALTER TABLE honeytoken_alert_outbox ENABLE ROW LEVEL SECURITY")
    # Without FORCE the table owner bypasses the policy, which is how an RLS
    # fix gets validated into a false pass.
    op.execute("ALTER TABLE honeytoken_alert_outbox FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS honeytoken_alert_outbox_tenant ON honeytoken_alert_outbox")
    op.execute(
        "CREATE POLICY honeytoken_alert_outbox_tenant ON honeytoken_alert_outbox "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

    # Same reasoning as revision 0003: this chain grants what its own tables
    # need rather than depending on the API chain's ALL TABLES grant having
    # run after them. Guarded, so a deployment using a different runtime role
    # gets a notice instead of a failure.
    op.execute(
        """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        RAISE NOTICE 'role aisoc_app does not exist; skipping runtime grants on honeytoken_alert_outbox.';
        RETURN;
    END IF;
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON honeytoken_alert_outbox TO aisoc_app';
END
$$;
"""
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS honeytoken_alert_outbox_tenant ON honeytoken_alert_outbox")
    op.drop_table("honeytoken_alert_outbox")
