"""Initial purple team tables.

Revision ID: 0001
Revises:
Create Date: 2026-05-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "purple_team_atomic_tests",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("technique_name", sa.String(256), nullable=False),
        sa.Column("tactic", sa.String(64), nullable=False),
        sa.Column("test_guid", sa.String(64), nullable=False),
        sa.Column("test_name", sa.String(512), nullable=False),
        sa.Column("test_description", sa.Text, nullable=True),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("executor", sa.String(32), nullable=False),
        sa.Column("input_arguments", JSONB, nullable=False, server_default="{}"),
        sa.Column("raw_yaml", JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_atomic_tests_tenant_id", "purple_team_atomic_tests", ["tenant_id"])
    op.create_index(
        "ix_atomic_tests_technique_id", "purple_team_atomic_tests", ["technique_id"]
    )
    op.create_index(
        "ix_atomic_tests_tenant_technique",
        "purple_team_atomic_tests",
        ["tenant_id", "technique_id"],
    )

    op.create_table(
        "purple_team_executions",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("technique_id", sa.String(16), nullable=False),
        sa.Column("test_name", sa.String(512), nullable=False),
        sa.Column("test_guid", sa.String(64), nullable=True),
        sa.Column("caldera_operation_id", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stdout", sa.Text, nullable=True),
        sa.Column("stderr", sa.Text, nullable=True),
        sa.Column("exit_code", sa.Integer, nullable=True),
        sa.Column("detected", sa.Boolean, nullable=True),
        sa.Column("alert_id", sa.String(64), nullable=True),
        sa.Column("detection_latency_seconds", sa.Float, nullable=True),
        sa.Column("executed_by", sa.String(128), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_executions_tenant_id", "purple_team_executions", ["tenant_id"])
    op.create_index(
        "ix_executions_technique_id", "purple_team_executions", ["technique_id"]
    )
    op.create_index(
        "ix_executions_created_at", "purple_team_executions", ["created_at"]
    )

    op.create_table(
        "purple_team_tabletop_sessions",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("scenario", sa.Text, nullable=False),
        sa.Column("technique_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("findings", JSONB, nullable=False, server_default="[]"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(128), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index(
        "ix_tabletop_sessions_tenant_id", "purple_team_tabletop_sessions", ["tenant_id"]
    )


def downgrade() -> None:
    op.drop_table("purple_team_tabletop_sessions")
    op.drop_table("purple_team_executions")
    op.drop_table("purple_team_atomic_tests")
