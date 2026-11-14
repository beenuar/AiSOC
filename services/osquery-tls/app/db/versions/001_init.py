"""Initial schema: node_registry, distributed_query_queue, pack_assignment.

Revision ID: 001
Revises:
Create Date: 2026-05-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "osquery_node",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_identifier", sa.String(length=255), nullable=False),
        sa.Column("node_key", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("host_details", sa.JSON(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("node_key"),
        sa.UniqueConstraint("host_identifier", "tenant_id", name="uq_node_host_tenant"),
    )
    op.create_index("ix_osquery_node_node_key", "osquery_node", ["node_key"])
    op.create_index("ix_osquery_node_tenant_id", "osquery_node", ["tenant_id"])

    op.create_table(
        "osquery_pack_assignment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "pack_id", name="uq_pack_assignment"),
    )

    op.create_table(
        "osquery_distributed_query",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=False),
        sa.Column("query_id", sa.String(length=64), nullable=False),
        sa.Column("query_text", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("results_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["node_id"], ["osquery_node.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("query_id"),
    )
    op.create_index(
        "ix_osquery_dq_node_status",
        "osquery_distributed_query",
        ["node_id", "status"],
    )


def downgrade() -> None:
    op.drop_table("osquery_distributed_query")
    op.drop_table("osquery_pack_assignment")
    op.drop_table("osquery_node")
