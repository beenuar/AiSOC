"""Create fim_event table.

Revision ID: 003
Revises: 002
Create Date: 2026-05-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fim_event",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("node_key", sa.String(128), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("target_path", sa.Text(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("md5", sa.String(64), nullable=True),
        sa.Column("sha256", sa.String(128), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("ppid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_fim_event_tenant_time", "fim_event", ["tenant_id", "event_time"])
    op.create_index("ix_fim_event_action", "fim_event", ["action"])


def downgrade() -> None:
    op.drop_index("ix_fim_event_action", table_name="fim_event")
    op.drop_index("ix_fim_event_tenant_time", table_name="fim_event")
    op.drop_table("fim_event")
