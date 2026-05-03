"""Initial honeytoken tables.

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
        "honeytokens",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("token_type", sa.String(32), nullable=False),
        sa.Column("token_value", sa.Text, nullable=False),
        sa.Column("metadata", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("created_by", sa.String(128), nullable=True),
    )
    op.create_index("ix_honeytokens_tenant_status", "honeytokens", ["tenant_id", "status"])
    op.create_index("ix_honeytokens_tenant_type", "honeytokens", ["tenant_id", "token_type"])

    op.create_table(
        "honeytoken_triggers",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "honeytoken_id",
            UUID(as_uuid=True),
            sa.ForeignKey("honeytokens.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("request_headers", JSONB, nullable=False, server_default="{}"),
        sa.Column("request_body", JSONB, nullable=False, server_default="{}"),
        sa.Column("geo_country", sa.String(8), nullable=True),
        sa.Column("geo_city", sa.String(128), nullable=True),
        sa.Column("threat_score", sa.Float, nullable=True),
        sa.Column("alert_sent", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("alert_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "triggered_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_honeytoken_triggers_triggered_at", "honeytoken_triggers", ["triggered_at"]
    )


def downgrade() -> None:
    op.drop_table("honeytoken_triggers")
    op.drop_table("honeytokens")
