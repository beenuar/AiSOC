"""Initial UEBA tables.

Revision ID: 0001
Revises:
Create Date: 2026-05-03
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ueba_entity_baselines",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(256), nullable=False),
        sa.Column("feature_stats", JSONB, nullable=False, server_default="{}"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index(
        "ix_ueba_entity_baselines_tenant_entity",
        "ueba_entity_baselines",
        ["tenant_id", "entity_type", "entity_id"],
        unique=False,
    )

    op.create_table(
        "ueba_anomalies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(256), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("anomaly_score", sa.Float, nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("features", JSONB, nullable=False, server_default="{}"),
        sa.Column("z_scores", JSONB, nullable=False, server_default="{}"),
        sa.Column("peer_group_id", sa.String(128)),
        sa.Column("peer_deviation_score", sa.Float),
        sa.Column("source_event_id", sa.String(128)),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("acknowledged", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index(
        "ix_ueba_anomalies_tenant_entity",
        "ueba_anomalies",
        ["tenant_id", "entity_type", "entity_id"],
    )
    op.create_index(
        "ix_ueba_anomalies_detected_at",
        "ueba_anomalies",
        ["detected_at"],
    )

    op.create_table(
        "ueba_peer_groups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("feature_stats", JSONB, nullable=False, server_default="{}"),
        sa.Column("member_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index(
        "ix_ueba_peer_groups_tenant_label",
        "ueba_peer_groups",
        ["tenant_id", "label"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("ueba_peer_groups")
    op.drop_table("ueba_anomalies")
    op.drop_table("ueba_entity_baselines")
