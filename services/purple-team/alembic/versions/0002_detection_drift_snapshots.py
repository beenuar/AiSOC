"""Detection drift snapshots.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-05
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "purple_team_detection_drift_snapshots",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "captured_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("trigger", sa.String(32), nullable=False, server_default="scheduled"),
        sa.Column("total_techniques", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tested_techniques", sa.Integer, nullable=False, server_default="0"),
        sa.Column("detected_techniques", sa.Integer, nullable=False, server_default="0"),
        sa.Column("overall_coverage", sa.Float, nullable=False, server_default="0"),
        sa.Column("coverage", JSONB, nullable=False, server_default="{}"),
    )
    op.create_index(
        "ix_drift_snapshots_tenant_id",
        "purple_team_detection_drift_snapshots",
        ["tenant_id"],
    )
    op.create_index(
        "ix_drift_snapshots_captured_at",
        "purple_team_detection_drift_snapshots",
        ["captured_at"],
    )
    op.create_index(
        "ix_drift_snapshots_tenant_captured_at",
        "purple_team_detection_drift_snapshots",
        ["tenant_id", "captured_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_drift_snapshots_tenant_captured_at",
        table_name="purple_team_detection_drift_snapshots",
    )
    op.drop_index(
        "ix_drift_snapshots_captured_at",
        table_name="purple_team_detection_drift_snapshots",
    )
    op.drop_index(
        "ix_drift_snapshots_tenant_id",
        table_name="purple_team_detection_drift_snapshots",
    )
    op.drop_table("purple_team_detection_drift_snapshots")
