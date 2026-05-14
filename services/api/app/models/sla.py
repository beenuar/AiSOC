"""SQLAlchemy ORM models for SLA tracking."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TenantSLAConfig(Base):
    __tablename__ = "tenant_sla_config"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    mttd_target: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    mttr_target: Mapped[int] = mapped_column(Integer, nullable=False, default=240)
    mttc_target: Mapped[int] = mapped_column(Integer, nullable=False, default=480)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "severity", name="uq_sla_config_tenant_severity"),
        # Mirrors the constraint we install in migration 040. We keep the
        # ORM-level name distinct from the live DB constraint name so this
        # stays drop-in compatible with existing deployments that still have
        # the original 4-tier `ck_sla_config_severity` constraint until
        # migration 040 swaps it for `ck_tenant_sla_config_severity_v2`.
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_sla_config_severity",
        ),
    )


class AlertSLAEvent(Base):
    __tablename__ = "alert_sla_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    # `metadata` is reserved on the Declarative `Base`; map the column to the
    # same DB name but expose it under `metadata_` on the ORM side, mirroring
    # what we already do in `app/models/compliance.py`.
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('detected','acknowledged','resolved','closed')",
            name="ck_sla_event_type",
        ),
    )
