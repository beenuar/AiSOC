"""ORM models for intel-driven retro-hunts (gap-closure Phase 8.1).

Mirrors ``services/api/migrations/070_retro_hunts.sql``. The reasoning for
every column lives in that file, beside the constraint that enforces it;
``scripts/check_orm_migration_parity.py`` reads both and fails when they
disagree in either direction.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _now() -> datetime:
    return datetime.now(UTC)


class RetroHuntSettings(Base):
    """One tenant's answer to "may AiSOC sweep my history, and how much"."""

    __tablename__ = "retro_hunt_settings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lookback_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    include_federated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    max_sweeps_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    max_sweeps_per_day: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)

    sweeps_this_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hour_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    sweeps_today: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    day_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    sweeps_skipped_budget: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class RetroHuntSighting(Base):
    """One (tenant, indicator) a retro-hunt has matched.

    The unique constraint is the dedup mechanism, not an index: a feed that
    republishes an indicator daily updates ``times_seen`` here rather than
    opening an alert a day.
    """

    __tablename__ = "retro_hunt_sightings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "indicator_type", "indicator_value", name="retro_hunt_sightings_unique"),
        Index("idx_retro_hunt_sightings_tenant", "tenant_id", "last_matched_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)

    indicator_type: Mapped[str] = mapped_column(Text, nullable=False)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False)

    feed_source: Mapped[str] = mapped_column(Text, nullable=False)
    intel_first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    first_matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    last_matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    first_sighting_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sighting_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sightings: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    matched_surfaces: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


__all__ = ["RetroHuntSettings", "RetroHuntSighting"]
