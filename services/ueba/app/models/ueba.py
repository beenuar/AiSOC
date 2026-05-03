"""SQLAlchemy ORM models for UEBA."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class EntityBaseline(Base):
    """Rolling behavioural baseline for a user/device/IP entity."""

    __tablename__ = "ueba_entity_baselines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)   # user | device | ip
    entity_id: Mapped[str] = mapped_column(String(256), nullable=False)

    # Feature statistics (JSON: {"feature": {"mean": X, "std": Y, "count": N}})
    feature_stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Peer group membership (comma-separated entity IDs)
    peer_group_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_ueba_baseline_tenant_entity", "tenant_id", "entity_type", "entity_id"),
    )


class UEBAAnomaly(Base):
    """Scored anomaly event emitted by the UEBA engine."""

    __tablename__ = "ueba_anomalies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(256), nullable=False)

    # The raw event that triggered this anomaly
    source_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)

    # Anomaly scoring
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)   # composite z-score
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)   # low|medium|high|critical
    features: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # {"feature": {"value": X, "mean": Y, "std": Z, "z_score": W}}

    # Peer group deviation
    peer_group_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    peer_deviation_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    acknowledged: Mapped[bool] = mapped_column(default=False)

    __table_args__ = (
        Index("ix_ueba_anomaly_tenant_entity", "tenant_id", "entity_type", "entity_id"),
        Index("ix_ueba_anomaly_detected_at", "detected_at"),
    )


class PeerGroup(Base):
    """Logical grouping of similar entities for peer-comparison analysis."""

    __tablename__ = "ueba_peer_groups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "dept:engineering"
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, default=0)
    feature_stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_ueba_peergroup_tenant", "tenant_id", "entity_type"),
    )
