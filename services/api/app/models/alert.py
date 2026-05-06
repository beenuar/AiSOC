"""Alert ORM model."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)

    # Core fields
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # critical/high/medium/low/info
    status: Mapped[str] = mapped_column(String(30), default="new", index=True)  # new/triaging/in_progress/resolved/fp/closed
    priority: Mapped[int] = mapped_column(Integer, default=50)  # 0-100

    # Classification
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Source
    connector_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    connector_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_event_ids: Mapped[list] = mapped_column(JSONB, default=list)
    ocsf_class_uid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Analyst verdict / disposition (set via feedback endpoint)
    disposition: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    # Timestamp when an analyst first viewed / started triaging the alert (for MTTD)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # AI/ML
    ai_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_recommendations: Mapped[list] = mapped_column(JSONB, default=list)
    false_positive_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Entities (denormalized for fast querying)
    affected_ips: Mapped[list] = mapped_column(JSONB, default=list)
    affected_hosts: Mapped[list] = mapped_column(JSONB, default=list)
    affected_users: Mapped[list] = mapped_column(JSONB, default=list)
    affected_assets: Mapped[list] = mapped_column(JSONB, default=list)

    # Relations
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    parent_alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    child_alert_ids: Mapped[list] = mapped_column(JSONB, default=list)
    is_merged: Mapped[bool] = mapped_column(default=False)

    # Assignment
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Mobile responder PWA: temporarily defer this alert from the queue.
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    snoozed_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # Raw data
    raw_event: Mapped[dict] = mapped_column(JSONB, default=dict)
    enrichment_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    tags: Mapped[list] = mapped_column(JSONB, default=list)

    # Timestamps
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        Index("ix_alerts_tenant_severity_status", "tenant_id", "severity", "status"),
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
        Index("ix_alerts_tenant_event_time", "tenant_id", "event_time"),
    )
