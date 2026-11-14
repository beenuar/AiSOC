"""SQLAlchemy models for compliance framework tables."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TIMESTAMP

from app.db.database import Base

# Aliased for readability; on Postgres this renders as TIMESTAMPTZ.
# (The PG dialect never exported a `TIMESTAMPTZ` symbol — that's just SQL
# syntax. The correct way to get a tz-aware column is `TIMESTAMP(timezone=True)`.)
TIMESTAMPTZ = TIMESTAMP(timezone=True)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False, default=_utcnow)


class ComplianceEvidence(Base):
    __tablename__ = "compliance_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="auto")
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="collected")
    collected_at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False, default=_utcnow)
    collected_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMPTZ, nullable=False, default=_utcnow)
