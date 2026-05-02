"""Detection Rule ORM model."""
import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )  # NULL = platform-wide rule
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_language: Mapped[str] = mapped_column(String(30), nullable=False)  # sigma/yara/kql/eql/etc
    rule_body: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="testing", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100

    # MITRE ATT&CK
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # False positive management
    fp_rate: Mapped[float] = mapped_column(default=0.0)
    suppression_config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Threshold
    threshold_config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Stats
    total_hits: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tags: Mapped[list] = mapped_column(JSONB, default=list)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)  # Platform-provided vs custom
    version: Mapped[int] = mapped_column(Integer, default=1)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
