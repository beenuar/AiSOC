"""SQLAlchemy ORM models for the Honeytokens service."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Honeytoken(Base):
    """A deployed honeytoken (credential, URL, file, API key, …)."""

    __tablename__ = "honeytokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # Human-readable name / description
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Type: "aws_key", "url", "file", "db_credential", "email", "dns", "custom"
    token_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # The actual token value (opaque string / URL / ARN, etc.)
    token_value: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional metadata: where deployed, owner, tags
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, server_default="{}")

    # Lifecycle
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active")
    # active | triggered | expired | revoked

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Who created it
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class HoneytokenTrigger(Base):
    """An access event that triggered a honeytoken."""

    __tablename__ = "honeytoken_triggers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    honeytoken_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("honeytokens.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # Contextual information from the incoming webhook
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_headers: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    request_body: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")

    # Geo / threat intel (enriched async)
    geo_country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Alert state
    alert_sent: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    alert_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
