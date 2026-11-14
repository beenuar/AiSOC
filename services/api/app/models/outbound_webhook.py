"""ORM models for outbound event webhooks and their delivery attempts.

See ``migrations/097_outbound_webhooks.sql`` for why the retry queue and
the dead-letter list are one table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ARRAY, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class OutboundWebhook(Base):
    __tablename__ = "aisoc_outbound_webhooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    #: Empty means every event — see `outbound_webhooks.enqueue_event`.
    event_types: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    #: A ``vault:`` token. Never returned by the API: rotation issues a new
    #: secret rather than showing the old one, the same rule the connector
    #: wizard follows.
    secret: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    created_by: Mapped[str] = mapped_column(Text, nullable=False, default="")


class OutboundDelivery(Base):
    __tablename__ = "aisoc_outbound_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    webhook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_outbound_webhooks.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    #: The body the first attempt sent, stored rather than recomputed: the
    #: signature covers the body, so re-serialising between attempts would
    #: produce two differently-signed messages for one event.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: NULL once terminal, so the worker's "what is due" query cannot pick
    #: up something it has finished with.
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
