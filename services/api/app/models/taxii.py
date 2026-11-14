"""TAXII 2.1 collection ORM model (depth plan 4.2).

A collection is a filtered view over ``threat_intel_iocs``, never a copy of
it: an indicator edited in the console must not have to be edited twice,
and the version a partner pulls must not drift from the version this
tenant's own detections run on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TaxiiCollection(Base):
    __tablename__ = "taxii_collections"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    alias: Mapped[str | None] = mapped_column(String(100), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    can_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Always false. The server refuses inbound writes; the column exists
    #: because the specification has it and clients read it to decide
    #: whether to offer an upload.
    can_write: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ioc_filter: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
