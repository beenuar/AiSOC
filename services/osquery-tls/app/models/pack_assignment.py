"""ORM model for tenant → osquery pack assignments."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


class OsqueryPackAssignment(Base):
    """Maps a tenant to a named osquery pack (managed in PR5)."""

    __tablename__ = "osquery_pack_assignment"
    __table_args__ = (UniqueConstraint("tenant_id", "pack_id", name="uq_pack_assignment"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
