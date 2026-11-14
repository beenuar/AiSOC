"""ORM model for an enrolled osquery node."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


class OsqueryNode(Base):
    """Represents an osqueryd agent enrolled with the AiSOC TLS service."""

    __tablename__ = "osquery_node"
    __table_args__ = (UniqueConstraint("host_identifier", "tenant_id", name="uq_node_host_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    host_details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
