"""ORM model for FIM (File Integrity Monitoring) events.

Populated by the log forwarder when osquery file_events rows arrive via the
TLS log endpoint.  The ``/v1/fim/*`` API queries this table.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


class FimEvent(Base):
    """One osquery file_events row, normalised for the FIM API."""

    __tablename__ = "fim_event"
    __table_args__ = (
        Index("ix_fim_event_tenant_time", "tenant_id", "event_time"),
        Index("ix_fim_event_action", "action"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    node_key: Mapped[str] = mapped_column(String(128), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # File metadata
    target_path: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # CREATED, DELETED, UPDATED, ATTRIBUTES_MODIFIED
    md5: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Process context
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Timing
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
