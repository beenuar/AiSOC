"""ORM model for distributed (ad-hoc) osquery queries."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


class OsqueryDistributedQuery(Base):
    """Tracks a per-node distributed query from enqueue through completion."""

    __tablename__ = "osquery_distributed_query"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(Integer, ForeignKey("osquery_node.id", ondelete="CASCADE"), nullable=False)
    query_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    query_text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    results_json: Mapped[list | None] = mapped_column(JSON, nullable=True)
