"""Cold-tier lake query jobs (depth plan 4.3).

A job is a lake query that outlives the request that started it, because
reading the cold volume is not a thing that reliably finishes inside the
published 30-second synchronous bound.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: The lifecycle. `queued` is the only state a runner may claim, and a
#: terminal state is never left.
JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})


class LakeQueryJob(Base):
    __tablename__ = "lake_query_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    submitted_email: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: The rewritten, tenant-scoped SQL — never the caller's original,
    #: which carries no tenant predicate.
    rewritten_sql: Mapped[str] = mapped_column(Text, nullable=False)
    row_cap: Mapped[int] = mapped_column(Integer, nullable=False)
    referenced_tables: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    query_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")

    #: As written at submit time and never recomputed: it is the number
    #: the analyst agreed to before the scan started.
    estimate: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    rows_read: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_read: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_rows_approx: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Nullable on purpose. NULL means unknown, never zero.
    progress_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)

    result_columns: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    result_rows: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
