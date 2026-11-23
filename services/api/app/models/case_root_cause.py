"""ORM mirrors of migration 165's root-cause tables.

The api service applies the SQL chain (``make upgrade`` / fresh install), so
the migration is the load-bearing definition; these models keep the ORM
parity gate's picture complete and give typed access to readers that prefer
the ORM. The write path uses explicit SQL with tenant predicates — the
cases-family convention — in ``app/services/case_root_cause.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CaseRootCauseRecord(Base):
    __tablename__ = "case_root_cause_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_cases.id"), nullable=False)
    #: determined | hypothesis | undetermined — the DB CHECK carries the same
    #: vocabulary, and the service layer enforces the cross-table rules
    #: (determined requires a citation; undetermined names missing telemetry).
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    missing_telemetry: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseRootCauseCitation(Base):
    __tablename__ = "case_root_cause_citations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    record_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("case_root_cause_records.id"), nullable=False)
    #: The Investigation Ledger address: ``investigation_events`` is
    #: ``UNIQUE (run_id, seq)``; the pair is the citation, never the row UUID.
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
