"""SQLAlchemy ORM models for the persistent agent decision ledger (Phase 1A).

Three tables back the ledger:

* ``investigation_runs``       - one row per investigation kicked off by an agent
* ``investigation_events``     - append-only sequence of agent steps (LLM calls,
                                 tool calls, decisions, reasons, errors)
* ``investigation_artifacts``  - large blobs (full prompts, responses, reports)

The schema is also defined in ``services/api/migrations/008_investigation_ledger.sql``
which is the canonical version for production: it adds Row-Level Security and an
immutability trigger that this ORM definition cannot express. Dev environments
auto-create the tables via ``Base.metadata.create_all``; the SQL migration
applies the security guardrails on top.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class InvestigationRun(Base):
    """One row per investigation. Status transitions: running -> completed|failed."""

    __tablename__ = "investigation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    alert_summary: Mapped[Optional[str]] = mapped_column(Text)
    raw_alert: Mapped[Optional[dict]] = mapped_column(JSONB)
    model_used: Mapped[Optional[str]] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    error: Mapped[Optional[str]] = mapped_column(Text)
    total_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_cost_usd: Mapped[float] = mapped_column(Numeric(10, 4), nullable=False, default=0)
    iterations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    events: Mapped[list["InvestigationEvent"]] = relationship(
        "InvestigationEvent",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="InvestigationEvent.seq",
    )
    artifacts: Mapped[list["InvestigationArtifact"]] = relationship(
        "InvestigationArtifact",
        back_populates="run",
        cascade="all, delete-orphan",
    )


class InvestigationEvent(Base):
    """One row per agent step. Append-only - the SQL migration enforces immutability.

    ``kind`` mirrors the values of ``StepKind`` in
    ``services/agents/app/investigator/state.py``.
    """

    __tablename__ = "investigation_events"
    __table_args__ = (UniqueConstraint("run_id", "seq", name="uq_inv_events_run_seq"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    agent: Mapped[str] = mapped_column(String(80), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[Optional[dict]] = mapped_column(JSONB)
    input_hash: Mapped[Optional[str]] = mapped_column(String(64))
    output_hash: Mapped[Optional[str]] = mapped_column(String(64))
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    run: Mapped[InvestigationRun] = relationship("InvestigationRun", back_populates="events")
    artifacts: Mapped[list["InvestigationArtifact"]] = relationship(
        "InvestigationArtifact",
        back_populates="event",
    )


class InvestigationArtifact(Base):
    """Large blobs attached to a run or event: prompts, responses, full reports."""

    __tablename__ = "investigation_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation_events.id", ondelete="CASCADE"),
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    content: Mapped[Optional[str]] = mapped_column(Text)
    blob_ref: Mapped[Optional[str]] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    run: Mapped[InvestigationRun] = relationship("InvestigationRun", back_populates="artifacts")
    event: Mapped[Optional[InvestigationEvent]] = relationship(
        "InvestigationEvent", back_populates="artifacts"
    )
