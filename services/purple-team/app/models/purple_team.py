"""SQLAlchemy ORM models for the Purple Team service."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AtomicTest(Base):
    """Represents an Atomic Red Team test that has been imported/tracked."""

    __tablename__ = "purple_team_atomic_tests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # ATT&CK reference
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(256), nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)

    # Atomic test details
    test_guid: Mapped[str] = mapped_column(String(64), nullable=False)
    test_name: Mapped[str] = mapped_column(String(512), nullable=False)
    test_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)  # windows/linux/macos
    executor: Mapped[str] = mapped_column(String(32), nullable=False)  # command_prompt/sh/powershell

    # Input arguments (YAML-parsed)
    input_arguments: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")

    # Raw YAML content
    raw_yaml: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TestExecution(Base):
    """Records a single execution of an atomic test or Caldera operation."""

    __tablename__ = "purple_team_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # What was executed
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # "atomic" | "caldera"
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    test_name: Mapped[str] = mapped_column(String(512), nullable=False)
    test_guid: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Caldera operation ID (if applicable)
    caldera_operation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Execution state
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="pending"
    )  # pending | running | success | failed | error

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Executor output
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Detection outcome
    detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detection_latency_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Who ran it
    executed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TabletopSession(Base):
    """A tabletop exercise session."""

    __tablename__ = "purple_team_tabletop_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scenario: Mapped[str] = mapped_column(Text, nullable=False)  # freeform scenario text

    # ATT&CK techniques this exercise covers
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")

    # Structured findings from the discussion
    findings: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="active"
    )  # active | completed | archived

    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
