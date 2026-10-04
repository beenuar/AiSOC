"""Case management ORM models."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Case(Base):
    # Gap-closure wave 1. This pointed at `cases` while the console wrote
    # `aisoc_cases`, and the two never synchronised — so MTTR, the case
    # counts, the executive digest and the MSSP portfolio were all blind
    # to every case an analyst created. Migration 083 moved the rows and
    # renamed the old table to `cases_pre_consolidation`.
    __tablename__ = "aisoc_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)

    # Core
    case_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    case_type: Mapped[str] = mapped_column(String(50), default="security_incident")

    # MITRE
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Assignment
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # SLA
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(default=False)

    # Linked data
    # `uuid[]`, not JSONB: that is what the surviving table declares, and
    # the ORM matching the column beats the column matching the ORM.
    alert_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    ioc_ids: Mapped[list] = mapped_column(JSONB, default=list)
    artifact_ids: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)

    # External tickets
    ticket_refs: Mapped[list] = mapped_column(JSONB, default=list)

    # Metadata
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)

    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    tasks: Mapped[list["CaseTask"]] = relationship("CaseTask", back_populates="case", lazy="noload")
    timeline: Mapped[list["CaseTimeline"]] = relationship("CaseTimeline", back_populates="case", lazy="noload")


class CaseTask(Base):
    """A task on a case.

    The table is `aisoc_case_tasks`. This model named `case_tasks`, which no
    migration creates, so every write through it raised
    `UndefinedTableError` -- on the demo seed and on the KEV exposure path,
    both of which are reached only with data that the rest of the product had
    no way to produce. Fix-pass item 5.2 found it by creating that data.

    Four of the declared columns did not exist either. `description`,
    `completed_at` and a uuid `assigned_to_id` are gone; the real table stores
    the assignee as text and the due date as `due_at`, and carries
    `depends_on_task_id` and `blocked_reason`, which the model never had.
    Attribute names that call sites already use are preserved by mapping them
    onto the real column.
    """

    __tablename__ = "aisoc_case_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_cases.id"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    #: `todo` / `in_progress` / `done` -- what `aisoc_case_tasks_status_check`
    #: allows. The model defaulted to "pending", which the constraint rejects,
    #: so every insert through it would have failed even once the table name
    #: was right.
    status: Mapped[str] = mapped_column(Text, default="todo", nullable=False)
    assignee: Mapped[str | None] = mapped_column(Text, nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    depends_on_task_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    blocked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )

    case: Mapped["Case"] = relationship("Case", back_populates="tasks")


class CaseTimeline(Base):
    __tablename__ = "case_timeline_events"
    """Same defect as `CaseTask` above: this named `case_timeline`, a table no
    migration creates. The real one is `case_timeline_events`, and it stores
    the text as `summary`, the payload as `detail`, and the actor as an
    `actor_id` plus an `actor_type` rather than a `user_id` and an
    `is_automated` flag.

    The Python attribute names the three call sites use are kept and mapped
    onto the real columns; `is_automated` becomes a property over `actor_type`
    because the two carry the same fact and storing both invites them to
    disagree."""

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_cases.id"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # comment/status_change/assignment/etc
    content: Mapped[str] = mapped_column("summary", Text, nullable=False)
    event_metadata: Mapped[dict | None] = mapped_column("detail", JSONB, default=dict, nullable=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column("actor_id", UUID(as_uuid=True), nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)

    @property
    def is_automated(self) -> bool:
        """Whether a machine wrote this event.

        Derived rather than stored: the real table records `actor_type`, and a
        second column meaning the same thing is a column that can disagree
        with it."""
        return (self.actor_type or "").lower() in {"system", "agent", "automation"}

    case: Mapped["Case"] = relationship("Case", back_populates="timeline")
