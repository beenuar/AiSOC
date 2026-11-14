"""Tenant-skill ORM models.

Gap-closure Phase 6.1 and 6.2. Backs ``/api/v1/tenant-skills`` and migration
``070_tenant_skills.sql``; the migration header carries the reasoning for each
column and constraint.

The short version: a skill steers an agent's verdict, so it is versioned like
a detection rule rather than stored like a preference. :class:`TenantSkill` is
the current state of one skill and :class:`TenantSkillVersion` is the
append-only history that makes the ``(skill_id, version)`` pair an
investigation records resolvable back to the text that was in force.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: The lifecycle the plan specifies, plus ``retired`` for a skill taken out of
#: service without deleting its history. Mirrored by a CHECK on the column so
#: a row cannot reach a state the application does not know about.
SKILL_STATUSES: tuple[str, ...] = ("draft", "backtested", "active", "retired")

DRAFT = "draft"
BACKTESTED = "backtested"
ACTIVE = "active"
RETIRED = "retired"


class TenantSkill(Base):
    """One tenant-authored investigation skill, current state."""

    __tablename__ = "aisoc_tenant_skills"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    skill_id: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=DRAFT)

    name: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    body: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    source_yaml: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # The "after" run and the "before" run. Both, because a figure with no
    # baseline beside it is not a comparison.
    #
    # No ``ForeignKey`` here, and the migration does declare one. The
    # difference is not drift: ``aisoc_replay_evaluations`` is written and read
    # entirely through raw SQL in ``app.services.replay_evaluation.store`` and
    # has no mapped class, so a ForeignKey naming it cannot resolve against
    # ``Base.metadata`` at all. Declaring one here fails table creation rather
    # than enforcing anything. The constraint is real in Postgres, where it is
    # enforced, and the migration is its authority.
    backtest_evaluation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    backtest_baseline_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    backtest_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class TenantSkillVersion(Base):
    """One immutable version of a skill.

    Written on every content change and stamped on activation and retirement.
    Nothing here is edited: an activation stamp is a fact about the version
    rather than a change to it.
    """

    __tablename__ = "aisoc_tenant_skill_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    skill_row_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("aisoc_tenant_skills.id", ondelete="CASCADE"),
        nullable=False,
    )

    skill_id: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    name: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    body: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    source_yaml: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Unmapped target, same as on the live row above.
    backtest_evaluation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    backtest_baseline_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    authored_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    authored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


__all__ = [
    "ACTIVE",
    "BACKTESTED",
    "DRAFT",
    "RETIRED",
    "SKILL_STATUSES",
    "TenantSkill",
    "TenantSkillVersion",
]
