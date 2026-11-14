"""ORM model for semantic memory items.

Depth plan 9.2 (parity 6.5); migration ``105_semantic_memory.sql`` carries
the reasoning for each column and for the conflict state machine.

The short version of why this table exists beside Qdrant: a vector payload
cannot hold a foreign key, a CHECK or a row-level policy, and all three are
load-bearing here. The vectors are derivable by re-embedding from these rows,
so this is the store of record and Qdrant is an index over it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: What a memory item can be about.
MEMORY_KINDS: tuple[str, ...] = ("case", "runbook", "memory")

#: Recall returns ``in_use`` only. ``conflict`` withholds *both* sides of a
#: disagreement rather than preferring the newer one, because resolving by
#: timestamp is wrong in exactly the case this feature exists for: an analyst
#: corrects a bad entry and a job re-ingests the bad one an hour later.
MEMORY_STATES: tuple[str, ...] = ("in_use", "conflict", "not_in_use")


class MemoryItem(Base):
    """One attributable claim the agent may be told, and why it may be trusted."""

    __tablename__ = "aisoc_memory_items"
    __table_args__ = (
        CheckConstraint("kind IN ('case', 'runbook', 'memory')", name="aisoc_memory_items_kind_check"),
        CheckConstraint("scope IN ('tenant', 'global')", name="aisoc_memory_items_scope_check"),
        CheckConstraint(
            "state IN ('in_use', 'conflict', 'not_in_use')",
            name="aisoc_memory_items_state_check",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    #: What the item is about. Two items with the same subject make claims
    #: about the same thing, which is what makes a contradiction detectable.
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    source_ref: Mapped[str] = mapped_column(Text, nullable=False, default="")
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)

    author: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(Text, nullable=False, default="analyst")
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="tenant")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    state: Mapped[str] = mapped_column(Text, nullable=False, default="in_use")
    conflicts_with: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("aisoc_memory_items.id", ondelete="SET NULL"), nullable=True
    )
    state_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Which model produced the vector, and when. Both nullable, and the two
    #: NULL cases are different: never embedded, versus embedded by a model
    #: nobody is running any more. The status route renders them apart.
    embedding_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
