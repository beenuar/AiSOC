"""Published (public) investigation-replay snapshots — v8 W3.

A published replay is an **immutable, redacted** snapshot of an investigation
ledger, served without authentication at ``tryaisoc.com/r/<slug>`` so analysts
can share how the agent reasoned through a case.

Design decisions:

* **Immutable.** Once published, the snapshot never changes. A re-publish mints
  a new slug. The SQL migration adds an UPDATE-blocking trigger; the app layer
  never issues UPDATEs (view-count is a separate best-effort increment column
  that the trigger explicitly allows).
* **Redacted at publish time.** Only the already-redacted ``snapshot`` JSON is
  stored — the original entity values and the alias→original map are *never*
  persisted. Redaction runs in ``app/services/replay_redaction.py`` using the
  vendored :class:`Pseudonymizer`, and the publisher reviews the alias map in a
  pre-publish diff before confirming.
* **Public-by-design, so no RLS.** Unlike every other tenant table, this one is
  intentionally readable without a tenant context (that's the whole point). The
  data it holds is post-redaction and non-identifying. Writes are still scoped
  to the publishing tenant in the application layer, and ``tenant_id`` is
  retained purely for the publisher's own audit / unpublish path.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class PublishedReplay(Base):
    """One row per published, redacted investigation replay."""

    __tablename__ = "published_replays"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # URL-safe short slug served at /r/<slug>. Unique across all tenants.
    slug: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    # The source run. No FK cascade delete — a published replay is a durable
    # artifact that must survive the run being pruned.
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(String(200), nullable=False)
    # Redacted, display-safe title (e.g. "Ransomware on HOST_1").
    title: Mapped[str] = mapped_column(Text, nullable=False)
    # The immutable, fully-redacted replay snapshot (verdict, techniques,
    # elapsed, step count, evidence cards, attack-graph nodes/edges).
    snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    published_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
