"""Saved natural-language hunts ORM model — Track 3, T3.4 (`/hunt` NL surface).

A *saved hunt* is the analyst's stored natural-language hunt question plus the
translator's structured output. The `/hunt` page lets analysts ask questions
like "Did we get any new attacks from Iran?", review the parsed query, and
save the prompt for re-use or scheduled execution.

Why a separate table from ``aisoc_hunts`` (the hypothesis-driven hunt
workbench)? The two surfaces serve different jobs:

* ``aisoc_hunts`` is detection-engineering authored: a senior analyst
  hand-writes a hypothesis, attaches multi-platform queries (ES|QL/SPL/KQL),
  and tracks runs + findings. Heavyweight, version-controlled.

* ``aisoc_saved_hunts`` (this table) is operator-authored: a tier-1 analyst
  types a question in plain English on the ``/hunt`` page, the platform
  translates it, and the analyst clicks Save. Lightweight, throwaway-friendly,
  optionally scheduled.

Tenant isolation is enforced via Row-Level Security in
``services/api/migrations/040_saved_hunts.sql``. User scoping is enforced in
the API layer (saved hunts are visible to every analyst in the tenant — they
are a shared knowledge surface, unlike ``saved_views`` which are personal).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class SavedHunt(Base):
    """A stored natural-language hunt question + translator output."""

    __tablename__ = "aisoc_saved_hunts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Author of the hunt. Saved hunts are tenant-shared (not user-private),
    # so this is metadata only — used for the "saved by" badge in the UI.
    # Nullable so demo-mode / system-seeded hunts can omit it.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Human-readable label rendered in the saved-hunts list.
    name: Mapped[str] = mapped_column(String(160), nullable=False)

    # The original NL question. Kept verbatim so we can re-translate when the
    # translator improves (and re-show the prompt to the user).
    nl_query: Mapped[str] = mapped_column(Text, nullable=False)

    # Structured translator output — opaque JSON ``{esql, kql, spl, explanation,
    # intents}``. The backend never inspects the contents; the translator owns
    # the schema. Re-running a hunt re-translates so this can drift safely.
    translated_query: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # Preferred dialect at save time — ``esql | kql | spl``. The translator
    # always emits all three; this is just the one the analyst was looking at
    # when they hit Save, so the UI can re-open in the same view.
    language: Mapped[str] = mapped_column(String(16), nullable=False, default="esql")

    # Optional cron schedule, e.g. ``"0 */6 * * *"``. NULL → manual run only.
    # The hunt scheduler worker (``services/api/app/workers/hunt_scheduler.py``)
    # picks up rows where this is non-null and fires the hunt on cadence.
    schedule: Mapped[str | None] = mapped_column(String(120), nullable=True, default=None)

    # Last time the scheduler executed this hunt (or the analyst clicked
    # Re-run). Used by the scheduler to decide whether the cron interval has
    # elapsed since the previous run.
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (
        # Two analysts can't pick the same name in the same tenant — keeps the
        # saved-hunts list searchable. We intentionally don't scope this to
        # ``created_by`` so a teammate can find "Iran inbound" without
        # guessing who saved it.
        UniqueConstraint("tenant_id", "name", name="aisoc_saved_hunts_unique_name"),
        Index("aisoc_saved_hunts_tenant_idx", "tenant_id"),
        # Hot path for the scheduler: "any rows in this tenant with a cron
        # set whose last_run_at is older than the schedule cadence?".
        Index(
            "aisoc_saved_hunts_scheduled_idx",
            "tenant_id",
            "schedule",
            postgresql_where=text("schedule IS NOT NULL"),
        ),
    )
