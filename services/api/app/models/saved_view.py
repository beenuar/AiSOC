"""Per-user saved views ORM model — Workstream F3 (analyst quality-of-life).

A *saved view* is the analyst's stored preset for a list page. Three
list pages currently use this: Alerts, Cases / Investigations, and
Playbooks. Each preset is a `(filters, columns)` pair — opaque JSON
blobs whose schema is owned entirely by the frontend. The API never
inspects the contents; it round-trips them as JSONB.

Why "opaque"? The list pages keep evolving (new filter chips, new
column ids), and a strongly-typed backend schema would force a
migration every time a filter is added. Instead the frontend renders
saved views best-effort: unknown filter keys are dropped, missing keys
fall back to defaults. This is the same trade-off Sentry/Linear/Jira
make for their saved views — flexibility wins over server-side
validation for a per-user preference store.

Tenant isolation is enforced via Row-Level Security in
``services/api/migrations/037_saved_views.sql``. User isolation is
enforced in the API layer (every query is scoped
``WHERE user_id = current_user.id``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class SavedView(Base):
    """Per-user filter+column preset for an AiSOC list page."""

    __tablename__ = "saved_views"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Which list page this preset belongs to. One of:
    # ``alerts | cases | investigations | playbooks``. Stored as a
    # short string instead of an enum so adding a new page in v1.1
    # is a code-only change.
    view_type: Mapped[str] = mapped_column(String(40), nullable=False)

    # Human-readable label rendered as a pill in the saved-views bar.
    name: Mapped[str] = mapped_column(String(120), nullable=False)

    # Opaque JSON matching the list page's filter shape. The backend
    # never inspects the contents.
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))

    # Optional ordered list of column ids/widths. NULL means "use the
    # page default column set" — saves a row from carrying redundant
    # default state.
    columns: Mapped[list | dict | None] = mapped_column(JSONB, nullable=True, default=None)

    # Exactly one default per (tenant, user, view_type) — the partial
    # unique index in the migration enforces this at the DB layer so
    # we don't have to do a transactional toggle in the API.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))

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
        UniqueConstraint(
            "tenant_id",
            "user_id",
            "view_type",
            "name",
            name="saved_views_unique_name",
        ),
        Index(
            "saved_views_owner_type_idx",
            "tenant_id",
            "user_id",
            "view_type",
        ),
        # Partial unique index — at most one default per
        # (tenant, user, view_type). Mirrors the migration.
        Index(
            "saved_views_one_default_idx",
            "tenant_id",
            "user_id",
            "view_type",
            unique=True,
            postgresql_where=text("is_default"),
        ),
    )
