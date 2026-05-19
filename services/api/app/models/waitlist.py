"""Waitlist ORM model — T6.1 (`tryaisoc.com` managed beta).

Persists every signup that lands on ``/waitlist`` so the support team can:

  1. Triage demand from the admin console (``/admin/waitlist``).
  2. Promote an approved entry into a real tenant via the
     :mod:`app.services.tenant_provision` pipeline (`new` → `contacted`
     → `onboarded`) or close it out (`declined`).
  3. Audit who reached out, when, and what stack they're coming from.

Schema notes
------------

* ``email`` is **case-insensitively unique**. We normalise on write
  (``.strip().lower()``) so an analyst who signs up as ``Alice@Acme.io``
  and again later as ``alice@acme.io`` doesn't get two rows.
* ``soc_stack`` is stored as a JSONB list — the form sends a multiselect
  ('siem:splunk', 'edr:crowdstrike', etc.); the column accepts any
  string-list shape so we can broaden the form's vocabulary without a
  schema migration.
* ``status`` is a free-form string with a CHECK constraint at the SQL
  layer (see ``migrations/042_waitlist.sql``). The four-state ladder is
  ``new → contacted → onboarded → declined``. ``declined`` is terminal,
  ``onboarded`` is terminal-but-with-tenant.
* No PII is encrypted at rest in v1 — every column is something the
  signup form already collected in plaintext. If we ever start storing
  freeform notes from the support team, those should land in a separate
  ``waitlist_notes`` table so the row level audit is clean.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

# Status ladder. Kept in sync with the CHECK constraint in
# ``migrations/042_waitlist.sql`` — adding a new state requires both an
# entry here AND a migration to widen the constraint.
WAITLIST_STATUS_NEW: str = "new"
WAITLIST_STATUS_CONTACTED: str = "contacted"
WAITLIST_STATUS_ONBOARDED: str = "onboarded"
WAITLIST_STATUS_DECLINED: str = "declined"

ALLOWED_WAITLIST_STATUSES: frozenset[str] = frozenset(
    {
        WAITLIST_STATUS_NEW,
        WAITLIST_STATUS_CONTACTED,
        WAITLIST_STATUS_ONBOARDED,
        WAITLIST_STATUS_DECLINED,
    }
)


class WaitlistEntry(Base):
    __tablename__ = "aisoc_waitlist_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    company: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(100), nullable=False)
    soc_stack: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    motivation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=WAITLIST_STATUS_NEW, nullable=False, index=True)
    # Optional FK once tenant_provision lands — populated when the row
    # crosses into ``onboarded``. Stored as a plain UUID rather than a
    # ForeignKey here so the import graph stays free of circular deps
    # with the tenant model; the migration adds the actual FK at the
    # database layer.
    provisioned_tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    contacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    onboarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
