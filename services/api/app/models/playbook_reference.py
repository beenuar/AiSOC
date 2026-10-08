"""ORM model for the named handles a playbook step addresses.

See ``migrations/095_playbook_references.sql`` for why names and not hosts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: Kinds a reference can take. Mirrors the CHECK constraint in migration 095;
#: a value here that the constraint rejects is an insert that fails at the
#: database rather than at validation, which is a worse error for an operator.
REFERENCE_KINDS: frozenset[str] = frozenset({"url", "headers", "webhook", "routing_key", "smtp"})

#: Channels a `notify` reference can serve. Empty for `url` and `headers`.
REFERENCE_CHANNELS: frozenset[str] = frozenset({"", "slack", "teams", "email", "pagerduty"})


class PlaybookReference(Base):
    __tablename__ = "aisoc_playbook_references"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    connector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("connectors.id"), nullable=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: A ``vault:`` token, never plaintext. Decrypted only inside
    #: ``playbook_references.resolve`` on the way to one step.
    secret_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: FALSE on creation. Existing is not the same as usable — see the
    #: migration's "off by default" note.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    created_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
