"""AuditLog ORM model — append-only event store."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AuditLog(Base):
    """Immutable audit event.  Never update or delete rows; enforced by DB trigger."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(200), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    changes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    # Tamper-evident hash chain. ``prev_hash`` is the ``entry_hash`` of
    # the previous audit row for the same tenant; ``entry_hash`` is a
    # sha256 digest over the canonical serialization of this row mixed
    # with ``prev_hash``. See migration 043_audit_log_hash_chain.sql
    # and ``app.services.audit_hash`` for the canonical algorithm.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
