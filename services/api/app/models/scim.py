"""SCIM 2.0 provisioning ORM models (migration 071).

Kept deliberately thin. The interesting decisions are recorded in
``services/api/migrations/071_scim_provisioning.sql`` next to the constraints
that enforce them; repeating them here would give a reader two places to
disagree with each other.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ScimToken(Base):
    """A per-organisation SCIM bearer credential.

    The raw secret exists only in the mint response. This row holds a
    SHA-256 digest for lookup and a short prefix for display.
    """

    __tablename__ = "aisoc_scim_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    token_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("aisoc_scim_tokens.id", ondelete="SET NULL"), nullable=True)

    def is_usable(self, *, now: datetime | None = None) -> bool:
        """Whether this credential may authenticate a request right now.

        Revocation wins over expiry and both win over existence, so a caller
        never has to remember the order.
        """
        moment = now or datetime.now(UTC)
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= moment)


class ScimUser(Base):
    """SCIM metadata for a provisioned principal, beside ``users``."""

    __tablename__ = "aisoc_scim_users"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    given_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    family_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("aisoc_scim_tokens.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )


class ScimGroup(Base):
    """A directory group pushed by the identity provider.

    ``mapped_role`` is NULL for a group whose name does not resolve to a role
    this platform enforces. Such a group records membership and confers
    nothing, so an unrecognised directory group is powerless rather than
    unconstrained.
    """

    __tablename__ = "aisoc_scim_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    mapped_role: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("aisoc_scim_tokens.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )


class ScimGroupMember(Base):
    """Membership of one principal in one pushed group."""

    __tablename__ = "aisoc_scim_group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_scim_groups.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))


__all__ = ["ScimGroup", "ScimGroupMember", "ScimToken", "ScimUser"]
