"""Operator organisations: the parent concept above tenants (migration 058).

`tenants.parent_tenant_id` (migration 012) makes the managing provider a
tenant, which is enough to draw a tree and not enough to run a managed
service. These four tables separate the operator from the boundary:

- :class:`Organization` is the provider itself.
- :class:`OrganizationMember` says who belongs to it, with what authority.
- :class:`OrganizationTenant` is the managed portfolio.
- :class:`OrganizationMemberTenant` scopes an individual principal to a
  subset of that portfolio.

The composite foreign keys on the last table are load-bearing and are
declared here as well as in the migration so a test running against SQLite
gets the same rejection Postgres gives: a grant can only name a tenant the
organisation actually manages.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

# Authority to act on a scoped tenant. `viewer` reads; the rest may act.
ORG_ROLES: tuple[str, ...] = ("owner", "admin", "operator", "viewer")

# Roles whose reach is the whole portfolio. Everyone else reaches only what
# `organization_member_tenants` grants them — and nothing when that is empty.
PORTFOLIO_WIDE_ROLES: frozenset[str] = frozenset({"owner", "admin"})

# Roles permitted to perform actions rather than only read.
ACTING_ROLES: frozenset[str] = frozenset({"owner", "admin", "operator"})

# Roles permitted to change the organisation itself: membership, portfolio,
# per-member grants.
ADMINISTERING_ROLES: frozenset[str] = frozenset({"owner", "admin"})


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False, default="mssp")
    # The tenant the operator's own staff sign in to. Cascades on delete: an
    # erased home tenant takes the organisation with it, and leaves the
    # managed customers standing as unclaimed tenants.
    home_tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    org_role: Mapped[str] = mapped_column(Text, nullable=False, default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (UniqueConstraint("org_id", "user_id", name="organization_members_org_id_user_id_key"),)


class OrganizationTenant(Base):
    __tablename__ = "organization_tenants"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True, index=True)
    relationship: Mapped[str] = mapped_column(Text, nullable=False, default="managed")
    onboarded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    onboarded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # One managing organisation per tenant, so "whose portfolio is this in"
    # has exactly one answer and two providers cannot both claim a customer.
    __table_args__ = (UniqueConstraint("tenant_id", name="organization_tenants_tenant_id_key"),)


class OrganizationMemberTenant(Base):
    """Which managed tenants one principal may reach.

    Enforced by the database rather than by the code path that writes it: the
    composite keys mean a grant cannot name a tenant outside the portfolio,
    and a tenant leaving the portfolio takes its grants with it.
    """

    __tablename__ = "organization_member_tenants"

    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    __table_args__ = (
        PrimaryKeyConstraint("org_id", "user_id", "tenant_id"),
        ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["organization_members.org_id", "organization_members.user_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["org_id", "tenant_id"],
            ["organization_tenants.org_id", "organization_tenants.tenant_id"],
            ondelete="CASCADE",
        ),
    )
