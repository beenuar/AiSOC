"""Readers for the three tables migration 087 created.

``087_enterprise_iam.sql`` created ``permission_conditions``,
``privilege_grants`` and ``workload_identities`` and shipped no reader for
any of them — the CHANGELOG said so in the same release that announced
them, and ``FIX_PASS_PROGRESS.md`` retracted the claim. These models are
half of the repair; the other half is ``app.core.permission_cache``, which
resolves them onto the principal, and ``CurrentUser.require_permission``,
which is the one place they are applied.

Each model maps a table that already exists. Nothing here creates schema,
so the column set is dictated by the migration rather than the other way
round.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class PermissionCondition(Base):
    """An attribute condition that narrows one permission for one tenant.

    Conditions never grant. ``app.security.abac.evaluate_conditions`` can
    only turn an allow into a deny, which is what keeps this one
    authorization system rather than two that can disagree.
    """

    __tablename__ = "permission_conditions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)

    #: The permission string this constrains, e.g. ``cases:write``. A row
    #: applies to exactly this permission: an evaluator that applied every
    #: row to every check would turn one narrow rule into a tenant outage.
    permission: Mapped[str] = mapped_column(Text, nullable=False)

    #: Optional role filter. ``NULL`` means every role in the tenant.
    role: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: ``{"operator": ..., "value": ...}``. Declarative so the evaluator is
    #: one audited function rather than scattered checks, and so a condition
    #: can be added from the console without a deploy.
    condition: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class PrivilegeGrant(Base):
    """A time-boxed elevation: these permissions, this user, until then.

    Permissions rather than a role, because elevating to ``admin`` to
    isolate one host confers the wildcard — the opposite of least privilege.

    ``expires_at`` is ``NOT NULL`` in the migration so a grant cannot become
    permanent by omission, which is how every JIT system decays into
    standing access.
    """

    __tablename__ = "privilege_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    permissions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    #: Why, in the requester's words. An elevation nobody has to justify is
    #: a role held permanently with extra steps.
    justification: Mapped[str] = mapped_column(Text, nullable=False)

    #: Who approved. ``NULL`` means the request is still pending — nothing
    #: is conferred until this is set, which is what makes approval a gate
    #: rather than a record.
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: What the elevation was for, so a review can ask whether it was used
    #: for that.
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class WorkloadIdentity(Base):
    """A per-service credential, replacing the single shared service token.

    ``AISOC_SERVICE_TOKEN`` is one string every internal caller presents. It
    cannot be attributed — the audit trail says "a service" did it — it
    cannot be rotated without restarting everything at once, and it cannot
    be scoped, so the agents worker presents the same credential as the
    ingest pipeline.

    Deployment-wide rather than tenant-scoped: a service authenticates
    before any tenant is known, and names the tenant it acts for on a
    header. That split is deliberate and is why this table has no
    ``tenant_id`` and no row-level security policy.
    """

    __tablename__ = "workload_identities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    #: Which service this belongs to, so an audit row can name ``agents``
    #: rather than "a service".
    service: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: What this workload may do. The ingest pipeline does not need to read
    #: the action registry, and the shared token could not express that.
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)

    secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    secret_prefix: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    #: Rotation without downtime needs two live secrets at once. The
    #: previous one keeps working until ``previous_expires_at``, so callers
    #: roll over on their own schedule instead of all at the same instant.
    previous_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


__all__ = ["PermissionCondition", "PrivilegeGrant", "WorkloadIdentity"]
