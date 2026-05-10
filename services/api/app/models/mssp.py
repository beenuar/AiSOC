"""MSSP parent-tenant console ORM models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class MSSPTenantNote(Base):
    __tablename__ = "mssp_tenant_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    child_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class MSSPDelegation(Base):
    __tablename__ = "mssp_delegations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    child_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    granted_role: Mapped[str] = mapped_column(String(50), default="soc_analyst")
    granted_by_user: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class MSSPTenantMetrics(Base):
    __tablename__ = "mssp_tenant_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    open_alerts: Mapped[int] = mapped_column(Integer, default=0)
    critical_alerts: Mapped[int] = mapped_column(Integer, default=0)
    open_cases: Mapped[int] = mapped_column(Integer, default=0)
    mttr_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    sla_breaches: Mapped[int] = mapped_column(Integer, default=0)
    connector_count: Mapped[int] = mapped_column(Integer, default=0)
    health_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)


class MSSPRulePack(Base):
    """Parent-curated bundle of detection rules an MSSP can assign to child tenants.

    Aligns with migration 023_mssp_detection_scoping.sql.
    """

    __tablename__ = "mssp_rule_packs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    created_by_user: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (UniqueConstraint("parent_tenant_id", "name", name="mssp_rule_packs_parent_tenant_id_name_key"),)


class MSSPRulePackRule(Base):
    """Membership of detection rules within an MSSP rule pack.

    Composite primary key (pack_id, rule_id) per migration.
    """

    __tablename__ = "mssp_rule_pack_rules"

    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mssp_rule_packs.id", ondelete="CASCADE"), primary_key=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    added_by_user: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class MSSPRulePackAssignment(Base):
    """Assignment of a parent-curated rule pack to a specific child tenant."""

    __tablename__ = "mssp_rule_pack_assignments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pack_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mssp_rule_packs.id", ondelete="CASCADE"), nullable=False, index=True)
    child_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    parameter_overrides: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    assigned_by_user: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (UniqueConstraint("pack_id", "child_tenant_id", name="mssp_rule_pack_assignments_pack_id_child_tenant_id_key"),)


class MSSPRuleOverride(Base):
    """Per-child-tenant override / exclusion / parameter tweak for a single detection rule."""

    __tablename__ = "mssp_rule_overrides"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    child_tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    # 'exclude' or 'customize'
    action: Mapped[str] = mapped_column(Text, nullable=False)
    severity_override: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter_overrides: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_user: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (UniqueConstraint("child_tenant_id", "rule_id", name="mssp_rule_overrides_child_tenant_id_rule_id_key"),)
