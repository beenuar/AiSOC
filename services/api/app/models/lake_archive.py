"""ORM models for the archive tier (migrations 170–171)."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class LakeArchivePolicy(Base):
    """Per-tenant archive-tier policy. An absent row means OFF."""

    __tablename__ = "lake_archive_policies"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    archive_years: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    s3_endpoint: Mapped[str] = mapped_column(Text, default="", nullable=False)
    s3_bucket: Mapped[str] = mapped_column(Text, default="", nullable=False)
    s3_region: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: Vault-encrypted (`vault:v1:` tokens) — never plaintext at rest.
    s3_access_key_enc: Mapped[str] = mapped_column(Text, default="", nullable=False)
    s3_secret_key_enc: Mapped[str] = mapped_column(Text, default="", nullable=False)
    worm_declared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class LakeArchivePartition(Base):
    """One exported (tenant, month): the signed manifest + verification state."""

    __tablename__ = "lake_archive_partitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    month: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="exported", nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    exported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class LakeRehydration(Base):
    """An audited rehydration job: estimate → load → ready (expiring) → expired."""

    __tablename__ = "lake_rehydrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    range_start: Mapped[date] = mapped_column(Date, nullable=False)
    range_end: Mapped[date] = mapped_column(Date, nullable=False)
    filters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    estimate: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="estimated", nullable=False)
    table_name: Mapped[str] = mapped_column(Text, default="", nullable=False)
    rows_loaded: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class LakePortabilityExport(Base):
    """An audited portability export to a bucket the tenant names."""

    __tablename__ = "lake_portability_exports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    range_start: Mapped[date] = mapped_column(Date, nullable=False)
    range_end: Mapped[date] = mapped_column(Date, nullable=False)
    s3_endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    s3_bucket: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    manifest: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
