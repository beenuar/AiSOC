"""Insider-threat module ORM models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class UserRiskProfile(Base):
    __tablename__ = "user_risk_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    external_user_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_tier: Mapped[str] = mapped_column(String(20), default="low")
    # aggregated signals
    failed_auth_24h: Mapped[int] = mapped_column(Integer, default=0)
    off_hours_events_7d: Mapped[int] = mapped_column(Integer, default=0)
    data_staging_score: Mapped[float] = mapped_column(Float, default=0.0)
    peer_anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    privilege_delta: Mapped[int] = mapped_column(Integer, default=0)
    # watchlist
    is_watchlisted: Mapped[bool] = mapped_column(Boolean, default=False)
    watchlist_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    watchlisted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    watchlisted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # WS4.4 (migration 168): a watchlist row is never indefinite, and it
    # records which door listed it ('manual' | 'hr_sync').
    watchlist_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    watchlist_source: Mapped[str] = mapped_column(String(20), default="manual")
    # timestamps
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    indicators: Mapped[list[InsiderIndicator]] = relationship("InsiderIndicator", back_populates="profile", lazy="noload")


class InsiderIndicator(Base):
    __tablename__ = "insider_indicators"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_risk_profiles.id", ondelete="CASCADE"), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    profile: Mapped[UserRiskProfile] = relationship("UserRiskProfile", back_populates="indicators")


class InsiderPeerGroup(Base):
    __tablename__ = "insider_peer_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    criteria: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class InsiderWatchlistPolicy(Base):
    """Per-tenant insider-watchlist policy (WS4.4, migration 168).

    One row per tenant; an absent row means every automation is off. The
    HR door (`hr_sync_enabled`) watches `workforce_members` for departing
    members and auto-watchlists them — automation a tenant opts into.
    """

    __tablename__ = "insider_watchlist_policies"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    hr_sync_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_expiry_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    hr_grace_days: Mapped[int] = mapped_column(Integer, default=14, nullable=False)
    lookback_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
