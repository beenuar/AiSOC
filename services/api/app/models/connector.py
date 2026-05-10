"""Connector ORM model."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_config: Mapped[dict] = mapped_column(JSONB, default=dict)  # Encrypted at application layer
    connector_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    health_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events_ingested: Mapped[int] = mapped_column(default=0)
    events_dropped: Mapped[int] = mapped_column(default=0)
    error_count: Mapped[int] = mapped_column(default=0)
    # Schema-drift sentinel state (migration 026). NULL until the first
    # non-empty poll has populated a fingerprint baseline.
    schema_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_schema_drift_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_drift_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Workstream 1 / 5: distinct from `last_sync` (which ticks every poll
    # cycle including empty polls). `last_event_at` only advances when an
    # event actually lands — it's what the onboarding "verify data flowing"
    # screen polls and what feeds the freshness-SLO badge.
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_kind: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Workstream 6: opaque token for /v1/inbox/{tenant_token} push endpoint.
    # NULL until the operator clicks "generate push token" in the UI.
    ingest_token: Mapped[str | None] = mapped_column(String(80), nullable=True, unique=True)
    # Workstream 2: True when this connector was provisioned through the
    # hosted OAuth flow (/oauth/start + /oauth/callback) rather than by
    # pasting an API token. Drives a read-only credential view in the UI
    # and lets the auto-refresh worker (Workstream 5) know it owns the
    # token rotation.
    oauth_provisioned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Workstream 5 (self-healing) — bookkeeping for the auto OAuth
    # refresh worker. ``oauth_refresh_failures`` ticks for each
    # consecutive refresh attempt that failed and resets to 0 on
    # success; the worker raises an operator alarm at >= 3.
    # ``oauth_last_refresh_at`` is the timestamp of the most recent
    # successful refresh, so the UI can display "rotated 3 min ago".
    oauth_refresh_failures: Mapped[int] = mapped_column(default=0, nullable=False)
    oauth_last_refresh_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Workstream 5 (self-healing) — backfill-on-outage state.
    # ``last_outage_at`` is set when the connector first flips to
    # ``unhealthy`` and is cleared on recovery. The backfill worker
    # checks ``recovery_at - last_outage_at`` against the 30 min
    # plan threshold to decide whether to schedule a one-shot backfill.
    # ``last_backfill_at`` is the wall clock of the most recent backfill
    # run — the worker uses it to avoid re-firing during a recovery
    # flap and the UI surfaces it as "backfilled to <ts>".
    last_outage_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_backfill_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Workstream 4: per-instance capability downscoping. ``NULL`` means
    # "no downscoping — agent may use every capability the connector class
    # declares". A non-NULL JSON array is the canonical allow-list (e.g.
    # ``["pull_alerts", "query_logs"]``) and is consumed by
    # ``BaseConnector.effective_capabilities()`` before tools are surfaced
    # to the agent layer via ``GET /api/v1/agents/tools``.
    allowed_capabilities: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="connectors")  # type: ignore[name-defined]
