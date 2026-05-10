"""Tenant inbox token ORM model — Workstream 6 (universal capture).

For every closed-proprietary tool that has neither a read API nor an
OAuth flow, AiSOC mints a per-tenant, rotatable inbox URL of the form
``/v1/inbox/{token}``. The customer points the vendor's existing webhook
at that URL; ``services/ingest`` resolves the token to a tenant +
vendor template and reuses the existing OCSF normalizer + Kafka
publisher.

This is distinct from the per-connector ``connectors.ingest_token``
column (migration 029): that one ties a webhook to a *specific*
connector instance, while :class:`TenantInboxToken` ties it to a
tenant + ``template_id`` (e.g. ``pagerduty``, ``opsgenie``,
``generic-json``). The "Push (any vendor)" card in the onboarding flow
mints rows here without requiring a connector to exist yet — the first
event landing creates one virtually.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TenantInboxToken(Base):
    """Per-tenant rotatable webhook receiver token.

    The ``token`` column is the URL-safe random secret embedded in
    the inbox URL. We treat it like a credential — it never round-trips
    to logs or audit events.
    """

    __tablename__ = "tenant_inbox_tokens"

    # Token is the natural primary key — globally unique, embedded in
    # URLs. Using the raw token as PK avoids an extra index lookup on
    # the hot ingest path.
    token: Mapped[str] = mapped_column(String(80), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Filename stem in services/ingest/internal/normalizer/templates/.
    # Mapped values like ``pagerduty``, ``opsgenie``, ``generic-json``,
    # ``cloudflare-logpush``, ``aws-sns``, ``github-security-advisory``,
    # ``microsoft-defender-email``.
    template_id: Mapped[str] = mapped_column(String(80), nullable=False)
    # Human-readable label shown in the UI ("PagerDuty on-call").
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Optional HMAC secret for X-Signature verification. NULL means the
    # token in the URL is the only authenticator.
    hmac_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    # Non-NULL means the token has been rotated and the ingest service
    # rejects requests for it.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("tenant_inbox_tokens_tenant_idx", "tenant_id"),
        Index(
            "tenant_inbox_tokens_active_idx",
            "token",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )
