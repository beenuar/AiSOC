"""Observed AI estate: one row per AI asset a tenant actually runs.

Depth plan 6.1. Backs ``/api/v1/ai-assets`` and migration
``110_ai_assets.sql``; the migration header carries the reasoning for each
column and is the thing to read first.

The distinction worth repeating here, because it is what makes the table
useful: ``aisoc_mcp_servers`` is what an operator *declared*, this is what
AiSOC *observed*. The row that matters is the one present here and absent
there.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: The kinds depth plan 6.1 named, plus the two wave-2 7.2 added. Mirrored
#: by the CHECK constraint in migrations 110 and 147, so a ninth value fails
#: at the write rather than appearing as an unfilterable row in the console.
#:
#: `hosted_agent` runs in a provider's control plane, so it has no device to
#: contain and `score_risk` must not charge it for the absence of one.
#: `repo_ai_artifact` is an agent-instruction file, skill directory or MCP
#: configuration file in a repository; the tools and servers it names live
#: in `attributes`.
AI_ASSET_KINDS: tuple[str, ...] = (
    "ai_app",
    "coding_agent",
    "mcp_server",
    "ide_extension",
    "provider_key",
    "oauth_grant",
    "hosted_agent",
    "repo_ai_artifact",
)

#: Kinds for which no device can exist, as opposed to kinds where one was
#: simply not learned. `score_risk` reads this rather than naming the kinds
#: inline, so adding a kind is one edit and not two that can disagree.
DEVICELESS_KINDS: frozenset[str] = frozenset({"provider_key", "oauth_grant", "hosted_agent", "repo_ai_artifact"})

#: Which discovery path produced a row. Carried rather than inferred because
#: the three sources see genuinely different things, and an analyst reading an
#: unlinked asset needs to know whether the link is missing or unknowable:
#: runtime telemetry knows the model and never the device, endpoint discovery
#: knows the device and never the model.
AI_ASSET_SOURCES: tuple[str, ...] = (
    "ai_runtime",
    "endpoint",
    "provider_audit",
    "oauth_audit",
    "declared",
)


class AiAsset(Base):
    """One observed AI asset, with the person and device behind it."""

    __tablename__ = "aisoc_ai_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    kind: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovery_source: Mapped[str] = mapped_column(Text, nullable=False)

    # NULL means "not learned", never "none". The console renders the two
    # differently and the difference is the finding.
    principal: Mapped[str | None] = mapped_column(Text, nullable=True)
    device: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective_permissions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_reasons: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Tri-state on purpose: NULL is "nobody has decided", which is not the
    # same as reviewed and refused.
    sanctioned: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    observation_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
