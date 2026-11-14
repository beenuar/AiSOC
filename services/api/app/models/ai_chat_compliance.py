"""Enterprise AI-chat compliance records.

Depth plan wave 2, Phase 7.1. Backs ``/api/v1/ai-chat-compliance`` and
migration ``146_ai_chat_compliance.sql``; the migration header carries the
reasoning for each column and is the thing to read first.

The one thing to notice here rather than there: there is no model for
message content, because there is no table for it. ``AiChatContentLabel``
carries labels, shape names and one ``String(280)`` snippet. The column
lengths below are not decoration — they mirror the database's own bounds, so
a caller that over-long-strings a field fails in the ORM with a readable
error instead of at the driver.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: Providers with a compliance API this service can read. Mirrors the CHECK
#: constraint in migration 146.
AI_CHAT_PROVIDERS: tuple[str, ...] = ("anthropic",)

#: The classification vocabulary, mirroring both the CHECK constraint in
#: migration 146 and ``services/api/app/services/ai_chat_compliance/
#: classifier.py::LABELS``. A test asserts all three agree, because three
#: copies of one vocabulary is exactly the shape that drifts.
AI_CHAT_LABELS: tuple[str, ...] = ("secrets", "personal_data", "regulated", "financial")

#: The snippet bound. Mirrors ``VARCHAR(280)``.
SNIPPET_MAX = 280


def _now() -> datetime:
    return datetime.now(UTC)


class AiChatComplianceConfig(Base):
    """Per-tenant enablement. No row means collection does not run."""

    __tablename__ = "aisoc_ai_chat_compliance_config"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    #: Opaque ``vault:v1:<base64>``. Never returned to the console; the read
    #: route exposes ``hasKey: bool``.
    access_key_vault: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: A second, narrower opt-in covering anything derived from message
    #: text. Off even when collection is on.
    content_labels_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    activity_cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class AiChatUser(Base):
    """One member of the provider organisation."""

    __tablename__ = "aisoc_ai_chat_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_org_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class AiChatProject(Base):
    """A project, which groups conversations."""

    __tablename__ = "aisoc_ai_chat_projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider_org_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class AiChatAuditEvent(Base):
    """One activity-feed record."""

    __tablename__ = "aisoc_ai_chat_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    actor_external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    provider_org_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    chat_external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    project_external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class AiChatContentLabel(Base):
    """What one conversation evidenced. Never what it said.

    Deliberately carries no column able to hold a message. Adding one is a
    migration somebody has to write and review, which is the point.
    """

    __tablename__ = "aisoc_ai_chat_content_labels"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    chat_external_id: Mapped[str] = mapped_column(Text, nullable=False)
    project_external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    provider_org_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    labels: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    secret_kinds: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    snippet: Mapped[str | None] = mapped_column(String(SNIPPET_MAX), nullable=True)
    snippet_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    messages_examined: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    messages_matched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)
