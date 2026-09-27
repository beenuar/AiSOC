"""Per-tenant MCP server registry ORM model.

Gap-closure Phase 5.2. Backs ``/api/v1/mcp-servers`` and migration
``069_mcp_servers.sql``; read the migration header for why each bound exists.

The short version: an MCP server is third-party code, reached over the
network, whose replies land in the prompt that decides what the agent does
next. Every field here narrows that. ``tool_allowlist`` defaults to empty so
a saved server advertises nothing, ``enabled`` defaults to false so
registering is not the same decision as reaching, and ``timeout_seconds`` and
``max_response_bytes`` are not nullable so no row can mean "unbounded".

``auth_config`` holds :class:`app.security.credential_vault.CredentialVault`
ciphertext under the convention connector credentials already use, rather
than a bespoke column. It is never returned to a console caller; the read
model exposes ``has_credential: bool``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: Transports the registry can store. ``stdio`` starts a local process on the
#: agents container, so the agents service refuses one unless an operator has
#: enabled stdio *and* allowlisted the command. Stored rather than rejected
#: here so the refusal can name what was configured.
MCP_TRANSPORTS: tuple[str, ...] = ("streamable_http", "stdio")


class McpServer(Base):
    """One third-party MCP server a tenant has chosen to trust, and how far."""

    __tablename__ = "aisoc_mcp_servers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The namespace segment in ``mcp.<name>.<tool>``. The DB constrains the
    # shape with a CHECK because the value becomes part of an OpenAI function
    # name; the API mirrors the same regex so the 422 is readable.
    name: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)

    transport: Mapped[str] = mapped_column(Text, nullable=False, default="streamable_http")
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    args: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    auth_config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tool_allowlist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    max_response_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=65536)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


__all__ = ["MCP_TRANSPORTS", "McpServer"]
