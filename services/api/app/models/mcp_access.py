"""ORM models for the inbound MCP surface — tool grants and call approvals.

Depth plan 9.1 (parity 6.6); migration ``109_mcp_access.sql`` carries the
reasoning for each column.

Not to be confused with :mod:`app.models.mcp_server`, which is the *outbound*
registry: third-party MCP servers a tenant has told the agent it may call.
These two tables are the inbound side — AiSOC's own MCP server, and who may
reach into this deployment through it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: States an approval row can hold. ``consumed`` exists so an approval is
#: spent by the call it authorised rather than standing open until it
#: expires: a one-shot grant is what an approver believes they are giving.
APPROVAL_STATES: tuple[str, ...] = ("pending", "approved", "denied", "consumed", "expired")


class McpToolGrant(Base):
    """One tenant's deliberate decision about one MCP tool.

    Absence of a row is not a denial — it means the tool's catalogue default
    applies. See the migration header.
    """

    __tablename__ = "aisoc_mcp_tool_grants"
    __table_args__ = (UniqueConstraint("tenant_id", "tool_name", name="aisoc_mcp_tool_grants_unique"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    decided_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))


class McpToolApproval(Base):
    """One non-read-only MCP tool call waiting on, or carrying, a human decision."""

    __tablename__ = "aisoc_mcp_tool_approvals"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'approved', 'denied', 'consumed', 'expired')",
            name="aisoc_mcp_tool_approvals_state_check",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    #: SHA-256 hex over the canonicalised arguments. A digest rather than the
    #: arguments because those carry hostnames and queries and this row is
    #: rendered in the console.
    argument_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    #: The credential label that asked -- a key prefix or an email. Kept for
    #: display and for rows predating migration 158, and deliberately *not*
    #: the basis for separation of duties: one person holding a key and a
    #: session appears here under two labels (GHSA-xhmc-69rh-h3rr, F10).
    requested_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: The human who asked, resolved from the authenticated principal. This is
    #: what separation of duties compares. NULL on pre-158 rows.
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    decided_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
