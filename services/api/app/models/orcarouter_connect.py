"""Pending OrcaRouter OAuth 2.0 + PKCE authorizations.

One row per in-flight "Connect with OrcaRouter" attempt. The row is the only
place the code verifier exists outside process memory: it is created by
``/llm/orcarouter/connect/start``, read once by ``/connect/finish`` and deleted
before the code is exchanged, so a replayed state can never redeem a second
key.

Why a table rather than the connector ``oauth_states`` table
-----------------------------------------------------------
``oauth_states`` is scoped to connector types and carries a registry of OAuth
client applications. OrcaRouter's flow has no client registration, no client
secret and no connector, so writing rows there would force a fake connector
type through the connector catalogue validator and make the connector
reauth path look at rows it did not create. This table is deliberately small:
tenant, user, verifier, expiry.

The verifier is short-lived and single-use. It is never returned to the
browser, never logged, and never included in an error message.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class OrcaRouterConnectState(Base):
    """A single-use PKCE authorization attempt."""

    __tablename__ = "orcarouter_connect_states"

    state: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    code_verifier: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
