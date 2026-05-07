"""Institutional memory ORM model.

Mirrors the table that ``services/agents/app/memory/institutional.py``
maintains via asyncpg. Both writers share the same schema; the API
service goes through SQLAlchemy so that the request/response and
multi-tenant guards stay consistent with the rest of the codebase.

Tier-1.5 (analyst-override feedback loop) writes rows here with
``analyst_override = True`` so the agent's institutional memory query
naturally retrieves them alongside any agent-authored entries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class InstitutionalMemory(Base):
    __tablename__ = "aisoc_institutional_memory"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Stored as TEXT in the agents-service migration so we keep the same type
    # here; tenants are addressed by their string id from auth context, which
    # the API service already coerces to/from UUID at the boundary.
    tenant_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    analyst_override: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    override_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="aisoc_institutional_memory_tenant_id_key_key"),
        Index("aisoc_institutional_memory_tenant_key", "tenant_id", "key"),
    )
