"""ORM mirrors of migration 166's resolution-contract tables.

The SQL migration is the load-bearing definition (`make upgrade` / fresh
install apply the chain); these models keep the parity picture complete and
register the tables in the boot-time metadata. The write path uses explicit
SQL with tenant predicates in ``app/services/case_resolution.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CaseResolutionPolicy(Base):
    __tablename__ = "case_resolution_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    #: Off by default: no row, or enforce=false, means the contract does not
    #: gate `resolved` for this tenant (new enforcement is opt-in).
    enforce: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    require_containment: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_eradication_recovery: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_root_cause: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_entities: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_notification: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseResolutionFacts(Base):
    __tablename__ = "case_resolution_facts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("aisoc_cases.id"), nullable=False)
    #: verified | not_required — verified requires containment_reference,
    #: not_required requires containment_reason (service-enforced).
    containment_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    containment_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    containment_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    eradication: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery: Mapped[str | None] = mapped_column(Text, nullable=True)
    customer_notified_channel: Mapped[str | None] = mapped_column(String(200), nullable=True)
    customer_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
