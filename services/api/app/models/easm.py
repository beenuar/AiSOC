"""
External Attack Surface Management (EASM) models (Tier 3.6).
"""

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy import (
    Enum as SQLAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from . import Base


class ExternalAssetType(str, Enum):
    """Types of externally-discovered assets."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CERT = "cert"
    WEB_SERVICE = "web_service"
    API_ENDPOINT = "api_endpoint"


class ExternalAsset(Base):
    """
    Represents an externally-discovered asset (Tier 3.6 EASM).
    """

    __tablename__ = "external_assets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    asset_type: Mapped[ExternalAssetType] = mapped_column(SQLAEnum(ExternalAssetType, name="external_asset_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)  # domain, IP, cert CN, etc.
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    metadata_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default={})
    # e.g. {"ports": [443, 22], "certs": [...], "asn": "...", "org": "..."}

    # Relationships
    tenant = relationship("Tenant", back_populates="external_assets", lazy="selectin")

    __table_args__ = (
        Index("idx_easm_tenant_type", "tenant_id", "asset_type"),
        Index("idx_easm_value", "value"),
    )


class ExternalAssetDrift(Base):
    """
    Records drift events (new port, new cert, new subdomain, etc.).
    """

    __tablename__ = "external_asset_drift"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    external_asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("external_assets.id", ondelete="CASCADE"), nullable=False
    )
    drift_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "new_port", "new_cert"
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    # Relationships
    tenant = relationship("Tenant", back_populates="external_asset_drift", lazy="selectin")
    external_asset = relationship("ExternalAsset", lazy="selectin")

    __table_args__ = (
        Index("idx_easm_drift_tenant", "tenant_id"),
        Index("idx_easm_drift_asset", "external_asset_id"),
    )
