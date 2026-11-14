"""Per-tenant home-region pin (t6-multi-region).

A tenant's *home region* is the place its data lives. Every request
for that tenant must be served by the home-region deployment — or
explicitly forwarded to it. This row is the durable record.

We keep it in its own table (rather than adding a column to a
``Tenant`` table) because:

1. There is no first-class ``Tenant`` table today; tenants are
   inferred from JWT claims.
2. A residency change is a regulated event (the auditor cares); a
   dedicated table makes it trivial to log and revert.

The table is empty by default. A tenant with no row falls back to
the platform's ``region_default_residency_zone`` setting, which
maps to the local region in single-region deployments.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class TenantHomeRegion(SQLModel, table=True):
    """One row per tenant whose home region is explicitly pinned."""

    __tablename__ = "tenant_home_region"

    tenant_id: str = Field(primary_key=True)
    region_id: str = Field(index=True)
    residency_zone: str = Field(index=True)
    pinned_by: str = Field(default="system", max_length=120)
    note: str = Field(default="")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TenantRegionEvent(SQLModel, table=True):
    """Audit log of every home-region change.

    Append-only. We record both the previous and new values so a
    later auditor can reconstruct the residency timeline of any
    tenant from a single ``ORDER BY created_at`` query.
    """

    __tablename__ = "tenant_region_event"

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    previous_region_id: str = Field(default="")
    previous_residency_zone: str = Field(default="")
    new_region_id: str = Field(index=True)
    new_residency_zone: str = Field(index=True)
    actor: str = Field(default="system", max_length=120)
    note: str = Field(default="")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
