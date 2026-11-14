"""Region service: tenant home-region CRUD + decision wiring (t6-multi-region).

The service is the place every consumer (API routes, the residency
middleware, the smoke test forwarder) goes to ask "what should I
do with this request?"

It composes the pure :func:`decide_residency` helper with a SQL
read of :class:`TenantHomeRegion` so the call site doesn't have to
plumb the mesh and the row through itself.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, select

from app.config import settings
from app.db import session_scope
from app.models.region import TenantHomeRegion, TenantRegionEvent
from app.regions.policy import (
    RegionMesh,
    ResidencyDecision,
    build_region_mesh,
    decide_residency,
)


_mesh_cache: Optional[RegionMesh] = None


def get_region_mesh() -> RegionMesh:
    """Return the process-wide mesh, cached after first build."""

    global _mesh_cache
    if _mesh_cache is not None:
        return _mesh_cache
    _mesh_cache = build_region_mesh(
        local_region_id=settings.region_id,
        peers_csv=settings.region_peers,
        allowed_zones_csv=settings.region_allowed_residency_zones,
    )
    return _mesh_cache


def reload_region_mesh() -> RegionMesh:
    """Reload the mesh from settings. Used by tests + region admin endpoints."""

    global _mesh_cache
    _mesh_cache = None
    return get_region_mesh()


def _snapshot_home(row: Optional[TenantHomeRegion]) -> Optional[TenantHomeRegion]:
    """Detached-safe copy of the persisted row.

    SQLAlchemy expires attributes on a row when its session closes,
    so callers that hold the ORM object and then read attributes
    after ``with session_scope():`` see a ``DetachedInstanceError``.
    Returning a freshly-constructed copy lets us keep the ergonomic
    "look up + read attributes" pattern without coupling callers to
    session lifecycle.
    """

    if row is None:
        return None
    return TenantHomeRegion(
        tenant_id=row.tenant_id,
        region_id=row.region_id,
        residency_zone=row.residency_zone,
        pinned_by=row.pinned_by,
        note=row.note,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def home_region_for(
    tenant_id: str, *, session: Optional[Session] = None
) -> Optional[TenantHomeRegion]:
    """Look up a tenant's pinned home region row, if any."""

    def _query(active: Session) -> Optional[TenantHomeRegion]:
        return active.exec(
            select(TenantHomeRegion).where(TenantHomeRegion.tenant_id == tenant_id)
        ).one_or_none()

    if session is not None:
        return _query(session)
    with session_scope() as scoped:
        row = _query(scoped)
        return _snapshot_home(row)


def resolve_for_tenant(tenant_id: str) -> ResidencyDecision:
    """Compute the residency decision for ``tenant_id``.

    Falls back to the platform's default residency zone (mapped to
    the local region) when the tenant has no explicit pin.
    """

    mesh = get_region_mesh()
    pinned = home_region_for(tenant_id)
    if pinned is None:
        # No pin → serve locally. The decision still goes through
        # ``decide_residency`` so the residency-zone allow-list is
        # honoured for the local zone too.
        local = mesh.local()
        if local is None:
            return ResidencyDecision(
                resolution=decide_residency(
                    mesh=mesh, tenant_home_region_id=mesh.local_region_id
                ).resolution,
                target_region=None,
                reason="no_local_region_in_mesh",
            )
        return decide_residency(mesh=mesh, tenant_home_region_id=local.region_id)
    return decide_residency(mesh=mesh, tenant_home_region_id=pinned.region_id)


def pin_home_region(
    tenant_id: str,
    *,
    region_id: str,
    actor: str = "system",
    note: str = "",
) -> TenantHomeRegion:
    """Idempotently pin a tenant's home region.

    Writes to both :class:`TenantHomeRegion` (the live state) and
    :class:`TenantRegionEvent` (the audit trail). The mesh is
    consulted to populate ``residency_zone`` so the column always
    matches the deployed peer's zone.
    """

    mesh = get_region_mesh()
    target = mesh.by_id(region_id)
    if target is None:
        raise ValueError(f"region '{region_id}' is not registered in this mesh")

    with session_scope() as session:
        existing = home_region_for(tenant_id, session=session)
        previous_region = existing.region_id if existing else ""
        previous_zone = existing.residency_zone if existing else ""

        if existing is None:
            row = TenantHomeRegion(
                tenant_id=tenant_id,
                region_id=region_id,
                residency_zone=target.residency_zone,
                pinned_by=actor,
                note=note,
            )
            session.add(row)
        else:
            row = existing
            row.region_id = region_id
            row.residency_zone = target.residency_zone
            row.pinned_by = actor
            row.note = note
            row.updated_at = datetime.now(timezone.utc)
            session.add(row)

        if (previous_region, previous_zone) != (region_id, target.residency_zone):
            session.add(
                TenantRegionEvent(
                    tenant_id=tenant_id,
                    previous_region_id=previous_region,
                    previous_residency_zone=previous_zone,
                    new_region_id=region_id,
                    new_residency_zone=target.residency_zone,
                    actor=actor,
                    note=note,
                )
            )

        session.commit()
        session.refresh(row)
        return _snapshot_home(row)


def list_region_events(tenant_id: str) -> list[TenantRegionEvent]:
    """Return the audit trail for a tenant's region pins, oldest first."""

    with session_scope() as session:
        rows = list(
            session.exec(
                select(TenantRegionEvent)
                .where(TenantRegionEvent.tenant_id == tenant_id)
                .order_by(TenantRegionEvent.created_at)
            )
        )
        # Snapshot the rows into plain Pythonic copies so the data
        # survives the session closing. Returning the SQLAlchemy
        # objects directly produces a detached-instance error when
        # the caller reads ``created_at``.
        return [
            TenantRegionEvent(
                id=r.id,
                tenant_id=r.tenant_id,
                previous_region_id=r.previous_region_id,
                previous_residency_zone=r.previous_residency_zone,
                new_region_id=r.new_region_id,
                new_residency_zone=r.new_residency_zone,
                actor=r.actor,
                note=r.note,
                created_at=r.created_at,
            )
            for r in rows
        ]
