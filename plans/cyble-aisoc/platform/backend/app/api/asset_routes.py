"""Asset / CMDB REST API (todo ``t2i-api``).

Read/write surface for the CMDB intelligence graph. Mirrors the
``asset.*`` agent tools but exposes them over HTTP so the dashboard,
connectors, and external automation can drive the same code paths.

Endpoints
~~~~~~~~~

* ``GET    /assets``                    – paginated list with light filters
* ``GET    /assets/{key}``              – fetch one asset by natural key
* ``GET    /assets/{key}/context``      – full :class:`AssetContext` payload
* ``POST   /assets/resolve``            – fuzzy lookup by free-form identifier
* ``POST   /assets``                    – idempotent upsert (analyst / connector)

Every route is tenant-scoped via :func:`app.security.tenant.require_tenant`
and never auto-fans-out across the MSSP fleet; analysts pivot explicitly
with the ``X-AISOC-Tenant`` header.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.cmdb import (
    get_asset_context,
    list_assets,
    resolve_asset,
    upsert_asset,
)
from app.models.asset import AssetCriticality, AssetEnvironment, AssetType
from app.security.tenant import TenantContext, require_tenant

router = APIRouter(prefix="/assets", tags=["assets"])


# ── Request bodies ───────────────────────────────────────────────────────


class AssetResolveBody(BaseModel):
    identifier: str = Field(..., description="Hostname, user, IP, alias, FQDN, …")
    asset_type: AssetType | None = Field(
        None, description="Optional type hint to disambiguate (host, user, …)"
    )


class AssetUpsertBody(BaseModel):
    """Mirror of :func:`app.cmdb.upsert_asset` kwargs.

    Kept as a Pydantic model so FastAPI can validate enums and surface
    a clean OpenAPI schema for SDK generators.
    """

    asset_type: AssetType
    key: str = Field(..., description="Natural key: hostname, sAMAccountName, ARN, …")
    name: str | None = None
    aliases: list[str] | None = None
    criticality: AssetCriticality | None = None
    environment: AssetEnvironment | None = None
    owner: str | None = None
    business_unit: str | None = None
    location: str | None = None
    cost_center: str | None = None
    compliance_scopes: list[str] | None = None
    data_classifications: list[str] | None = None
    ip_addresses: list[str] | None = None
    mac_addresses: list[str] | None = None
    os: str | None = None
    os_version: str | None = None
    cloud_provider: str | None = None
    cloud_account_id: str | None = None
    region: str | None = None
    sources: list[str] | None = None
    tags: list[str] | None = None
    notes: str | None = None
    attributes: dict[str, Any] | None = None


# ── Routes ───────────────────────────────────────────────────────────────


@router.get("")
def list_assets_route(
    ctx: TenantContext = Depends(require_tenant),
    asset_type: AssetType | None = Query(None),
    criticality: AssetCriticality | None = Query(None),
    environment: AssetEnvironment | None = Query(None),
    q: str | None = Query(None, description="Substring search over key/name/owner"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """Paginated CMDB list — always scoped to the caller's active tenant.

    MSSP analysts pivot tenants via the ``X-AISOC-Tenant`` header rather
    than by fan-out: the CMDB intentionally answers only for one tenant
    at a time to avoid accidental cross-tenant disclosure.
    """
    return list_assets(
        tenant_id=ctx.active_tenant_id,
        asset_type=asset_type,
        criticality=criticality,
        environment=environment,
        query=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{key}")
def get_asset_route(
    key: str,
    ctx: TenantContext = Depends(require_tenant),
    asset_type: AssetType | None = Query(None),
) -> dict[str, Any]:
    """Fetch one asset by natural key (case-insensitive)."""
    ref = resolve_asset(
        tenant_id=ctx.active_tenant_id, identifier=key, asset_type=asset_type
    )
    if ref is None:
        raise HTTPException(status_code=404, detail="asset not found")
    # Re-list with a tight filter so we return the full row, not just the ref.
    rows = list_assets(
        tenant_id=ctx.active_tenant_id,
        asset_type=ref.asset_type,
        query=ref.key,
        limit=1,
    )
    if not rows:
        # Theoretically possible if a writer raced us; treat as 404 rather
        # than a 500 — the caller can retry.
        raise HTTPException(status_code=404, detail="asset not found")
    return rows[0]


@router.get("/{key}/context")
def get_asset_context_route(
    key: str,
    ctx: TenantContext = Depends(require_tenant),
    asset_type: AssetType | None = Query(None),
    recent_case_limit: int = Query(5, ge=0, le=50),
    graph_depth: int = Query(1, ge=0, le=3),
    graph_limit: int = Query(25, ge=0, le=200),
) -> dict[str, Any]:
    """Full :class:`AssetContext` — same payload as ``asset.get_context``.

    This is what the dashboard "Asset detail" panel renders and what the
    Triager/Investigator agents read when they need to know criticality,
    blast radius, owner, compliance scope, and recent case history in
    one round trip.
    """
    context = get_asset_context(
        tenant_id=ctx.active_tenant_id,
        identifier=key,
        asset_type=asset_type,
        recent_case_limit=recent_case_limit,
        graph_depth=graph_depth,
        graph_limit=graph_limit,
    )
    if context is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return context.to_dict()


@router.post("/resolve")
def resolve_asset_route(
    body: AssetResolveBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Fuzzy lookup → ``{matched, asset_id, key, matched_on, …}`` or 404.

    Useful for the dashboard's "search bar" and for connectors that have
    a free-form identifier (e.g. "10.4.21.118") and need to find the
    CMDB row.
    """
    ref = resolve_asset(
        tenant_id=ctx.active_tenant_id,
        identifier=body.identifier,
        asset_type=body.asset_type,
    )
    if ref is None:
        raise HTTPException(status_code=404, detail="no matching asset")
    return {
        "asset_id": ref.asset_id,
        "tenant_id": ref.tenant_id,
        "asset_type": ref.asset_type.value,
        "key": ref.key,
        "name": ref.name,
        "criticality": ref.criticality.value,
        "environment": ref.environment.value,
        "matched_on": ref.matched_on,
    }


@router.post("", status_code=200)
def upsert_asset_route(
    body: AssetUpsertBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Idempotent upsert. Connectors and analysts both ingest here.

    Returns the resulting :class:`AssetRef` so the caller can chain into
    ``GET /assets/{key}/context`` without an extra lookup.
    """
    ref = upsert_asset(
        tenant_id=ctx.active_tenant_id,
        asset_type=body.asset_type,
        key=body.key,
        name=body.name,
        aliases=body.aliases,
        criticality=body.criticality,
        environment=body.environment,
        owner=body.owner,
        business_unit=body.business_unit,
        location=body.location,
        cost_center=body.cost_center,
        compliance_scopes=body.compliance_scopes,
        data_classifications=body.data_classifications,
        ip_addresses=body.ip_addresses,
        mac_addresses=body.mac_addresses,
        os=body.os,
        os_version=body.os_version,
        cloud_provider=body.cloud_provider,
        cloud_account_id=body.cloud_account_id,
        region=body.region,
        sources=body.sources,
        tags=body.tags,
        notes=body.notes,
        attributes=body.attributes,
    )
    return {
        "asset_id": ref.asset_id,
        "tenant_id": ref.tenant_id,
        "asset_type": ref.asset_type.value,
        "key": ref.key,
        "name": ref.name,
        "criticality": ref.criticality.value,
        "environment": ref.environment.value,
        "matched_on": ref.matched_on,
    }
