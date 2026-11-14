"""Threat Actor Profiling REST API (t3e-actor-profiling).

Analyst-facing surface for the proactive Threat Actor Profiling Agent
implemented in :mod:`app.agents.actor_profiler`. Three workflows:

- ``POST /actors/sweep``        — on-demand profiling sweep (the
  scheduled loop runs every ``actor_profiler_scan_interval_seconds``,
  but during a hunt you want fresh attribution *now*).
- ``GET  /actors``              — paginated list of profiled actors
  for the active tenant (the actor table view).
- ``GET  /actors/{handle}``     — single actor card. Merges the
  tenant-local :class:`ThreatActor` row with the
  ``cti.actor_lookup`` catalogue record so the UI sees one
  consistent payload regardless of where each field came from.
- ``GET  /actors/pivot``        — given an IOC, return every actor
  the platform has attributed it to. The hot lookup path; uses the
  denormalised :class:`ActorIOCLink` table so it stays sub-ms even
  on tenants with tens of thousands of IOCs.

Design rules (same as exposure_routes.py):

1. Tenant-scoped via ``require_tenant``. MSSP analysts pivoting into
   a child tenant see only that child's actor view (plus the
   ``__global__`` catalogue inherited by every tenant).
2. Routes delegate to the agent for writes — the API never
   reimplements business logic.
3. Read endpoints are pure SQL: no tool calls, no graph traversal,
   so they're safe to call from dashboards on a tight refresh cadence.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select

from app.agents.actor_profiler import ThreatActorProfilingAgent
from app.config import settings
from app.db import session_scope
from app.models.threat_actor import ActorIOCLink, ThreatActor
from app.security.tenant import TenantContext, require_tenant
from app.tools.registry import registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/actors", tags=["actors"])


# ──────────────────────────────────────────────────────────────────────
# Response shapes
# ──────────────────────────────────────────────────────────────────────


class ActorSweepResponse(BaseModel):
    """Compact mirror of :class:`ActorProfilingResult` over the wire."""

    tenant_id: str
    iocs_scanned: int
    actors_upserted: int
    actors_new: int
    ioc_links_upserted: int
    ioc_links_new: int
    graph_nodes_upserted: int
    graph_edges_upserted: int
    catalogue_misses: int
    errors: list[str]


class ActorSummary(BaseModel):
    """Compact row for the actor-table view."""

    handle: str
    tenant_id: str
    aliases: list[str]
    motivation: str
    sophistication: str
    origin_country: str | None
    target_sectors: list[str]
    confidence: int
    active: bool
    first_observed: str | None
    last_observed: str | None
    ioc_count: int
    """Cardinality of the IOC link set; the table view sorts by this."""


class ActorListResponse(BaseModel):
    tenant_id: str
    actors: list[ActorSummary]
    total: int


class ActorIOC(BaseModel):
    """One IOC linked to the actor (denormalised view)."""

    value: str
    type: str
    confidence: int
    source: str
    first_seen: str | None
    last_seen: str | None


class ActorCard(BaseModel):
    """Full actor-card payload: tenant row merged with catalogue.

    Field-level merge precedence: catalogue values win when the tenant
    row hasn't been customised (e.g. left empty); tenant-set values
    survive a catalogue refresh. This matches the agent's
    materialisation logic so the API is self-consistent with what the
    agent writes.
    """

    handle: str
    tenant_id: str
    aliases: list[str]
    description: str
    motivation: str
    sophistication: str
    origin_country: str | None
    target_sectors: list[str]
    target_regions: list[str]
    techniques: list[str]
    tools: list[str]
    campaigns: list[str]
    references: list[str]
    confidence: int
    active: bool
    first_observed: str | None
    last_observed: str | None
    catalogue_hit: bool
    """True if ``cti.actor_lookup`` returned a canonical record."""
    iocs: list[ActorIOC]


class ActorPivotResponse(BaseModel):
    """``GET /actors/pivot?ioc=...`` payload."""

    tenant_id: str
    ioc: str
    actors: list[ActorSummary]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _row_to_summary(row: ThreatActor, ioc_count: int) -> ActorSummary:
    return ActorSummary(
        handle=row.handle,
        tenant_id=row.tenant_id,
        aliases=list(row.aliases or []),
        motivation=row.motivation.value,
        sophistication=row.sophistication.value,
        origin_country=row.origin_country,
        target_sectors=list(row.target_sectors or []),
        confidence=row.confidence,
        active=row.active,
        first_observed=row.first_observed.isoformat()
        if row.first_observed
        else None,
        last_observed=row.last_observed.isoformat()
        if row.last_observed
        else None,
        ioc_count=ioc_count,
    )


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────


@router.post("/sweep", response_model=ActorSweepResponse)
async def trigger_actor_sweep(
    ctx: TenantContext = Depends(require_tenant),
) -> ActorSweepResponse:
    """Run one on-demand profiling sweep for the caller's active tenant.

    Same semantics as ``POST /exposure/sweep``: bounded by the
    configured timeout, surfaces errors as 5xx, and returns the full
    sweep counters so the analyst can confirm what was touched.
    """
    tenant_id = ctx.active_tenant_id
    try:
        with session_scope() as session:
            agent = ThreatActorProfilingAgent(
                session=session, tenant_id=tenant_id
            )
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.actor_profiler_sweep_timeout_seconds,
            )
    except asyncio.TimeoutError as exc:
        logger.warning(
            "actor_routes: on-demand sweep tenant=%s exceeded %ds",
            tenant_id,
            settings.actor_profiler_sweep_timeout_seconds,
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"Actor profiling sweep exceeded "
                f"{settings.actor_profiler_sweep_timeout_seconds}s; "
                "increase actor_profiler_sweep_timeout_seconds or wait "
                "for the scheduled run."
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "actor_routes: on-demand sweep tenant=%s failed", tenant_id
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ActorSweepResponse(
        tenant_id=result.tenant_id,
        iocs_scanned=result.iocs_scanned,
        actors_upserted=result.actors_upserted,
        actors_new=result.actors_new,
        ioc_links_upserted=result.ioc_links_upserted,
        ioc_links_new=result.ioc_links_new,
        graph_nodes_upserted=result.graph_nodes_upserted,
        graph_edges_upserted=result.graph_edges_upserted,
        catalogue_misses=result.catalogue_misses,
        errors=result.errors,
    )


@router.get("", response_model=ActorListResponse)
def list_actors(
    ctx: TenantContext = Depends(require_tenant),
    motivation: str | None = Query(default=None),
    sophistication: str | None = Query(default=None),
    sector: str | None = Query(
        default=None,
        description="Filter to actors whose target_sectors includes this value.",
    ),
    active_only: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=500),
) -> ActorListResponse:
    """Paginated actor list for the active tenant.

    Visibility rule: the caller sees their tenant rows *plus* the
    ``__global__`` catalogue (which every tenant inherits). We collapse
    duplicates by handle, preferring the tenant-local row when both
    exist — that way analysts who've added local notes don't see them
    erased by the global view.
    """
    tenant_id = ctx.active_tenant_id

    with session_scope() as session:
        stmt = (
            select(ThreatActor)
            .where(ThreatActor.tenant_id.in_([tenant_id, "__global__"]))
            .order_by(ThreatActor.confidence.desc(), ThreatActor.handle.asc())
        )
        rows = session.exec(stmt).all()

        # Collapse: prefer tenant-local row over global on handle clash.
        by_handle: dict[str, ThreatActor] = {}
        for row in rows:
            existing = by_handle.get(row.handle)
            if existing is None:
                by_handle[row.handle] = row
            elif existing.tenant_id == "__global__" and row.tenant_id != "__global__":
                by_handle[row.handle] = row

        # Apply filters in-Python because the set is already small after
        # the tenant filter; keeps query simple and avoids a JSON-array
        # contains-clause that varies by DB dialect.
        filtered: list[ThreatActor] = []
        for row in by_handle.values():
            if active_only and not row.active:
                continue
            if motivation and row.motivation.value != motivation.lower():
                continue
            if (
                sophistication
                and row.sophistication.value != sophistication.lower()
            ):
                continue
            if sector and sector.lower() not in (
                s.lower() for s in (row.target_sectors or [])
            ):
                continue
            filtered.append(row)

        # IOC counts — one batched query is cheaper than N point lookups.
        handles = [row.handle for row in filtered]
        counts: dict[str, int] = {h: 0 for h in handles}
        if handles:
            link_rows = session.exec(
                select(ActorIOCLink)
                .where(ActorIOCLink.tenant_id == tenant_id)
                .where(ActorIOCLink.actor_handle.in_(handles))
            ).all()
            for link in link_rows:
                counts[link.actor_handle] = counts.get(link.actor_handle, 0) + 1

        summaries = [
            _row_to_summary(row, counts.get(row.handle, 0))
            for row in filtered[:limit]
        ]

    return ActorListResponse(
        tenant_id=tenant_id,
        actors=summaries,
        total=len(filtered),
    )


@router.get("/pivot", response_model=ActorPivotResponse)
def pivot_from_ioc(
    ioc: str = Query(
        ..., min_length=1, description="IOC value to pivot on (ip/domain/hash/...)"
    ),
    ctx: TenantContext = Depends(require_tenant),
) -> ActorPivotResponse:
    """Pivot from an IOC to the actor(s) it's been attributed to.

    Hot path: serves the "click on an IOC, see the actor" UI gesture.
    Reads the denormalised :class:`ActorIOCLink` table so it stays
    fast even on very large tenants. If the link table is empty for an
    IOC, the response is empty — analysts can trigger a sweep to
    repopulate.
    """
    tenant_id = ctx.active_tenant_id
    ioc_value = ioc.strip()

    with session_scope() as session:
        links = session.exec(
            select(ActorIOCLink)
            .where(ActorIOCLink.tenant_id == tenant_id)
            .where(ActorIOCLink.ioc_value == ioc_value)
            .order_by(ActorIOCLink.confidence.desc())
        ).all()

        if not links:
            return ActorPivotResponse(
                tenant_id=tenant_id, ioc=ioc_value, actors=[]
            )

        handles = list({link.actor_handle for link in links})
        actor_rows = session.exec(
            select(ThreatActor)
            .where(ThreatActor.tenant_id.in_([tenant_id, "__global__"]))
            .where(ThreatActor.handle.in_(handles))
        ).all()
        # Same tenant-local-wins collapse as the list endpoint.
        by_handle: dict[str, ThreatActor] = {}
        for row in actor_rows:
            existing = by_handle.get(row.handle)
            if existing is None or (
                existing.tenant_id == "__global__"
                and row.tenant_id != "__global__"
            ):
                by_handle[row.handle] = row

        # IOC counts per matched actor — needed by ActorSummary.
        link_rows = session.exec(
            select(ActorIOCLink)
            .where(ActorIOCLink.tenant_id == tenant_id)
            .where(ActorIOCLink.actor_handle.in_(handles))
        ).all()
        counts: dict[str, int] = {}
        for link in link_rows:
            counts[link.actor_handle] = counts.get(link.actor_handle, 0) + 1

        summaries = [
            _row_to_summary(row, counts.get(row.handle, 0))
            for row in by_handle.values()
        ]

    return ActorPivotResponse(
        tenant_id=tenant_id, ioc=ioc_value, actors=summaries
    )


@router.get("/{handle}", response_model=ActorCard)
async def get_actor_card(
    handle: str,
    ctx: TenantContext = Depends(require_tenant),
) -> ActorCard:
    """Full actor card: tenant row + catalogue overlay + linked IOCs.

    Calls ``cti.actor_lookup`` so analysts always see the freshest
    catalogue data even if the tenant's last sweep was hours ago. The
    tenant row wins on field-level conflicts (it's the local override
    surface); the catalogue fills in anything the tenant left empty.
    """
    tenant_id = ctx.active_tenant_id
    handle = handle.strip()

    # Materialise everything we need from the DB *inside* the session
    # context — once it exits the rows are detached, and any lazy
    # attribute access (link.ioc_value, row.aliases, ...) raises
    # DetachedInstanceError. We snapshot to plain dicts/values so the
    # rest of the handler is pure CPU + one outbound CTI tool call.
    row_snapshot: dict[str, Any] | None = None
    link_snapshot: list[dict[str, Any]] = []
    with session_scope() as session:
        # Prefer the tenant-local row; fall back to the global catalogue
        # row if one exists. If neither is present we still try the live
        # catalogue lookup — the actor may be known to Cyble but never
        # observed in this tenant.
        row = session.exec(
            select(ThreatActor)
            .where(ThreatActor.tenant_id == tenant_id)
            .where(ThreatActor.handle == handle)
        ).first()
        if row is None:
            row = session.exec(
                select(ThreatActor)
                .where(ThreatActor.tenant_id == "__global__")
                .where(ThreatActor.handle == handle)
            ).first()
        if row is not None:
            row_snapshot = {
                "tenant_id": row.tenant_id,
                "handle": row.handle,
                "aliases": list(row.aliases or []),
                "description": row.description,
                "motivation": row.motivation.value,
                "sophistication": row.sophistication.value,
                "origin_country": row.origin_country,
                "target_sectors": list(row.target_sectors or []),
                "target_regions": list(row.target_regions or []),
                "techniques": list(row.techniques or []),
                "tools": list(row.tools or []),
                "campaigns": list(row.campaigns or []),
                "references": list(row.references or []),
                "confidence": row.confidence,
                "active": row.active,
                "first_observed": (
                    row.first_observed.isoformat()
                    if row.first_observed
                    else None
                ),
                "last_observed": (
                    row.last_observed.isoformat()
                    if row.last_observed
                    else None
                ),
            }

        # Pull the linked IOCs from the tenant's view. Global IOCs the
        # tenant observed during a sweep get linked under the tenant
        # scope (see ThreatActorProfilingAgent._upsert_link).
        link_rows = session.exec(
            select(ActorIOCLink)
            .where(ActorIOCLink.tenant_id == tenant_id)
            .where(ActorIOCLink.actor_handle == handle)
            .order_by(ActorIOCLink.last_seen.desc())
        ).all()
        link_snapshot = [
            {
                "value": link.ioc_value,
                "type": link.ioc_type,
                "confidence": link.confidence,
                "source": link.source,
                "first_seen": (
                    link.first_seen.isoformat() if link.first_seen else None
                ),
                "last_seen": (
                    link.last_seen.isoformat() if link.last_seen else None
                ),
            }
            for link in link_rows
        ]

    # Live catalogue overlay. Pure read; safe to call from the API.
    catalogue: dict[str, Any] = {}
    catalogue_hit = False
    td = registry.get("cti.actor_lookup")
    if td is not None and registry.is_allowed_for_tenant(
        "cti.actor_lookup", tenant_id
    ):
        try:
            payload = await td.handler(actor=handle)
            if isinstance(payload, dict) and payload.get("found"):
                catalogue = payload
                catalogue_hit = True
        except Exception:  # noqa: BLE001
            logger.exception(
                "actor_routes: cti.actor_lookup failed handle=%s tenant=%s",
                handle,
                tenant_id,
            )

    if row_snapshot is None and not catalogue_hit:
        raise HTTPException(
            status_code=404, detail=f"Unknown actor handle: {handle}"
        )

    # Merge: tenant row wins per-field when set, catalogue fills holes.
    def _pick(field_name: str, fallback: Any) -> Any:
        row_val = (
            row_snapshot.get(field_name) if row_snapshot is not None else None
        )
        # Lists: empty list counts as "unset" for merge purposes.
        if isinstance(row_val, list):
            return row_val if row_val else (catalogue.get(field_name) or fallback)
        if row_val:
            return row_val
        return catalogue.get(field_name) or fallback

    iocs = [
        ActorIOC(
            value=item["value"],
            type=item["type"],
            confidence=item["confidence"],
            source=item["source"],
            first_seen=item["first_seen"],
            last_seen=item["last_seen"],
        )
        for item in link_snapshot
    ]

    return ActorCard(
        handle=handle,
        tenant_id=(
            row_snapshot["tenant_id"] if row_snapshot is not None else "__global__"
        ),
        aliases=_pick("aliases", []),
        description=_pick("description", ""),
        motivation=(
            row_snapshot["motivation"]
            if row_snapshot is not None
            else (catalogue.get("motivation") or "unknown")
        ),
        sophistication=(
            row_snapshot["sophistication"]
            if row_snapshot is not None
            else (catalogue.get("sophistication") or "unknown")
        ),
        origin_country=_pick("origin_country", None),
        target_sectors=_pick("target_sectors", []),
        target_regions=_pick("target_regions", []),
        techniques=_pick("techniques", []),
        tools=_pick("tools", []),
        campaigns=_pick("campaigns", []),
        references=_pick("references", []),
        confidence=(
            row_snapshot["confidence"]
            if row_snapshot is not None
            else int(
                (catalogue.get("confidence") or 0.5) * 100
                if isinstance(catalogue.get("confidence"), float)
                else (catalogue.get("confidence") or 50)
            )
        ),
        active=row_snapshot["active"] if row_snapshot is not None else True,
        first_observed=(
            row_snapshot["first_observed"] if row_snapshot is not None else None
        ),
        last_observed=(
            row_snapshot["last_observed"] if row_snapshot is not None else None
        ),
        catalogue_hit=catalogue_hit,
        iocs=iocs,
    )


__all__ = ["router"]
