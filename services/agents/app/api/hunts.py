"""Hunt-as-code REST API (Wave 2 — w2-hac).

Endpoints:

* ``GET  /api/v1/hunts``                   — list YAML corpus
* ``GET  /api/v1/hunts/{hunt_id}``         — single hunt definition
* ``POST /api/v1/hunts/{hunt_id}/run``     — run a hunt on demand
* ``GET  /api/v1/hunts/runs``              — recent runs (DB-backed)
* ``GET  /api/v1/hunts/findings``          — recent findings (DB-backed,
                                              filterable by ``hunt_id`` /
                                              ``status``)
* ``POST /api/v1/hunts/reload``            — reload the corpus from disk
                                              and re-sync the catalog table

The corpus itself is the source of truth; the database tables exist so the
console can list runs/findings without re-reading every YAML on every
request. All write paths are best-effort: if the database is unreachable
the endpoint still returns the in-memory result so an operator can run a
hunt during a DB outage.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.hunt import HuntCorpus
from app.hunt import scheduler as hunt_scheduler
from app.hunt import store as hunt_store
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)

logger = logging.getLogger("aisoc.api.hunts")
#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/hunts", tags=["hunts"], dependencies=[Depends(require_console_or_service_auth)])

#: The resolved caller, bound as a handler parameter.
#:
#: Same defect as the playbooks router next door (GHSA-27wx-pcv5-pr7q): the
#: router-level dependency authenticated every request and bound nothing, so
#: the DB-backed reads below fell through to ``tenant_ref="default"`` — the
#: store's own default, which resolves to whichever tenant holds the slug
#: ``default``, i.e. the canonical seed tenant. Every caller on every
#: deployment therefore read *that* tenant's hunt runs and findings, which
#: carry finding titles, summaries and the entities they name.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]


def _hunt_summary(h: Any) -> dict[str, Any]:
    """Trim a HuntDefinition into a console-friendly dict."""
    return {
        "id": h.id,
        "name": h.name,
        "description": h.description,
        "version": h.version,
        "severity": h.severity,
        "category": h.category,
        "tags": list(h.tags),
        "log_sources": list(h.log_sources),
        "schedule": {
            "enabled": h.schedule.enabled,
            "interval_minutes": h.schedule.interval_minutes,
            "jitter_seconds": h.schedule.jitter_seconds,
        },
        "hypothesis": h.hypothesis.model_dump(by_alias=True),
        "expected": h.expected.model_dump(),
        "references": list(h.references),
        "author": h.author,
        "source_sha256": h.source_sha256,
        "source_path": h.source_path,
    }


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@router.get("", summary="List hunts in the YAML corpus")
async def list_hunts() -> list[dict[str, Any]]:
    corpus = HuntCorpus.default()
    return [_hunt_summary(h) for h in corpus.list()]


@router.get("/runs", summary="Recent hunt runs")
async def list_runs(
    principal: ScopedPrincipal,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    return await hunt_store.list_recent_runs(tenant_ref=str(scoped_tenant_or_403(principal)), limit=limit)


@router.get("/findings", summary="Recent hunt findings")
async def list_findings(
    principal: ScopedPrincipal,
    hunt_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return await hunt_store.list_recent_findings(
        tenant_ref=str(scoped_tenant_or_403(principal)),
        hunt_id=hunt_id,
        status=status,
        limit=limit,
    )


@router.get("/{hunt_id}", summary="Get a single hunt definition")
async def get_hunt(hunt_id: str) -> dict[str, Any]:
    corpus = HuntCorpus.default()
    h = corpus.get(hunt_id)
    if h is None:
        raise HTTPException(status_code=404, detail=f"hunt {hunt_id} not found")
    return _hunt_summary(h)


@router.post("/reload", summary="Reload corpus from disk + re-sync catalog")
async def reload_hunts(principal: ScopedPrincipal) -> dict[str, Any]:
    corpus = HuntCorpus.default()
    count = corpus.reload()
    synced = await hunt_store.sync_catalog(corpus.list(), tenant_ref=str(scoped_tenant_or_403(principal)))
    return {"loaded": count, "synced": synced}


# ---------------------------------------------------------------------------
# Run on demand
# ---------------------------------------------------------------------------


@router.post("/{hunt_id}/run", summary="Run a hunt on demand")
async def run_hunt(hunt_id: str, principal: ScopedPrincipal) -> dict[str, Any]:
    sched = hunt_scheduler.get_scheduler()
    # The scheduler's own ``tenant_ref`` is a process-wide default chosen at
    # boot, which is right for the timer and wrong for a person: an on-demand
    # run must search the caller's telemetry and record against the caller's
    # tenant, not whichever one the process was started for.
    out = await sched.run_one(hunt_id, tenant_ref=str(scoped_tenant_or_403(principal)))
    if not out.get("ok"):
        raise HTTPException(status_code=404, detail=out.get("error", "hunt run failed"))
    return out


# ---------------------------------------------------------------------------
# Read-side (DB-backed)
# ---------------------------------------------------------------------------
