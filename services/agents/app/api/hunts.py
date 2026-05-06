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
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.hunt import HuntCorpus
from app.hunt import scheduler as hunt_scheduler
from app.hunt import store as hunt_store

logger = logging.getLogger("aisoc.api.hunts")
router = APIRouter(prefix="/api/v1/hunts", tags=["hunts"])


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


@router.get("/{hunt_id}", summary="Get a single hunt definition")
async def get_hunt(hunt_id: str) -> dict[str, Any]:
    corpus = HuntCorpus.default()
    h = corpus.get(hunt_id)
    if h is None:
        raise HTTPException(status_code=404, detail=f"hunt {hunt_id} not found")
    return _hunt_summary(h)


@router.post("/reload", summary="Reload corpus from disk + re-sync catalog")
async def reload_hunts() -> dict[str, Any]:
    corpus = HuntCorpus.default()
    count = corpus.reload()
    synced = await hunt_store.sync_catalog(corpus.list())
    return {"loaded": count, "synced": synced}


# ---------------------------------------------------------------------------
# Run on demand
# ---------------------------------------------------------------------------


@router.post("/{hunt_id}/run", summary="Run a hunt on demand")
async def run_hunt(hunt_id: str) -> dict[str, Any]:
    sched = hunt_scheduler.get_scheduler()
    out = await sched.run_one(hunt_id)
    if not out.get("ok"):
        raise HTTPException(
            status_code=404, detail=out.get("error", "hunt run failed")
        )
    return out


# ---------------------------------------------------------------------------
# Read-side (DB-backed)
# ---------------------------------------------------------------------------


@router.get("/runs", summary="Recent hunt runs")
async def list_runs(
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    return await hunt_store.list_recent_runs(limit=limit)


@router.get("/findings", summary="Recent hunt findings")
async def list_findings(
    hunt_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return await hunt_store.list_recent_findings(
        hunt_id=hunt_id, status=status, limit=limit
    )
