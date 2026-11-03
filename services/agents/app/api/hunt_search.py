"""
Hunt search & saved-searches API.

The console's threat-hunter view posts ad-hoc queries here and saves/retrieves
search bookmarks. This is *distinct* from the hunt-corpus YAML runner
(``hunts.py``); this module handles free-form telemetry search.

Endpoints (under ``/api/v1/hunt``):

    POST /search          — substring-match a term against this tenant's lake events
    GET  /saved           — list saved searches for the current tenant
    POST /saved           — save a new search
    DELETE /saved/{id}    — delete a saved search
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api import conversation_store
from app.security.tenant_scope import (
    TenantPrincipal,
    TenantScopeError,
    require_console_or_service_auth,
    resolve_scoped_tenant,
)

logger = structlog.get_logger()

#: Default-deny. The console reaches this router directly through a Next
#: rewrite carrying the first-party access token, so the guard resolves
#: either that session or a trusted service declaring the tenant it acts
#: for — a bearer-token-only scheme would lock the browser out.
router = APIRouter(prefix="/api/v1/hunt", tags=["hunt-search"], dependencies=[Depends(require_console_or_service_auth)])


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class HuntQuery(BaseModel):
    query: str
    language: str = "lucene"  # lucene | eql | sigma | spl
    timeRange: str | None = "24h"
    indices: list[str] | None = None
    limit: int = 100


class HuntHit(BaseModel):
    id: str
    timestamp: str
    source: str
    event_type: str
    raw: dict[str, Any]
    #: Always present. This was ``list[str] | None = None`` while every code
    #: path set it, so ``null`` and ``[]`` were two spellings of "nothing
    #: matched" and a caller had to handle both for a case the handler has
    #: never produced. One representation per value, decided here rather
    #: than in each consumer.
    highlights: list[str]


#: Every value ``HuntResponse.source`` can take, and nothing else. Named once
#: so the declared vocabulary and the branches that produce it cannot drift:
#: the field used to declare ``live`` while no code path could return it, and
#: a ``Literal`` member nothing produces is a contract callers write dead code
#: against. A test asserts this set equals the annotation's arguments.
HUNT_SOURCES = ("live", "unavailable")


class HuntResponse(BaseModel):
    query: str
    total: int
    #: How long the lake read took. ``None`` when no query ran.
    #:
    #: Not ``0``. This handler used to time the *generation of fabricated
    #: hits* and publish the result, so a query that never happened reported
    #: a measured ``0ms`` next to a real-looking hit count — the same claim as
    #: the hardcoded ``took: 42`` removed before it, with a humbler number.
    took_ms: int | None = None
    hits: list[HuntHit]
    #: Where the hits came from.
    #:
    #: ``live`` — the tenant's event lake answered. Zero hits here means the
    #: lake has nothing matching, which is a result.
    #: ``unavailable`` — no query ran, and ``notice`` says why. Zero hits here
    #: is not a result and must never render as one.
    #:
    #: There is deliberately no third value for invented telemetry. The
    #: handler used to return five fabricated CrowdStrike process events
    #: unconditionally; that generator is deleted rather than reworded,
    #: because a path that invents evidence is the defect and not the
    #: wording of its disclaimer.
    source: Literal["live", "unavailable"]
    #: Human-readable reason, surfaced in the UI banner.
    notice: str | None = None


class LakeAnswer(BaseModel):
    """What the lake read produced, including the case where it could not run.

    A single return type rather than an exception for the unavailable case,
    so "the lake is not part of this deployment" is a value the handler
    renders rather than a control-flow surprise it has to remember to catch.
    """

    available: bool
    reason: str | None
    hits: list[dict[str, Any]]


class SavedSearchCreate(BaseModel):
    name: str
    query: str
    language: str = "lucene"


class SavedSearch(BaseModel):
    id: str
    name: str
    query: str
    language: str
    createdAt: str
    pinned: bool = False


# ---------------------------------------------------------------------------
# Tenant-scoped persistence
# ---------------------------------------------------------------------------
#
# This was a module-level dict with no tenant, listed by a handler that bound
# no principal, so one analyst's saved searches were returned to every other
# tenant and a restart lost all of them. A saved hunt search is the query an
# analyst wrote against their own telemetry, which names their hosts, their
# users and what they were looking for.


def _tenant_of(principal: TenantPrincipal) -> uuid.UUID:
    try:
        return resolve_scoped_tenant(principal)
    except TenantScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


#: ``timeRange`` as the console sends it. Anything unrecognised falls back to
#: the default rather than silently searching a window nobody asked for.
_WINDOW_HOURS = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "2d": 48, "7d": 168, "30d": 720}
_DEFAULT_WINDOW_HOURS = 24


def _window_hours(time_range: str | None) -> int:
    return _WINDOW_HOURS.get((time_range or "").strip().lower(), _DEFAULT_WINDOW_HOURS)


def _to_hit(event: dict[str, Any], term: str) -> dict[str, Any]:
    """One lake row as the console's hit shape."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": event.get("event_time") or datetime.now(UTC).isoformat(),
        # The connector that recorded it, which is the honest answer to
        # "where did this come from" — not a vendor name this handler chose.
        "source": event.get("connector_type") or "unknown",
        "event_type": str(event.get("class_uid") or "event"),
        "raw": event,
        "highlights": [term] if term else [],
    }


async def _search_lake(tenant_ref: str, term: str, *, hours: int, limit: int) -> LakeAnswer:
    """Run the search against this tenant's lake, or say why it could not.

    The read is synchronous (``clickhouse-driver`` has no async client) and
    is therefore pushed to a worker thread: an ``async def`` that blocks on a
    socket blocks the whole event loop, which is how this service once
    answered nothing at all during a feed ingest.

    An unreachable lake is reported, never substituted. On the CORE profile
    ClickHouse is genuinely not deployed, and the honest answer there is "no
    query ran" — not an empty result, and emphatically not sample events.
    """
    try:
        from app.hunt.lake_source import search_events
    except ImportError as exc:  # pragma: no cover - the module ships with the service
        return LakeAnswer(available=False, reason=f"the lake reader is not available in this image ({exc})", hits=[])

    try:
        rows = await asyncio.to_thread(search_events, tenant_ref, term, hours=hours, cap=limit)
    except Exception as exc:  # noqa: BLE001 - any lake failure is reported, never swallowed into an empty page
        detail = str(exc)[:200].replace("\r", "").replace("\n", " ")
        logger.warning("hunt.search.lake_unavailable", error=detail)
        return LakeAnswer(
            available=False,
            reason=(
                "the event lake did not answer, so no query ran. ClickHouse runs in the `full` profile "
                f"and is not part of a CORE deployment ({detail})"
            ),
            hits=[],
        )

    return LakeAnswer(available=True, reason=None, hits=[_to_hit(row, term) for row in rows])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/search", response_model=HuntResponse)
async def hunt_search(
    query: HuntQuery,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> HuntResponse:
    """Match a term against this tenant's recorded events in the lake.

    What this does and does not do, stated here because the previous
    docstring said "Execute a hunt query and return matching telemetry
    events" over a handler that executed nothing:

    * It **is** a real read of ``aisoc.raw_events``, scoped to the caller's
      tenant by a bound predicate, with the term bound as a parameter.
    * It is a **substring match**, not an execution of the selected query
      language. Lucene, EQL, Sigma and SPL are not parsed here, and the
      response says so rather than letting a structured query quietly degrade
      into a text match that returns confident nonsense.

    The handler binds a principal. It previously bound none at all, which was
    survivable only because it never touched a store; the moment it reads one
    there is no tenant to scope by without it.
    """
    tenant_ref = str(_tenant_of(principal))
    term = query.query.strip()
    hours = _window_hours(query.timeRange)

    start = time.monotonic()
    answer = await _search_lake(tenant_ref, term, hours=hours, limit=max(1, min(query.limit, 500)))

    if not answer.available:
        # No query ran. No latency, no hits, and a reason that does not send
        # the reader to the page they are already on.
        return HuntResponse(
            query=query.query,
            total=0,
            took_ms=None,
            hits=[],
            source="unavailable",
            notice=f"No query ran: {answer.reason}.",
        )

    took_ms = int((time.monotonic() - start) * 1000)
    notice: str | None = None
    if query.language and query.language.lower() != "lucene":
        notice = (
            f"Matched {term!r} as free text against your recorded events. "
            f"{query.language.upper()} is not executed by this endpoint, so a structured query was "
            "treated as a search term."
        )
    return HuntResponse(
        query=query.query,
        total=len(answer.hits),
        took_ms=took_ms,
        hits=[HuntHit(**h) for h in answer.hits],
        source="live",
        notice=notice,
    )


@router.get("/saved")
async def list_saved_searches(
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> dict[str, list[dict[str, Any]]]:
    """This tenant's saved searches, newest first."""
    rows = await conversation_store.list_saved_searches(tenant_id=_tenant_of(principal))
    return {
        "searches": [
            {
                "id": row.id,
                "name": row.name,
                "query": row.query,
                "language": row.backend,
                "createdAt": row.updated_at,
                "pinned": False,
            }
            for row in rows
        ]
    }


@router.post("/saved", response_model=SavedSearch, status_code=201)
async def save_search(
    data: SavedSearchCreate,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> SavedSearch:
    """Persist a new saved search against the caller's tenant."""
    row = await conversation_store.save_search(
        tenant_id=_tenant_of(principal),
        user_id=None,
        name=data.name,
        query=data.query,
        backend=data.language,
    )
    return SavedSearch(
        id=row.id,
        name=row.name,
        query=row.query,
        language=row.backend,
        createdAt=row.updated_at,
    )


@router.delete("/saved/{search_id}", status_code=204, response_model=None)
async def delete_saved_search(
    search_id: str,
    principal: TenantPrincipal = Depends(require_console_or_service_auth),
) -> None:
    """Delete one of this tenant's saved searches.

    The delete carries the tenant predicate, so an id belonging to another
    tenant removes nothing and answers 404 — the same answer as an id that
    does not exist, which is what stops the route being a probe for whether
    one does.
    """
    deleted = await conversation_store.delete_saved_search(tenant_id=_tenant_of(principal), search_id=search_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="saved search not found")
