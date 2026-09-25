"""Read the indicators this service has collected.

Why this route exists
---------------------
The console ships a `/threat-intel` page that calls
``GET /api/v1/threat-intel/indicators``. Nothing implemented it. The page was
recently caught rendering five invented IOCs and a hard-coded "3 Added Today"
counter on tenants that had never ingested one; removing the fabrication left
the page correct and empty, because the real feed was in the `full` profile and
the endpoint it wanted did not exist in any profile. The missing feed and the
fabrication were one hole.

``services/threatintel`` and Qdrant now ship in CORE, and the CISA Known
Exploited Vulnerabilities catalog is authoritative, public and needs no API
key — so a default ``make up`` collects real indicators. This route serves
them, and the API proxies it.

Why Qdrant and not OpenSearch
-----------------------------
``ThreatIntelPipeline`` writes to three sinks. OpenSearch is the full-text one
and stays in the `full` profile; Qdrant is the one CORE has, it already carries
the complete IOC payload on every point, and ``tenant_scope_filter`` already
expresses the read scope this route needs — public feed intel under the
``shared`` sentinel, private intel under its owning tenant. Serving from the
store that is actually present is what makes the page work in CORE.

Scrolling a vector store is an unusual list path, and it is bounded on purpose:
``limit`` is capped, and this is a browse surface, not an export.
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from qdrant_client import AsyncQdrantClient

from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from app.storage.qdrant import IOC_COLLECTION, tenant_scope_filter

logger = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
    dependencies=[Depends(require_console_or_service_auth)],
)

#: Ceiling on one page. The console renders a browse list; anything wanting
#: the whole catalog should read the feed at source.
MAX_LIMIT = 500


class Indicator(BaseModel):
    """One indicator, in the shape the console's IOC inbox renders.

    Deliberately permissive about the source payload: feeds disagree about
    which fields they carry, and a missing `description` is not a reason to
    drop a real IOC from the list.
    """

    type: str
    value: str
    description: str | None = None
    confidence: int = 50
    malicious: bool = True
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    tlp: str | None = None


class IndicatorListResponse(BaseModel):
    indicators: list[Indicator]
    total: int
    #: Which store answered. The console has no other way to tell "no
    #: indicators collected yet" from "the store is not there", and the two
    #: call for different things from the reader.
    source: str


def _to_indicator(payload: dict[str, Any]) -> Indicator:
    raw_tags = payload.get("tags")
    tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
    source = payload.get("source")
    return Indicator(
        type=str(payload.get("type") or "unknown"),
        value=str(payload.get("value") or ""),
        description=payload.get("description") or payload.get("vulnerability_name") or None,
        confidence=int(payload.get("confidence") or 50),
        # A feed entry is an indicator of compromise; CISA KEV in particular
        # lists vulnerabilities under active exploitation. `false` here would
        # be a claim the feed does not make.
        malicious=bool(payload.get("malicious", True)),
        sources=[str(source)] if source else [],
        tags=tags,
        first_seen=payload.get("first_seen") or payload.get("date_added"),
        last_seen=payload.get("last_seen") or payload.get("date_added"),
        tlp=payload.get("tlp"),
    )


def _qdrant(request: Request) -> AsyncQdrantClient:
    client = getattr(request.app.state, "qdrant_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="vector store is not configured on this deployment")
    return client


@router.get("/indicators", response_model=IndicatorListResponse)
async def list_indicators(
    request: Request,
    principal: Annotated[TenantPrincipal, Depends(require_console_or_service_auth)],
    # `alias` keeps the query string `?type=` the console already sends while
    # the parameter itself is named something that does not shadow `type()` —
    # which this function calls, in the except arm below.
    ioc_type: str | None = Query(default=None, alias="type", description="filter to one indicator type"),
    tag: str | None = Query(default=None),
    q: str | None = Query(default=None, description="substring match on value or description"),
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
) -> IndicatorListResponse:
    """Indicators collected by the feed scheduler, scoped to the caller.

    ``tenant_scope_filter`` is what enforces the scope: a caller sees their own
    tenant's points plus the ``shared`` sentinel that public feed intel is
    written under. A principal with no tenants is an empty scope, never a
    global one.
    """
    client = _qdrant(request)

    tenant_ids = principal.ordered_ids()
    scope = tenant_scope_filter(str(tenant_ids[0]) if tenant_ids else None)

    try:
        points, _next_page = await client.scroll(
            collection_name=IOC_COLLECTION,
            scroll_filter=scope,
            # Over-read so post-filtering (`q`, `tag`, `type`) still fills a
            # page. Bounded at 4x so a wide filter cannot walk the collection.
            limit=min(limit * 4, MAX_LIMIT * 4),
            with_payload=True,
            with_vectors=False,
        )
    except Exception as exc:
        # An absent collection is "nothing collected yet", not an error; the
        # scheduler creates it on the first successful poll. Anything else is
        # reported rather than rendered as an empty list, because an empty list
        # is indistinguishable from a working store with no data.
        message = str(exc)
        if "not found" in message.lower() or "doesn't exist" in message.lower():
            logger.info("threatintel.indicators.collection_absent", collection=IOC_COLLECTION)
            return IndicatorListResponse(indicators=[], total=0, source="qdrant")
        logger.warning("threatintel.indicators.read_failed", error=type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="the threat-intel vector store did not answer; no indicators can be listed",
        ) from exc

    indicators = [_to_indicator(p.payload or {}) for p in points if p.payload]

    if ioc_type:
        indicators = [i for i in indicators if i.type == ioc_type]
    if tag:
        indicators = [i for i in indicators if tag in i.tags]
    if q:
        needle = q.lower()
        indicators = [i for i in indicators if needle in i.value.lower() or needle in (i.description or "").lower()]

    total = len(indicators)
    return IndicatorListResponse(indicators=indicators[:limit], total=total, source="qdrant")
