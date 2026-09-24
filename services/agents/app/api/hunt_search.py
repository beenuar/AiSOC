"""
Hunt search & saved-searches API.

The console's threat-hunter view posts ad-hoc queries here and saves/retrieves
search bookmarks. This is *distinct* from the hunt-corpus YAML runner
(``hunts.py``); this module handles free-form telemetry search.

Endpoints (under ``/api/v1/hunt``):

    POST /search          — execute a hunt query against telemetry
    GET  /saved           — list saved searches for the current tenant
    POST /saved           — save a new search
    DELETE /saved/{id}    — delete a saved search
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.security.tenant_scope import require_console_or_service_auth

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
    highlights: list[str] | None = None


class HuntResponse(BaseModel):
    query: str
    total: int
    took_ms: int
    hits: list[HuntHit]
    #: Where the hits came from. ``sample`` means this handler generated
    #: illustrative telemetry rather than querying anything.
    #:
    #: This field exists because the endpoint returns synthetic hits
    #: unconditionally and used to say nothing about it. A 200 with no marker
    #: read to the console as a successful live query, so the hunt workbench
    #: rendered a green "Live backend" pill over fabricated CrowdStrike process
    #: events. A caller must be able to tell the difference without reading
    #: this file.
    source: Literal["sample", "live"] = "sample"
    #: Human-readable reason, surfaced in the UI banner.
    notice: str | None = None


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
# In-memory store (demo; production would persist to Postgres)
# ---------------------------------------------------------------------------

_SAVED_SEARCHES: dict[str, SavedSearch] = {}


def _synthetic_hits(query: str, limit: int) -> list[dict[str, Any]]:
    """Return plausible-looking synthetic telemetry hits for demo mode."""
    templates = [
        {
            "source": "crowdstrike",
            "event_type": "ProcessCreation",
            "raw": {
                "process_name": "cmd.exe",
                "parent_name": "explorer.exe",
                "cmdline": f"cmd.exe /c {query}",
                "user": "DOMAIN\\analyst",
                "host": "WS-DEV-01",
            },
        },
        {
            "source": "azure_ad",
            "event_type": "SignInLog",
            "raw": {
                "userPrincipalName": "user@corp.example",
                "ipAddress": "192.0.2.42",
                "location": "US",
                "appDisplayName": "Microsoft 365",
                "resultType": "0",
            },
        },
        {
            "source": "aws_cloudtrail",
            "event_type": "AssumeRole",
            "raw": {
                "eventName": "AssumeRole",
                "sourceIPAddress": "10.0.0.100",
                "userAgent": "aws-sdk-python",
                "requestParameters": {"roleArn": "arn:aws:iam::123456789:role/Admin"},
            },
        },
    ]
    now = datetime.now(UTC)
    hits = []
    for i in range(min(limit, 5)):
        t = templates[i % len(templates)]
        hits.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "source": t["source"],
                "event_type": t["event_type"],
                "raw": t["raw"],
                "highlights": [query] if query else [],
            }
        )
    return hits


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/search", response_model=HuntResponse)
async def hunt_search(query: HuntQuery) -> HuntResponse:
    """Execute a hunt query and return matching telemetry events."""
    import time

    start = time.monotonic()

    hits_raw = _synthetic_hits(query.query, query.limit)

    took_ms = int((time.monotonic() - start) * 1000)
    return HuntResponse(
        query=query.query,
        total=len(hits_raw),
        took_ms=took_ms,
        hits=[HuntHit(**h) for h in hits_raw],
        source="sample",
        notice=(
            "These are illustrative sample events, not results from your telemetry. "
            "This endpoint does not yet execute the query against the event lake; "
            "run the hunt from /hunt against a configured data source for real hits."
        ),
    )


@router.get("/saved")
async def list_saved_searches() -> dict[str, list[dict[str, Any]]]:
    """Return all saved searches."""
    return {"searches": [s.model_dump() for s in _SAVED_SEARCHES.values()]}


@router.post("/saved", response_model=SavedSearch, status_code=201)
async def save_search(data: SavedSearchCreate) -> SavedSearch:
    """Persist a new saved search."""
    ss = SavedSearch(
        id=str(uuid.uuid4()),
        name=data.name,
        query=data.query,
        language=data.language,
        createdAt=datetime.now(UTC).isoformat(),
    )
    _SAVED_SEARCHES[ss.id] = ss
    return ss


@router.delete("/saved/{search_id}", status_code=204, response_model=None)
async def delete_saved_search(search_id: str) -> None:
    """Delete a saved search by ID."""
    if search_id not in _SAVED_SEARCHES:
        raise HTTPException(status_code=404, detail="saved search not found")
    del _SAVED_SEARCHES[search_id]
