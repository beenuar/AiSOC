"""Internal threat-intel generation endpoints.

Access control
--------------
Threat-intel data (IOCs, threat actors, feeds) is sensitive in MSSP/multi-tenant
deployments — a noisy or malicious analyst could otherwise poison detections
across the whole tenant by injecting false IOCs or deleting feeds.

All endpoints below are gated on RBAC permissions resolved by
``app.api.v1.deps.require_permission``:

* ``threat_intel:read``  – list / get
* ``threat_intel:write`` – create / delete

The ``viewer`` role gets read access; analyst-tier roles
(``threat_hunter``, ``soc_lead``, ``tenant_admin``) get write access.
See ``app.core.security.ROLE_PERMISSIONS`` for the authoritative map.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.db.database import get_db
from app.models.threat_intel import ThreatActor, ThreatIntelFeed, ThreatIntelIOC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

#: Header a trusted service uses to declare which tenant it is acting for.
#: Must match ``TENANT_HEADER`` in
#: services/threatintel/app/security/tenant_scope.py.
_TENANT_HEADER = "X-AiSOC-Tenant-ID"


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "medium"
    tlp: str = "amber"
    threat_actor: str | None = None
    campaign: str | None = None
    malware_family: str | None = None
    tags: list[str] | None = None
    source: str = "internal"
    source_ref: str | None = None
    expires_at: datetime | None = None
    linked_alerts: list[uuid.UUID] | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class IOCOut(IOCCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_active: bool
    false_positive: bool
    first_seen: str
    last_seen: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class ThreatActorCreate(BaseModel):
    name: str
    aliases: list[str] | None = None
    motivation: str | None = None
    sophistication: str | None = None
    country_of_origin: str | None = None
    target_sectors: list[str] | None = None
    ttps: list[str] | None = None
    description: str | None = None
    first_observed: datetime | None = None
    last_activity: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatActorOut(ThreatActorCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_active: bool
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class FeedCreate(BaseModel):
    name: str
    feed_type: str
    url: str | None = None
    api_key_ref: str | None = None
    poll_interval: int = 3600
    config: dict[str, Any] = Field(default_factory=dict)


class FeedOut(FeedCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_enabled: bool
    last_polled_at: str | None = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Collected feed indicators (proxied from services/threatintel)
# ---------------------------------------------------------------------------


class FeedIndicatorsResponse(BaseModel):
    """What the console's `/threat-intel` page renders.

    ``source`` and ``degraded`` travel with the payload for the same reason
    they do on the connector catalog: an empty list because nothing has been
    collected yet and an empty list because the service is not deployed are
    different facts, and a reader cannot tell them apart from the rows alone.
    """

    indicators: list[dict[str, Any]]
    #: Indicators in the caller's scope, per the upstream store's own count.
    total: int
    #: Indicators carried by this response. ``total`` is the catalogue,
    #: ``shown`` is the page — the console renders "N of M" and used to render
    #: the page size as the catalogue.
    shown: int = 0
    #: Upstream narrowed inside a bounded scan window, so ``shown`` is a lower
    #: bound on the matches that exist.
    bounded: bool = False
    source: str
    degraded: bool = False
    reason: str = ""


@router.get("/indicators", response_model=FeedIndicatorsResponse)
async def list_feed_indicators(
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:read"))],
    # `alias` preserves the `?type=` the console sends while keeping the
    # builtin `type()` callable in this scope — it is used in the except arm.
    ioc_type: str | None = Query(None, alias="type", description="filter to one indicator type"),
    tag: str | None = Query(None),
    q: str | None = Query(None, description="substring match on value or description"),
) -> FeedIndicatorsResponse:
    """Indicators the feed scheduler has collected, from `services/threatintel`.

    The console has called this path since the IOC inbox shipped and nothing
    served it — the page 404'd, and for a while rendered five invented IOCs
    instead. `services/threatintel` and its Qdrant store are in CORE now, and
    the CISA Known Exploited Vulnerabilities catalog is public and keyless, so
    a default install has real indicators to show within a poll interval.

    Tenant scope is enforced upstream: this proxy asserts the caller's tenant
    in the same header the connectors proxy uses, and the threatintel route
    filters on it plus the `shared` sentinel that public feed intel is written
    under.
    """
    base = (getattr(settings, "THREATINTEL_SERVICE_URL", "") or "").strip().rstrip("/")
    if not base:
        return FeedIndicatorsResponse(
            indicators=[],
            total=0,
            source="unconfigured",
            degraded=True,
            reason="THREATINTEL_SERVICE_URL is not set on this deployment",
        )

    params = {k: v for k, v in (("type", ioc_type), ("tag", tag), ("q", q)) if v}
    headers: dict[str, str] = {_TENANT_HEADER: str(current_user.tenant_id)}
    token = (os.getenv("AISOC_THREATINTEL_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    timeout = httpx.Timeout(settings.THREATINTEL_SERVICE_TIMEOUT_SECONDS, connect=5.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{base}/api/v1/threat-intel/indicators", params=params, headers=headers)
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        upstream_status = getattr(getattr(exc, "response", None), "status_code", None)
        logger.warning(
            "threatintel.indicators.unreachable error_type=%s status=%s",
            type(exc).__name__,
            upstream_status,
        )
        return FeedIndicatorsResponse(
            indicators=[],
            total=0,
            source="unavailable",
            degraded=True,
            reason=(
                f"the threat-intel service did not answer ({type(exc).__name__}"
                + (f", HTTP {upstream_status}" if upstream_status else "")
                + "); no indicators can be listed"
            ),
        )

    if not isinstance(body, dict):
        return FeedIndicatorsResponse(indicators=[], total=0, source="unavailable", degraded=True, reason="malformed upstream response")

    raw = body.get("indicators")
    indicators = [i for i in raw if isinstance(i, dict)] if isinstance(raw, list) else []
    return FeedIndicatorsResponse(
        indicators=indicators,
        total=int(body.get("total") or len(indicators)),
        shown=int(body.get("shown") or len(indicators)),
        bounded=bool(body.get("bounded")),
        source=str(body.get("source") or "threatintel"),
    )


# ---------------------------------------------------------------------------
# IOC endpoints
# ---------------------------------------------------------------------------


@router.get("/iocs", response_model=list[IOCOut])
async def list_iocs(
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:read"))],
    ioc_type: str | None = Query(None),
    severity: str | None = Query(None),
    is_active: bool | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatIntelIOC]:
    q = select(ThreatIntelIOC).where(ThreatIntelIOC.tenant_id == current_user.tenant_id)
    if ioc_type:
        q = q.where(ThreatIntelIOC.ioc_type == ioc_type)
    if severity:
        q = q.where(ThreatIntelIOC.severity == severity)
    if is_active is not None:
        q = q.where(ThreatIntelIOC.is_active == is_active)
    q = q.order_by(ThreatIntelIOC.last_seen.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/iocs", response_model=IOCOut, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    body: IOCCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:write"))],
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelIOC:
    ioc = ThreatIntelIOC(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.get("/iocs/{ioc_id}", response_model=IOCOut)
async def get_ioc(
    ioc_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:read"))],
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelIOC:
    ioc = await db.get(ThreatIntelIOC, ioc_id)
    if not ioc or ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_ioc(
    ioc_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:write"))],
    db: AsyncSession = Depends(get_db),
) -> None:
    ioc = await db.get(ThreatIntelIOC, ioc_id)
    if not ioc or ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="IOC not found")
    await db.delete(ioc)
    await db.commit()


# ---------------------------------------------------------------------------
# Threat actor endpoints
# ---------------------------------------------------------------------------


@router.get("/actors", response_model=list[ThreatActorOut])
async def list_actors(
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:read"))],
    is_active: bool | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatActor]:
    q = select(ThreatActor).where(ThreatActor.tenant_id == current_user.tenant_id)
    if is_active is not None:
        q = q.where(ThreatActor.is_active == is_active)
    q = q.order_by(ThreatActor.name).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/actors", response_model=ThreatActorOut, status_code=status.HTTP_201_CREATED)
async def create_actor(
    body: ThreatActorCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:write"))],
    db: AsyncSession = Depends(get_db),
) -> ThreatActor:
    actor = ThreatActor(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return actor


# ---------------------------------------------------------------------------
# Feed management endpoints
# ---------------------------------------------------------------------------


@router.get("/feeds", response_model=list[FeedOut])
async def list_feeds(
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:read"))],
    db: AsyncSession = Depends(get_db),
) -> list[ThreatIntelFeed]:
    result = await db.execute(
        select(ThreatIntelFeed).where(ThreatIntelFeed.tenant_id == current_user.tenant_id).order_by(ThreatIntelFeed.name)
    )
    return list(result.scalars().all())


@router.post("/feeds", response_model=FeedOut, status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:write"))],
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelFeed:
    feed = ThreatIntelFeed(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_feed(
    feed_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("threat_intel:write"))],
    db: AsyncSession = Depends(get_db),
) -> None:
    feed = await db.get(ThreatIntelFeed, feed_id)
    if not feed or feed.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Feed not found")
    await db.delete(feed)
    await db.commit()
