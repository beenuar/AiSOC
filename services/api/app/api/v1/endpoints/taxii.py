"""A TAXII 2.1 server over the tenant IOC store.

Depth plan 4.2 / parity 6.10.

Two surfaces live here:

* ``/taxii2/...`` — the shape the specification fixes, which is what a
  stock TAXII client walks: discovery, API root, collections, objects and
  manifest. Paths, media type and query parameters are not ours to choose.
* ``/taxii/collections`` — management, so a tenant can publish a subset
  without an operator editing a table.

Where the tenant comes from
---------------------------
From the authenticated principal, never from the URL. The API root is a
fixed string for exactly that reason: the obvious design puts a tenant id
there, where it is a path segment any caller can retype, and the whole
point of a TAXII server is that it is pointed at by a third party.

Writes
------
Refused. ``can_write`` is in every collection response because the
specification has the field and clients read it to decide whether to offer
an upload, and it is always false: an inbound TAXII write is an outside
party inserting indicators that drive this tenant's detections. That is a
reach-out capability, and those ship off.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, require_permission
from app.db.database import get_db
from app.db.rls import TenantDBSession
from app.models.taxii import TaxiiCollection
from app.models.threat_intel import ThreatIntelIOC
from app.services.taxii import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    STIX_MEDIA_TYPE,
    TAXII_MEDIA_TYPE,
    UNPUBLISHED_IOC_TYPES,
    FilterError,
    IndicatorRow,
    clamp_limit,
    manifest_entry,
    next_cursor,
    parse_cursor,
    to_stix_indicator,
    validate_filter,
)

logger = logging.getLogger(__name__)

#: The single API root this server exposes. A fixed string, not a tenant
#: id: a tenant in the path is a tenant the caller can retype, and this
#: endpoint exists to be pointed at by a third party.
API_ROOT = "feeds"

router = APIRouter(prefix="/taxii2", tags=["taxii"])
admin_router = APIRouter(prefix="/taxii", tags=["taxii"])


def _taxii_response(payload: dict[str, Any], status_code: int = status.HTTP_200_OK) -> Response:
    """Answer with the one media type TAXII 2.1 defines.

    FastAPI's default ``application/json`` is a conformance failure that
    some clients refuse outright, and a ``response_model`` cannot set it,
    so every route here builds its own response.
    """
    import json  # noqa: PLC0415 — local to keep the module's import graph flat

    return Response(
        content=json.dumps(payload, separators=(",", ":")),
        media_type=TAXII_MEDIA_TYPE,
        status_code=status_code,
    )


def _not_found(message: str) -> HTTPException:
    """The specification's error object, not FastAPI's ``detail`` shape."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"title": "Not found", "description": message, "http_status": "404"},
    )


# ---------------------------------------------------------------------------
# Discovery and API root
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(require_permission("threat_intel:read"))])
async def discovery(request: Request) -> Response:
    """``GET /taxii2/`` — what this server is and where its API roots are."""
    base = str(request.url).split("/taxii2/")[0]
    return _taxii_response(
        {
            "title": "AiSOC threat intelligence",
            "description": "TAXII 2.1 collections over this tenant's indicator store.",
            "default": f"{base}/taxii2/{API_ROOT}/",
            "api_roots": [f"{base}/taxii2/{API_ROOT}/"],
        }
    )


@router.get("/{api_root}/", dependencies=[Depends(require_permission("threat_intel:read"))])
async def api_root_information(api_root: str) -> Response:
    """``GET /taxii2/{api-root}/`` — the limits a client must respect."""
    if api_root != API_ROOT:
        raise _not_found(f"no API root named {api_root!r}; this server serves {API_ROOT!r}")
    return _taxii_response(
        {
            "title": "AiSOC indicators",
            "description": "Indicators this tenant has chosen to publish.",
            "versions": ["application/taxii+json;version=2.1"],
            # Advertised rather than silently enforced: a client that asks
            # for more than this gets fewer objects back and, without the
            # advertised ceiling, no way to tell that from the end of the
            # collection.
            "max_content_length": 104_857_600,
        }
    )


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------


def _collection_json(collection: TaxiiCollection) -> dict[str, Any]:
    return {
        "id": str(collection.id),
        "title": collection.title,
        "description": collection.description or "",
        "can_read": bool(collection.can_read),
        # Always false. See the module docstring.
        "can_write": False,
        "media_types": [STIX_MEDIA_TYPE],
        **({"alias": collection.alias} if collection.alias else {}),
    }


async def _load_collection(db: AsyncSession, tenant_id: uuid.UUID, collection_ref: str) -> TaxiiCollection:
    """Resolve a collection by id or alias, scoped to the caller's tenant.

    The tenant predicate is in the query rather than left to row-level
    security alone: RLS is defence in depth here, and a collection id is
    the one value a third party is expected to hold.
    """
    conditions = [TaxiiCollection.alias == collection_ref]
    try:
        conditions.append(TaxiiCollection.id == uuid.UUID(collection_ref))
    except ValueError:
        # Not a UUID, so it can only be an alias. Not an error yet — the
        # lookup below decides.
        pass

    result = await db.execute(
        select(TaxiiCollection).where(
            and_(
                TaxiiCollection.tenant_id == tenant_id,
                TaxiiCollection.is_enabled.is_(True),
                or_(*conditions),
            )
        )
    )
    collection = result.scalar_one_or_none()
    if collection is None:
        raise _not_found(f"no collection {collection_ref!r}")
    return collection


@router.get(
    "/{api_root}/collections/",
    dependencies=[Depends(require_permission("threat_intel:read"))],
)
async def list_collections(
    api_root: str,
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """``GET /taxii2/{api-root}/collections/``."""
    if api_root != API_ROOT:
        raise _not_found(f"no API root named {api_root!r}")
    result = await db.execute(
        select(TaxiiCollection)
        .where(
            TaxiiCollection.tenant_id == current_user.tenant_id,
            TaxiiCollection.is_enabled.is_(True),
        )
        .order_by(TaxiiCollection.created_at)
    )
    return _taxii_response({"collections": [_collection_json(c) for c in result.scalars().all()]})


@router.get(
    "/{api_root}/collections/{collection_ref}/",
    dependencies=[Depends(require_permission("threat_intel:read"))],
)
async def get_collection(
    api_root: str,
    collection_ref: str,
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """``GET /taxii2/{api-root}/collections/{id}/``."""
    if api_root != API_ROOT:
        raise _not_found(f"no API root named {api_root!r}")
    collection = await _load_collection(db, current_user.tenant_id, collection_ref)
    return _taxii_response(_collection_json(collection))


# ---------------------------------------------------------------------------
# Objects and manifest
# ---------------------------------------------------------------------------


def _apply_filter(stmt: Any, ioc_filter: dict[str, Any]) -> Any:
    """Narrow the IOC query by the collection's declared filter.

    Only keys ``validate_filter`` accepts reach here, so an unknown key
    cannot arrive and be ignored.
    """
    if types := ioc_filter.get("ioc_type"):
        stmt = stmt.where(ThreatIntelIOC.ioc_type.in_(types))
    if tlps := ioc_filter.get("tlp"):
        stmt = stmt.where(ThreatIntelIOC.tlp.in_(tlps))
    if severities := ioc_filter.get("severity"):
        stmt = stmt.where(ThreatIntelIOC.severity.in_(severities))
    if sources := ioc_filter.get("source"):
        stmt = stmt.where(ThreatIntelIOC.source.in_(sources))
    if (floor := ioc_filter.get("min_confidence")) is not None:
        stmt = stmt.where(ThreatIntelIOC.confidence >= floor)
    if tags := ioc_filter.get("tags"):
        # Any-match. `overlap` is the array operator; a scalar `in_` here
        # would compare the whole array to one tag and match nothing.
        stmt = stmt.where(ThreatIntelIOC.tags.overlap(tags))
    return stmt


async def _page(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    collection: TaxiiCollection,
    added_after: str | None,
    next_token: str | None,
    limit: int,
    match_id: str | None,
    match_type: str | None,
) -> tuple[list[IndicatorRow], bool]:
    """One page of indicators, plus whether more follow.

    The sort key is ``(updated_at, id)`` and the cursor compares both.
    A bare ``updated_at >`` would skip every row sharing a timestamp with
    the last one on the previous page, and indicators written by one feed
    poll routinely share theirs to the microsecond.
    """
    stmt = select(ThreatIntelIOC).where(
        ThreatIntelIOC.tenant_id == tenant_id,
        ThreatIntelIOC.is_active.is_(True),
        ThreatIntelIOC.false_positive.is_(False),
    )
    stmt = _apply_filter(stmt, collection.ioc_filter or {})

    # Types with no STIX pattern are excluded in the query rather than
    # dropped after the fact, so `more` and the page size describe the
    # same set the client receives.
    stmt = stmt.where(ThreatIntelIOC.ioc_type.in_(_publishable_types()))

    if match_type is not None:
        # TAXII `match[type]` filters on the STIX object type. This
        # collection publishes indicators and nothing else, so anything
        # other than "indicator" selects nothing — which is the honest
        # answer rather than ignoring the filter.
        if "indicator" not in {part.strip() for part in match_type.split(",")}:
            return [], False

    if match_id is not None:
        wanted = {part.strip() for part in match_id.split(",")}
        # A STIX id is derived from the row id, so the filter is applied
        # after projection rather than translated into SQL. Bounded by the
        # page limit either way.
        stmt = stmt.order_by(ThreatIntelIOC.updated_at, ThreatIntelIOC.id)
        rows = (await db.execute(stmt.limit(MAX_PAGE_LIMIT))).scalars().all()
        selected = [_row(r) for r in rows]
        from app.services.taxii import stix_id_for  # noqa: PLC0415 — avoids a cycle at import time

        selected = [r for r in selected if stix_id_for(r.id) in wanted]
        return selected[:limit], len(selected) > limit

    if next_token:
        try:
            stamp, row_id = parse_cursor(next_token)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "title": "Bad next value",
                    "description": str(exc),
                    "http_status": "400",
                },
            ) from exc
        stmt = stmt.where(
            or_(
                ThreatIntelIOC.updated_at > stamp,
                and_(ThreatIntelIOC.updated_at == stamp, ThreatIntelIOC.id > row_id),
            )
        )
    elif added_after:
        try:
            boundary = _parse_timestamp(added_after)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "title": "Bad added_after",
                    "description": "added_after must be an RFC 3339 timestamp",
                    "http_status": "400",
                },
            ) from exc
        stmt = stmt.where(ThreatIntelIOC.updated_at > boundary)

    stmt = stmt.order_by(ThreatIntelIOC.updated_at, ThreatIntelIOC.id).limit(limit + 1)
    rows = (await db.execute(stmt)).scalars().all()
    more = len(rows) > limit
    return [_row(r) for r in rows[:limit]], more


def _publishable_types() -> list[str]:
    from app.services.taxii import _STIX_PATTERNS  # noqa: PLC0415

    return sorted(_STIX_PATTERNS)


def _parse_timestamp(raw: str) -> datetime:
    value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _row(ioc: ThreatIntelIOC) -> IndicatorRow:
    return IndicatorRow(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        confidence=ioc.confidence,
        severity=ioc.severity,
        tlp=ioc.tlp,
        threat_actor=ioc.threat_actor,
        campaign=ioc.campaign,
        malware_family=ioc.malware_family,
        tags=list(ioc.tags or []),
        source=ioc.source,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        expires_at=ioc.expires_at,
        updated_at=ioc.updated_at,
        created_at=ioc.created_at,
    )


def _envelope_headers(rows: list[IndicatorRow]) -> dict[str, str]:
    """The two headers a polling client bookmarks.

    Omitted on an empty page rather than set to "now": a client that
    records a boundary no row was ever written at skips anything that
    lands in between.
    """
    if not rows:
        return {}
    stamps = [r.updated_at for r in rows]
    from app.services.taxii import _rfc3339  # noqa: PLC0415

    return {
        "X-TAXII-Date-Added-First": _rfc3339(min(stamps)) or "",
        "X-TAXII-Date-Added-Last": _rfc3339(max(stamps)) or "",
    }


@router.get(
    "/{api_root}/collections/{collection_ref}/objects/",
    dependencies=[Depends(require_permission("threat_intel:read"))],
)
async def get_objects(
    api_root: str,
    collection_ref: str,
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    added_after: Annotated[str | None, Query(alias="added_after")] = None,
    limit: Annotated[int | None, Query(ge=1, le=MAX_PAGE_LIMIT)] = None,
    next_token: Annotated[str | None, Query(alias="next")] = None,
    match_id: Annotated[str | None, Query(alias="match[id]")] = None,
    match_type: Annotated[str | None, Query(alias="match[type]")] = None,
) -> Response:
    """``GET /taxii2/{api-root}/collections/{id}/objects/``."""
    if api_root != API_ROOT:
        raise _not_found(f"no API root named {api_root!r}")
    collection = await _load_collection(db, current_user.tenant_id, collection_ref)
    if not collection.can_read:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "title": "Forbidden",
                "description": "this collection is not readable",
                "http_status": "403",
            },
        )

    page_limit = clamp_limit(limit)
    rows, more = await _page(db, current_user.tenant_id, collection, added_after, next_token, page_limit, match_id, match_type)

    objects = [obj for obj in (to_stix_indicator(r) for r in rows) if obj is not None]
    envelope: dict[str, Any] = {"more": more, "objects": objects}
    if more and rows:
        envelope["next"] = next_cursor(rows[-1])

    response = _taxii_response(envelope)
    for header, value in _envelope_headers(rows).items():
        response.headers[header] = value
    return response


@router.get(
    "/{api_root}/collections/{collection_ref}/manifest/",
    dependencies=[Depends(require_permission("threat_intel:read"))],
)
async def get_manifest(
    api_root: str,
    collection_ref: str,
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    added_after: Annotated[str | None, Query(alias="added_after")] = None,
    limit: Annotated[int | None, Query(ge=1, le=MAX_PAGE_LIMIT)] = None,
    next_token: Annotated[str | None, Query(alias="next")] = None,
) -> Response:
    """``GET /taxii2/{api-root}/collections/{id}/manifest/``.

    The manifest is what a client polls to decide what to fetch, so it
    pages by the same cursor as ``objects``. Two different orderings would
    let a client hold a manifest entry it can never reach.
    """
    if api_root != API_ROOT:
        raise _not_found(f"no API root named {api_root!r}")
    collection = await _load_collection(db, current_user.tenant_id, collection_ref)
    page_limit = clamp_limit(limit)
    rows, more = await _page(db, current_user.tenant_id, collection, added_after, next_token, page_limit, None, None)

    envelope: dict[str, Any] = {"more": more, "objects": [manifest_entry(r) for r in rows]}
    if more and rows:
        envelope["next"] = next_cursor(rows[-1])
    response = _taxii_response(envelope)
    for header, value in _envelope_headers(rows).items():
        response.headers[header] = value
    return response


@router.post(
    "/{api_root}/collections/{collection_ref}/objects/",
    dependencies=[Depends(require_permission("threat_intel:read"))],
)
async def refuse_write(api_root: str, collection_ref: str) -> Response:
    """Inbound TAXII writes are refused, and say why.

    A 405 would read as "wrong verb" and send the integrator looking for
    the right one. This is a deliberate posture, so it is a 403 that names
    it.
    """
    return _taxii_response(
        {
            "title": "Writes are not accepted",
            "description": (
                "This server publishes indicators and does not accept them. An inbound "
                "TAXII write is an outside party inserting indicators that drive this "
                "tenant's detections; add them through the threat-intel API instead."
            ),
            "http_status": "403",
        },
        status_code=status.HTTP_403_FORBIDDEN,
    )


# ---------------------------------------------------------------------------
# Management
# ---------------------------------------------------------------------------


class CollectionCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    alias: str | None = Field(default=None, max_length=100)
    ioc_filter: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True


class CollectionOut(BaseModel):
    id: uuid.UUID
    title: str
    description: str
    alias: str | None
    can_read: bool
    can_write: bool
    ioc_filter: dict[str, Any]
    is_enabled: bool
    created_at: datetime


@admin_router.get("/collections", response_model=list[CollectionOut])
async def list_managed_collections(
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("threat_intel:read"))] = None,
) -> list[CollectionOut]:
    result = await db.execute(
        select(TaxiiCollection).where(TaxiiCollection.tenant_id == current_user.tenant_id).order_by(TaxiiCollection.created_at)
    )
    return [CollectionOut.model_validate(c, from_attributes=True) for c in result.scalars().all()]


@admin_router.post("/collections", response_model=CollectionOut, status_code=status.HTTP_201_CREATED)
async def create_managed_collection(
    payload: CollectionCreate,
    current_user: AuthUser,
    # Tenant-scoped on purpose: taxii_collections carries the strict RLS
    # policy `WITH CHECK (tenant_id = current_tenant_id())`, so an INSERT
    # through a session that never sets app.current_tenant_id is refused for
    # every tenant (HTTP 500) — the same defect GHSA-898c-wxrw-hx6c reported
    # on outbound webhooks, reproduced live here too.
    db: TenantDBSession,
    _: Annotated[None, Depends(require_permission("threat_intel:write"))] = None,
) -> CollectionOut:
    try:
        ioc_filter = validate_filter(payload.ioc_filter)
    except FilterError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    collection = TaxiiCollection(
        tenant_id=current_user.tenant_id,
        title=payload.title,
        description=payload.description,
        alias=payload.alias,
        ioc_filter=ioc_filter,
        is_enabled=payload.is_enabled,
        can_read=True,
        can_write=False,
    )
    db.add(collection)
    await db.commit()
    await db.refresh(collection)
    logger.info(
        "taxii: collection created",
        extra={"collection_id": str(collection.id), "tenant_id": str(current_user.tenant_id)},
    )
    return CollectionOut.model_validate(collection, from_attributes=True)


@admin_router.delete("/collections/{collection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_managed_collection(
    collection_id: uuid.UUID,
    current_user: AuthUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_permission("threat_intel:write"))] = None,
) -> Response:
    result = await db.execute(
        select(TaxiiCollection).where(
            TaxiiCollection.id == collection_id,
            TaxiiCollection.tenant_id == current_user.tenant_id,
        )
    )
    collection = result.scalar_one_or_none()
    if collection is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="collection not found")
    await db.delete(collection)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/unpublished-types")
async def unpublished_types(
    _: Annotated[None, Depends(require_permission("threat_intel:read"))] = None,
) -> dict[str, Any]:
    """Which IOC types this server will not publish, and why.

    An absence a tenant cannot explain reads as a bug. Published as data
    rather than documented in prose so the answer cannot drift from the
    table the projection actually uses.
    """
    return {
        "published": _publishable_types(),
        "unpublished": UNPUBLISHED_IOC_TYPES,
        "default_page_limit": DEFAULT_PAGE_LIMIT,
        "max_page_limit": MAX_PAGE_LIMIT,
    }
