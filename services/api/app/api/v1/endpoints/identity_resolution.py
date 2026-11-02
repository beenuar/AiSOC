"""Identity-resolution routes (depth plan wave 2, Phase 3.1).

Read-only over the tenant's own identities. Nothing here changes a vendor
object; the one write is a person confirming or rejecting a proposed link,
which is a decision about the link and not about the estate.

``GET  /identity-resolution/links``      every link touching one identity
``GET  /identity-resolution/cluster``    who else is this person
``POST /identity-resolution/resolve``    re-run resolution over supplied records
``POST /identity-resolution/links/{id}/decide``

The weak links are returned by default, and that is the contract rather
than an oversight: a weak link is genuinely useful to an analyst reading a
story and genuinely dangerous to anything that merges, so the list says
which is which per row and the cluster endpoint walks only the strong ones.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.services import identity_resolution_store
from app.services.identity_resolution import MERGE_THRESHOLD, SOURCE_KINDS, resolve_links

router = APIRouter(prefix="/identity-resolution", tags=["identity-resolution"])

#: Cap on records accepted in one resolution call. Resolution is pairwise,
#: so cost is quadratic; a bound here is the difference between a slow
#: request and one that occupies a worker for minutes.
MAX_RECORDS = 500


class IdentityRecord(BaseModel):
    """One source-scoped identity offered for resolution."""

    source: str
    id: str
    email: str | None = None
    email_verified: bool = False
    upn: str | None = None
    employee_id: str | None = None
    display_name: str | None = None
    maps_to: list[str] = Field(default_factory=list)


class ResolveRequest(BaseModel):
    records: list[IdentityRecord] = Field(default_factory=list)
    #: Off by default. Resolution is cheap to preview and consequential to
    #: store, and an endpoint that persisted on every call would make
    #: "what would this link" impossible to ask.
    persist: bool = False


class DecideRequest(BaseModel):
    decision: str


@router.get("/links", summary="Every proposed link touching one identity")
async def list_links(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    key: str = Query(..., description="A source-scoped identity, e.g. okta:alice@example.com"),
    include_weak: bool = Query(default=True),
) -> dict[str, Any]:
    links = await identity_resolution_store.links_for(db, tenant_id=user.tenant_id, key=key, include_weak=include_weak)
    return {"key": key, "links": links, "count": len(links), "merge_threshold": MERGE_THRESHOLD}


@router.get("/cluster", summary="Who else is this person")
async def cluster(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    key: str = Query(...),
    max_depth: int = Query(default=3, ge=1, le=6),
) -> dict[str, Any]:
    """Merge-strength links only, bounded. See the store for why both."""
    members = await identity_resolution_store.cluster_for(db, tenant_id=user.tenant_id, key=key, max_depth=max_depth)
    return {
        "key": key,
        "same_person": members,
        "count": len(members),
        "note": (
            "Only links at or above the merge threshold, or confirmed by a person, are walked. "
            "Weak links are visible on /identity-resolution/links and are never merged."
        ),
    }


@router.post("/resolve", summary="Resolve a set of identities into links")
async def resolve(
    body: ResolveRequest,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> dict[str, Any]:
    """Run resolution over the supplied records.

    ``settings:write`` rather than a read permission because ``persist``
    writes the tenant's identity graph, and a caller who may not change
    tenant configuration should not be able to decide who is the same
    person.
    """
    if not body.records:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no records supplied")
    if len(body.records) > MAX_RECORDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"at most {MAX_RECORDS} records per call; resolution is pairwise",
        )
    unknown = sorted({r.source for r in body.records} - set(SOURCE_KINDS))
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown source(s) {unknown}; supported: {sorted(SOURCE_KINDS)}",
        )

    result = resolve_links([r.model_dump() for r in body.records])
    persisted = 0
    if body.persist:
        persisted = await identity_resolution_store.save_links(db, tenant_id=user.tenant_id, result=result)
        await db.commit()
    return {**result.as_dict(), "persisted": persisted}


@router.post("/links/{link_id}/decide", summary="Confirm or reject a proposed link")
async def decide(
    link_id: uuid.UUID,
    body: DecideRequest,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> dict[str, Any]:
    """A 404 for another tenant's link, so this is not an existence oracle."""
    if body.decision not in {"confirmed", "rejected"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="decision must be 'confirmed' or 'rejected'",
        )
    updated = await identity_resolution_store.decide_link(
        db,
        tenant_id=user.tenant_id,
        link_id=link_id,
        decision=body.decision,
        user_id=user.user_id,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="link not found")
    await db.commit()
    return updated
