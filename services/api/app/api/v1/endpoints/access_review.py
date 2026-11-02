"""Access-review routes (depth plan wave 2, Phase 1.2).

Read-only, in the strongest sense available: these routes compute and read
findings, and there is no route here — and no caller anywhere — that changes
a vendor object. The only write is a reviewer acknowledging a finding, which
is state about the review and not about the estate.

Three routes:

``GET  /access-review/summary``   the honest empty state and the counts
``GET  /access-review/findings``  the list a reviewer works through
``POST /access-review/run``       recompute from the current posture + usage
``POST /access-review/findings/{id}/acknowledge``

The empty state is the part worth reading. Zero findings over zero reviewed
principals is ``nothing_reviewed``, never ``no_findings``: an estate nobody
could look at must not render identically to one with nothing wrong, and
this page is exactly where a reader would draw that conclusion.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.services import access_review_store
from app.services.access_review import FINDING_KINDS
from app.services.effective_permissions.service import SUPPORTED_PROVIDERS

router = APIRouter(prefix="/access-review", tags=["access-review"])


class AcknowledgeRequest(BaseModel):
    note: str = Field(default="", max_length=2000)


@router.get("/kinds", summary="The finding kinds this review can produce")
async def list_kinds(
    _user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
) -> dict[str, Any]:
    """Published so the console can render a filter without hardcoding a copy.

    A second list in the frontend is how a kind ends up filterable on one
    surface and invisible on the other; this repository has that defect on
    record in the playbook editor's step-type union.
    """
    return {
        "kinds": [
            {
                "kind": spec.kind,
                "title": spec.title,
                "severity": spec.severity,
                "object_hint": spec.object_hint,
                "recommendation": spec.recommendation,
                "needs_usage": spec.needs_usage,
            }
            for spec in sorted(FINDING_KINDS.values(), key=lambda s: s.kind)
        ]
    }


@router.get("/summary", summary="Review state and counts, with an honest empty state")
async def review_summary(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    provider: str | None = Query(default=None),
) -> dict[str, Any]:
    if provider and provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}",
        )
    return await access_review_store.summary(db, tenant_id=user.tenant_id, provider=provider)


@router.get("/findings", summary="Open access-review findings")
async def list_findings(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    provider: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    include_acknowledged: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    if provider and provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}",
        )
    if kind and kind not in FINDING_KINDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown finding kind {kind!r}; see GET /access-review/kinds",
        )
    rows = await access_review_store.list_findings(
        db,
        tenant_id=user.tenant_id,
        provider=provider,
        kind=kind,
        include_acknowledged=include_acknowledged,
        limit=limit,
    )
    return {"items": rows, "count": len(rows)}


@router.post("/run", summary="Recompute the review from current posture and usage")
async def run_review(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    provider: str = Query(...),
) -> dict[str, Any]:
    """Recompute. Reads only — no vendor object is touched by this call.

    Guarded by ``compliance:read`` rather than a write permission on
    purpose: the only thing it writes is this tenant's own review rows, and
    requiring a write scope would put the review behind a permission an
    auditor is deliberately not given.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}",
        )
    return await access_review_store.run_review(db, tenant_id=user.tenant_id, provider=provider)


@router.post("/findings/{finding_id}/acknowledge", summary="Acknowledge a finding")
async def acknowledge(
    finding_id: uuid.UUID,
    body: AcknowledgeRequest,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
) -> dict[str, Any]:
    """Record that a person decided this one is fine.

    A 404 rather than a 403 for a finding belonging to another tenant: a
    403 would make this route an existence oracle over every tenant's
    finding ids, and a genuine miss is byte-identical to a cross-tenant
    attempt from the caller's side either way.
    """
    updated = await access_review_store.acknowledge(
        db,
        tenant_id=user.tenant_id,
        finding_id=finding_id,
        user_id=user.user_id,
        note=body.note,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return updated
