"""Detection rule tuning workbench endpoints.

Backs the ``/detection/tuning`` workbench in apps/web. The heavy lifting lives
in :mod:`app.services.rule_tuning`; this module is a thin transport layer that
wires permissions, request bodies, and pagination through to that service.

The router is mounted under ``/detection/tuning`` so it sits naturally inside
the existing ``/detection`` URL tree without colliding with
``detection_compat`` (``/detection/rules``, ``/detection/test``,
``/detection/coverage``) or ``detection_proposals`` (``/detection/proposals``).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.services.rule_tuning import (
    ApplyTuningRequest,
    AutoTuneRequest,
    DismissTuningRequest,
    TuningEntry,
    TuningResponse,
    TuningSummary,
    apply_tuning,
    build_tuning,
    build_tuning_summary,
    dismiss_tuning,
    set_auto_tune,
)

router = APIRouter(prefix="/detection/tuning", tags=["detection"])


@router.get("", response_model=TuningResponse)
async def get_tuning_workbench(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: TenantDBSession,
    severity: str | None = Query(default=None, description="Filter by rule severity (info/low/medium/high/critical)."),
    suggestion: Literal[
        "disable",
        "add_suppression",
        "raise_threshold",
        "tune_confidence",
        "review_stale",
        "healthy",
    ]
    | None = Query(default=None, description="Filter to a single suggestion lane."),
    search: str | None = Query(default=None, max_length=200, description="Substring match on name/description/category."),
    enabled_only: bool = Query(default=False, description="Hide rules whose status != 'active'."),
    include_dismissed: bool = Query(default=False, description="Show rules previously dismissed from the workbench."),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
) -> TuningResponse:
    """Project every rule the tenant can tune into a workbench feed.

    The summary block is computed across the *entire classified population*
    (not the current page), so the header tiles stay stable as analysts page.
    Dismissed rules are excluded by default — pass ``include_dismissed=true``
    when auditing what's been hidden.
    """
    return await build_tuning(
        db,
        tenant_id=current_user.tenant_id,
        severity=severity,
        suggestion=suggestion,
        search=search,
        enabled_only=enabled_only,
        include_dismissed=include_dismissed,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=TuningSummary)
async def get_tuning_summary(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: TenantDBSession,
) -> TuningSummary:
    """Cheap summary-only endpoint for sidebar badges and the
    /console dashboard tile."""
    return await build_tuning_summary(db, tenant_id=current_user.tenant_id)


@router.post("/{rule_id}/apply", response_model=TuningEntry)
async def apply_tuning_endpoint(
    rule_id: uuid.UUID,
    body: ApplyTuningRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
    request: Request,
) -> TuningEntry:
    """Mechanically apply a tuning suggestion to a single rule.

    Supports ``raise_threshold``, ``add_suppression``, ``disable``, and
    ``acknowledge`` (no-op + audit). Every mutation bumps
    ``DetectionRule.version`` and writes a ``detection.tuning.apply`` audit
    log entry. Returns the re-projected entry so the UI can refresh in place.
    """
    return await apply_tuning(
        db,
        rule_id=rule_id,
        actor=current_user,
        body=body,
        request=request,
    )


@router.post("/{rule_id}/dismiss", response_model=TuningEntry)
async def dismiss_tuning_endpoint(
    rule_id: uuid.UUID,
    body: DismissTuningRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
    request: Request,
) -> TuningEntry:
    """Hide a rule from the default workbench view without changing semantics."""
    return await dismiss_tuning(
        db,
        rule_id=rule_id,
        actor=current_user,
        body=body,
        request=request,
    )


@router.post("/{rule_id}/auto_tune", response_model=TuningEntry)
async def set_auto_tune_endpoint(
    rule_id: uuid.UUID,
    body: AutoTuneRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
    request: Request,
) -> TuningEntry:
    """Flip the per-rule ``auto_tune`` opt-in flag.

    The flag is stored under ``suppression_config.auto_tune`` and is read by
    future automated tuners — flipping it does *not* trigger any immediate
    rule mutation.
    """
    return await set_auto_tune(
        db,
        rule_id=rule_id,
        actor=current_user,
        body=body,
        request=request,
    )
