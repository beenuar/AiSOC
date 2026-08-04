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
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import text

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.services.detection_tuner import DispositionRecord, suggest_tuning
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


class AutoSuggestResponse(BaseModel):
    """Disposition-history tuning suggestions + how many became draft proposals."""

    window_days: int
    records_considered: int
    suggestions: list[dict]
    proposals_created: int


def _disposition_records(rows) -> list[DispositionRecord]:  # noqa: ANN001
    """Map alert-disposition rows into the tuner's input records.

    ``human_verified`` is conservatively False here (these are stored
    dispositions, not confirmed human overrides), so the tuner only proposes
    scoped exceptions / severity reductions — never a bare ``suppress`` — from
    this surface. Human-confirmed suppression still flows via the override path.
    """
    out: list[DispositionRecord] = []
    for r in rows:
        rid = getattr(r, "rule_id", None)
        if not rid:
            continue
        out.append(
            DispositionRecord(
                rule_id=str(rid),
                disposition=str(getattr(r, "disposition", "") or ""),
                entity=(getattr(r, "entity", None) or None),
                human_verified=False,
            )
        )
    return out


@router.post("/auto-suggest", response_model=AutoSuggestResponse)
async def auto_suggest_tuning(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
    window_days: int = Query(default=30, ge=1, le=180),
    create_proposals: bool = Query(default=True),
) -> AutoSuggestResponse:
    """Derive human-approval-gated tuning suggestions from disposition history.

    Wave 1 wiring: connects the previously-orphaned ``suggest_tuning`` engine to
    real per-rule disposition history and, optionally, opens DRAFT detection
    proposals (source ``auto-tuner``) into the governed lifecycle. Nothing is
    auto-applied — an engineer reviews + eval-gates before promotion.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT rule_id,
                       disposition,
                       COALESCE(affected_hosts->>0, affected_users->>0, affected_ips->>0) AS entity
                  FROM alerts
                 WHERE tenant_id = :tid
                   AND rule_id IS NOT NULL
                   AND disposition IS NOT NULL
                   AND created_at > now() - make_interval(days => :days)
                """
            ).bindparams(tid=current_user.tenant_id, days=window_days)
        )
    ).fetchall()

    records = _disposition_records(rows)
    suggestions = suggest_tuning(records)

    created = 0
    if create_proposals and suggestions:
        now = datetime.now(UTC)
        for s in suggestions:
            body = (
                f"# Auto-tuner proposal for rule {s.rule_id}\n"
                f"# Action: {s.action}\n"
                f"# {s.rationale}\n"
                f"# FP rate {s.fp_rate:.0%} over {s.sample_count} decided alerts"
                + (f"; cluster entity: {s.entity}\n" if s.entity else "\n")
                + "# TODO(analyst): review + attach fixtures before promotion.\n"
            )
            await db.execute(
                text(
                    """
                    INSERT INTO detection_rule_proposals
                      (id, tenant_id, base_rule_id, name, description,
                       rule_language, rule_body, category, severity, confidence,
                       status, source, created_at, updated_at)
                    VALUES
                      (:id, :tid, NULL, :name, :desc,
                       'sigma', :body, 'tuning', 'low', 60,
                       'draft', 'auto-tuner', :now, :now)
                    """
                ).bindparams(
                    id=uuid.uuid4(),
                    tid=current_user.tenant_id,
                    name=f"tune {s.action}: {s.rule_id}"[:200],
                    desc=s.rationale[:2000],
                    body=body,
                    now=now,
                )
            )
            created += 1
        await db.commit()

    return AutoSuggestResponse(
        window_days=window_days,
        records_considered=len(records),
        suggestions=[asdict(s) for s in suggestions],
        proposals_created=created,
    )


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
