"""Closed-loop Exposure Agent REST API (t3a-closed-loop).

Analyst-facing surface for the proactive Exposure→Detection→Response→
Verification loop implemented in :mod:`app.agents.exposure`.

Endpoints:

- ``POST /exposure/sweep``  — trigger one bounded :class:`ExposureAgent`
  sweep against the active tenant, on demand. Useful during demos,
  incident response ("we just learned a vendor was breached — run a
  sweep now"), and CI smoke tests. Does **not** bypass the per-sweep
  timeout configured via ``settings.exposure_sweep_timeout_seconds``.

- ``GET  /exposure/cases`` — list currently-open proactive exposure
  cases for the active tenant. We filter on the ``[Exposure]`` title
  prefix the agent stamps onto every case it opens; that keeps the
  endpoint cheap and avoids a schema migration to introduce a
  dedicated "origin" column for what is currently a 1-agent feature.

Design rules:

1. Sweeps are write operations (they may open cases, mutate the Threat
   Graph, and nudge cases into ``RESPONDING``). They are tenant-scoped
   via the standard ``require_tenant`` dependency.

2. The route delegates wholly to :meth:`ExposureAgent.sweep`. We do
   **not** re-implement the loop here — there must be exactly one
   code path (scheduled or manual) that drives the agent.

3. Errors during a sweep are bubbled as 500s — the analyst pressed
   the button, they should see the failure. The scheduled path
   logs-and-continues by design, but the manual path is interactive.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import select

from app.agents.exposure import ExposureAgent
from app.config import settings
from app.db import session_scope
from app.models.case import Case, CaseStatus
from app.security.tenant import TenantContext, require_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/exposure", tags=["exposure"])


# ──────────────────────────────────────────────────────────────────────
# Response shapes
# ──────────────────────────────────────────────────────────────────────


class SweepResponse(BaseModel):
    """Mirror of :class:`ExposureSweepResult` over the wire."""

    tenant_id: str
    findings_total: int
    new_findings: int
    cases_opened: list[int]
    cases_verified_closed: list[int]
    cases_escalated: list[int]
    responses_routed: int
    graph_nodes_upserted: int
    graph_edges_upserted: int
    errors: list[str]


class ExposureCaseSummary(BaseModel):
    case_id: int
    title: str
    status: str
    severity: str
    created_at: str | None = None
    updated_at: str | None = None
    affected_users: list[str]
    affected_hosts: list[str]
    response_actions: list[dict[str, Any]]


class ExposureCasesResponse(BaseModel):
    tenant_id: str
    open_cases: list[ExposureCaseSummary]


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────


@router.post("/sweep", response_model=SweepResponse)
async def trigger_sweep(
    ctx: TenantContext = Depends(require_tenant),
) -> SweepResponse:
    """Run one on-demand Exposure sweep for the caller's active tenant.

    Returns the full :class:`ExposureSweepResult` so the analyst can
    see immediately what was opened, verified, and escalated. Subject
    to the same per-sweep timeout the scheduler uses.
    """
    tenant_id = ctx.active_tenant_id
    try:
        with session_scope() as session:
            agent = ExposureAgent(session=session, tenant_id=tenant_id)
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.exposure_sweep_timeout_seconds,
            )
    except asyncio.TimeoutError as exc:
        logger.warning(
            "exposure_routes: on-demand sweep tenant=%s exceeded %ds",
            tenant_id,
            settings.exposure_sweep_timeout_seconds,
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"Exposure sweep exceeded "
                f"{settings.exposure_sweep_timeout_seconds}s; "
                "increase exposure_sweep_timeout_seconds or wait for the "
                "scheduled run."
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001 — surface to caller
        logger.exception("exposure_routes: on-demand sweep tenant=%s failed", tenant_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return SweepResponse(**result.as_dict())


@router.get("/cases", response_model=ExposureCasesResponse)
def list_open_exposure_cases(
    ctx: TenantContext = Depends(require_tenant),
) -> ExposureCasesResponse:
    """List proactive exposure cases not yet resolved.

    Filters on the ``[Exposure]`` title prefix the agent writes; this
    is the same heuristic the verification phase uses, so the UI shows
    exactly the cohort the next sweep will re-evaluate.
    """
    tenant_id = ctx.active_tenant_id
    open_statuses = [
        CaseStatus.NEW,
        CaseStatus.TRIAGING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_HITL,
        CaseStatus.RESPONDING,
    ]
    with session_scope() as session:
        rows = session.exec(
            select(Case)
            .where(Case.tenant_id == tenant_id)
            .where(Case.status.in_(open_statuses))
            .where(Case.title.like("[Exposure]%"))
            .order_by(Case.created_at.desc())
        ).all()
        summaries = [
            ExposureCaseSummary(
                case_id=row.id,  # type: ignore[arg-type]
                title=row.title,
                status=row.status.value,
                severity=row.severity.value,
                created_at=row.created_at.isoformat() if row.created_at else None,
                updated_at=row.updated_at.isoformat() if row.updated_at else None,
                affected_users=list(row.affected_users or []),
                affected_hosts=list(row.affected_hosts or []),
                response_actions=list(row.response_actions or []),
            )
            for row in rows
            if row.id is not None
        ]
    return ExposureCasesResponse(tenant_id=tenant_id, open_cases=summaries)


__all__ = ["router"]
