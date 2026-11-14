"""FinOps for AI — REST surface (t5-finops).

  GET  /finops/rollup                  Per-tenant cost + ROI + budget.
  GET  /finops/budget                  Current month's budget posture.
  PUT  /finops/budget                  Idempotent budget upsert.
  GET  /finops/leaderboard             MSSP-only: cost-per-case ranked
                                       across the MSSP's child tenants.

Visibility rules:
  - Tenant analysts and admins see *their own* rollup.
  - MSSP analysts can pivot via the standard ``X-AISOC-Tenant`` header
    to look at a child tenant; the existing ``require_tenant``
    dependency enforces that.
  - The leaderboard is MSSP/admin only — exposing per-tenant cost
    leaderboards to non-MSSP tenants would leak fleet-wide data.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.finops.cost import (
    budget_status,
    finops_rollup,
    set_budget,
)
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/finops", tags=["finops"])


@router.get("/rollup")
def finops_rollup_route(
    window_days: int = 30,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Per-tenant FinOps rollup over a rolling window."""
    if window_days < 1 or window_days > 90:
        raise HTTPException(
            status_code=400,
            detail="window_days must be between 1 and 90",
        )
    rollup = finops_rollup(ctx.active_tenant_id, window_days=window_days)
    return rollup.to_dict()


@router.get("/budget")
def get_budget(
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Month-to-date budget posture for the active tenant."""
    status = budget_status(ctx.active_tenant_id)
    if status is None:
        return {
            "tenant_id": ctx.active_tenant_id,
            "configured": False,
            "monthly_usd": 0.0,
            "spent_usd": 0.0,
            "utilisation": 0.0,
            "over_threshold": False,
            "over_cap": False,
        }
    payload = {
        "tenant_id": status.tenant_id,
        "configured": True,
        "monthly_usd": status.monthly_usd,
        "alert_threshold": status.alert_threshold,
        "spent_usd": status.spent_usd,
        "utilisation": status.utilisation,
        "over_threshold": status.over_threshold,
        "over_cap": status.over_cap,
        "days_remaining_in_month": status.days_remaining_in_month,
        "projected_month_end_usd": status.projected_month_end_usd,
    }
    return payload


class BudgetUpsertRequest(BaseModel):
    monthly_usd: Optional[float] = Field(default=None, ge=0)
    alert_threshold: Optional[float] = Field(default=None, gt=0, le=1)
    alert_target: Optional[str] = Field(default=None, max_length=200)
    analyst_hourly_usd: Optional[float] = Field(default=None, ge=0, le=10_000)


@router.put("/budget")
def upsert_budget(
    body: BudgetUpsertRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Idempotently set the active tenant's monthly LLM-spend budget."""
    payload = body.model_dump(exclude_unset=True)
    try:
        row = set_budget(tenant_id=ctx.active_tenant_id, **payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "tenant_id": row.tenant_id,
        "monthly_usd": row.monthly_usd,
        "alert_threshold": row.alert_threshold,
        "alert_target": row.alert_target,
        "analyst_hourly_usd": row.analyst_hourly_usd,
    }


@router.get("/leaderboard")
def finops_leaderboard(
    window_days: int = 30,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """MSSP-only: cost-per-case across child tenants.

    Sorted by *highest cost-per-resolved-case* first so the operator
    can spot tenants whose automation is unusually expensive
    relative to the deflection it produces.
    """
    if not (ctx.is_mssp or ctx.is_admin):
        raise HTTPException(
            status_code=403,
            detail="leaderboard is only available to MSSP or admin tokens",
        )
    if ctx.is_admin:
        # Admins see a fleet view across the MSSP they're impersonating.
        # In practice the ``X-AISOC-Tenant`` header would pivot them
        # into a specific MSSP; for the platform admin we emit a
        # descriptive 422 if no MSSP is in scope.
        targets = [ctx.active_tenant_id]
    else:
        # Pull the MSSP's child tenant list directly from the tenant
        # links table. Defense in depth: intersect with the JWT's
        # ``allowed_tenants``.
        from app.mssp import list_links  # avoid import cycle at module load
        mssp_tid = ctx.claims.mssp_parent_tenant_id or ctx.claims.tenant_id
        link_rows = list_links(mssp_tid)
        viewable = ctx.viewable_tenant_ids() or []
        viewable_set = set(viewable) if viewable else set()
        targets = [
            l.customer_tenant_id
            for l in link_rows
            if not l.suspended
            and (not viewable_set or l.customer_tenant_id in viewable_set)
        ]

    rows: list[dict[str, Any]] = []
    for tid in targets:
        rollup = finops_rollup(tid, window_days=window_days)
        cases = rollup.roi.cases_resolved
        cost = rollup.cost_usd_total
        cost_per_case = round(cost / cases, 6) if cases else None
        rows.append(
            {
                "tenant_id": tid,
                "cost_usd_total": cost,
                "cases_resolved": cases,
                "cost_per_case_usd": cost_per_case,
                "roi_dollars": rollup.roi.roi_dollars,
                "roi_ratio": rollup.roi.roi_ratio,
            }
        )
    rows.sort(
        key=lambda r: (
            r["cost_per_case_usd"] is None,
            -(r["cost_per_case_usd"] or 0.0),
        )
    )
    return {
        "window_days": window_days,
        "count": len(rows),
        "leaderboard": rows,
    }
