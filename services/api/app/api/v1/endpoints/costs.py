"""Cost dashboard API endpoints.

WS-H1 — buyer-value plan
========================

Backs the admin cost dashboard at ``apps/web/src/app/(admin)/costs/`` with a
single consolidated read endpoint. The actual aggregation lives in
``app.services.cost_dashboard`` so the SQL surface stays there and the
endpoint is just a thin tenant-scoping + permission layer.

Why a new router instead of extending ``investigations.py``?
------------------------------------------------------------

``GET /api/v1/investigations/costs/aggregate`` is a per-run breakdown for an
analyst drilling into a single investigation. The dashboard answers a
fundamentally different question — "where is *all* my LLM money going across
my whole tenant, day by day?" — and pulls in audit_log + LLM provider
context that ``investigations.py`` has no business knowing about. Keeping
the surfaces separate keeps each endpoint cohesive.

Permissions
-----------

The dashboard is a financial-oversight surface, so we gate it behind
``reports:read``. ``platform_admin`` and ``tenant_admin`` always see it via
the static role table; ``soc_lead`` and analysts inherit it because they
already get ``reports:read``. Viewers also get it (read-only).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.v1.deps import AuthUser, require_permission
from app.api.v1.endpoints.llm_status import llm_status
from app.db.rls import TenantDBSession
from app.services.cost_dashboard import CostDashboard, build_cost_dashboard

router = APIRouter(prefix="/costs", tags=["costs"])

# Bound the dashboard window so a malformed query parameter cannot trigger an
# unbounded aggregate scan. 365 days covers every realistic operator question
# ("annual review") without letting a typo turn the dashboard into a DoS.
_MIN_WINDOW_DAYS = 1
_MAX_WINDOW_DAYS = 365
_DEFAULT_WINDOW_DAYS = 30


@router.get(
    "/dashboard",
    response_model=CostDashboard,
    summary="LLM spend, action counts, top-cost cases, and BYOK savings for the tenant",
)
async def get_cost_dashboard(
    current_user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
    db: TenantDBSession,
    window_days: int = Query(
        default=_DEFAULT_WINDOW_DAYS,
        ge=_MIN_WINDOW_DAYS,
        le=_MAX_WINDOW_DAYS,
        description=("Rolling window in days. Counts back from now() (UTC). Defaults to the last 30 days; capped at 365."),
    ),
) -> CostDashboard:
    """Return a deterministic snapshot of cost, activity, and BYOK savings.

    The response covers the rolling ``window_days``-long window ending at
    ``now()`` (UTC) and includes:

    * **headline** — total spend / tokens / calls / runs and average
      cost-per-run across the window.
    * **daily_costs** — per-day buckets so the UI can plot a trend line.
    * **by_model** — spend, tokens, runs, and average latency per model
      with the imputed public-list cost for context.
    * **top_cases** — the most expensive ``case_id`` values, the closest
      proxy AiSOC has for "top-cost playbook runs" since each playbook
      run lives under a case (no separate ``playbook_runs`` table).
    * **action_counts** — ``audit_log`` action distribution so operators
      can see how much SOC activity their LLM spend is buying.
    * **byok_savings** — imputed delta between recorded cost and public
      list pricing. ``is_byok_active`` reflects whether the live LLM
      provider is loopback / private (per ``/llm/status``).

    Tenant scoping is enforced by ``TenantDBSession`` (Postgres RLS sets
    ``app.current_tenant_id``) plus an explicit ``tenant_id`` predicate in
    the underlying query, so the same payload is safe to render for any
    role with ``reports:read``.
    """
    if window_days < _MIN_WINDOW_DAYS or window_days > _MAX_WINDOW_DAYS:
        # FastAPI's ge/le already short-circuits this for the typical
        # request, but defence-in-depth: a tampered router or programmatic
        # caller cannot bypass the clamp.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"window_days must be between {_MIN_WINDOW_DAYS} and {_MAX_WINDOW_DAYS}"),
        )

    # Pull the live LLM provider snapshot from the same code path the
    # /llm/status endpoint uses, so the BYOK panel cannot drift from the
    # provider indicator the operator sees in Settings.
    llm = llm_status()

    return await build_cost_dashboard(
        db,
        current_user.tenant_id,
        window_days=window_days,
        llm_provider=str(llm.get("provider") or "unknown"),
        is_local=bool(llm.get("is_local")),
    )
