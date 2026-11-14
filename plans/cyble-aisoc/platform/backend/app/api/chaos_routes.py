"""Chaos-engine REST surface (t6-chaos).

  GET   /chaos/faults                    Active scheduled faults
  POST  /chaos/faults                    Schedule one fault
  POST  /chaos/scenarios/{name}          Schedule a built-in scenario
  GET   /chaos/history                   Fault firing history
  DELETE /chaos/faults                   Clear all scheduled faults

Admin-only. A fault that fires inside an agent run is the security
equivalent of a controlled explosion — it must never be possible
for an unprivileged caller to schedule one against a production
deployment.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.chaos import (
    ChaosFault,
    ChaosKind,
    ChaosScenario,
    chaos_engine,
)
from app.chaos.scenarios import builtin_scenarios
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/chaos", tags=["chaos"])


def _fault_to_dict(fault: ChaosFault) -> dict[str, Any]:
    return {
        "kind": fault.kind.value,
        "target": fault.target,
        "remaining": fault.remaining,
        "delay_ms": fault.delay_ms,
        "fired": fault.fired,
        "message": fault.message,
    }


class ScheduleFaultRequest(BaseModel):
    kind: ChaosKind
    target: str = Field(min_length=1, max_length=200)
    remaining: int = Field(default=1, ge=1, le=100)
    delay_ms: int = Field(default=0, ge=0, le=10 * 60 * 1000)
    message: str = Field(default="chaos: synthetic fault", max_length=500)
    payload: Optional[dict[str, Any]] = None


@router.get("/faults")
def list_active_faults(ctx: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    """Active scheduled faults — visible to any authenticated user."""
    return {
        "count": len(chaos_engine.active_faults()),
        "faults": [_fault_to_dict(f) for f in chaos_engine.active_faults()],
    }


@router.post("/faults")
def schedule_fault(
    body: ScheduleFaultRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Schedule a single fault. Admin-only."""
    if not ctx.is_admin:
        raise HTTPException(
            status_code=403, detail="scheduling chaos faults requires admin"
        )
    fault = chaos_engine.schedule(
        ChaosFault(
            kind=body.kind,
            target=body.target,
            remaining=body.remaining,
            delay_ms=body.delay_ms,
            message=body.message,
            payload=body.payload or {},
        )
    )
    return _fault_to_dict(fault)


@router.post("/scenarios/{name}")
def schedule_scenario(
    name: str,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Schedule a named built-in scenario. Admin-only."""
    if not ctx.is_admin:
        raise HTTPException(
            status_code=403, detail="scheduling chaos scenarios requires admin"
        )
    available = {s.name: s for s in builtin_scenarios()}
    if name not in available:
        raise HTTPException(
            status_code=404,
            detail=f"unknown chaos scenario '{name}'. available: {sorted(available)}",
        )
    chaos_engine.schedule_scenario(available[name])
    return {
        "name": name,
        "description": available[name].description,
        "faults": [_fault_to_dict(f) for f in available[name].faults],
    }


@router.get("/history")
def get_history(ctx: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    history = chaos_engine.history()
    return {"count": len(history), "events": history[-200:]}


@router.delete("/faults")
def clear_faults(ctx: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    if not ctx.is_admin:
        raise HTTPException(status_code=403, detail="admin required")
    chaos_engine.clear()
    return {"cleared": True}
