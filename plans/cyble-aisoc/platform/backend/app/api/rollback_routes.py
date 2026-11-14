"""Rollback REST API.

Analyst-facing endpoints that expose the paired reverse-action machinery
(see :mod:`app.rollback.service`):

- ``GET  /rollback/eligible`` — list ``ToolCall`` rows the caller can undo
- ``GET  /rollback/{tool_call_id}/eligibility`` — single-row verdict + reverse param preview
- ``POST /rollback/{tool_call_id}`` — actually execute the rollback

The rollback service does the heavy lifting (eligibility, dispatch through
``ResponderAgent.call_tool(..., rollback_of_id=…)``, audit pairing); this
file is purely the HTTP shape + tenant guard.

Error mapping:
- ``RollbackNotEligible`` (any code) → ``409 Conflict`` with the reason
  embedded. This is the same pattern the HITL routes use for state
  conflicts and keeps "undo a thing twice" idempotent — the second call
  returns 409, not silent success.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.db import engine
from app.models.tool_call import ToolCall
from app.rollback.service import (
    RollbackNotEligible,
    execute_rollback,
    list_rollback_eligible,
    rollback_eligibility,
)
from app.security.tenant import (
    TenantContext,
    ensure_row_visible,
    require_tenant,
)


router = APIRouter(prefix="/rollback", tags=["rollback"])


# ──────────────────────────────────────────────────────────────────────
# Serialization helpers
# ──────────────────────────────────────────────────────────────────────


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _tc_to_dict(tc: ToolCall) -> dict[str, Any]:
    """Minimal forward-row projection for the rollback list view.

    We deliberately omit ``result``: a successful ``edr.isolate_host`` may
    have surfaced sensitive host metadata, and the rollback list view is
    invoked frequently from the analyst console. The full result is still
    available via the regular tool-call detail endpoint when needed.
    """
    return {
        "id": tc.id,
        "tenant_id": tc.tenant_id,
        "case_id": tc.case_id,
        "tool_name": tc.tool_name,
        "integration": tc.integration,
        "risk_class": tc.risk_class.value
        if hasattr(tc.risk_class, "value")
        else str(tc.risk_class),
        "params": tc.params,
        "success": tc.success,
        "created_at": _iso(tc.created_at),
        "rolled_back_at": _iso(tc.rolled_back_at),
        "rolled_back_by": tc.rolled_back_by,
    }


# ──────────────────────────────────────────────────────────────────────
# Read endpoints
# ──────────────────────────────────────────────────────────────────────


@router.get("/eligible")
def list_eligible(
    case_id: int | None = Query(
        None, description="Restrict to a single case_id."
    ),
    limit: int = Query(50, ge=1, le=500),
    include_ineligible: bool = Query(
        False,
        description=(
            "If true, also returns forward rows that fail eligibility, "
            "with the reason. Lets the UI show greyed-out 'Undo' buttons."
        ),
    ),
    ctx: TenantContext = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """List forward ``ToolCall`` rows the caller could roll back.

    Tenant scoping is enforced via ``TenantContext.viewable_tenant_ids()``
    so MSSP analysts see actions across the tenants they own and ordinary
    tenant users see only their own.
    """
    viewable = ctx.viewable_tenant_ids()
    with Session(engine) as s:
        rows = list_rollback_eligible(
            s,
            tenant_ids=viewable,
            case_id=case_id,
            limit=limit,
            include_ineligible=include_ineligible,
        )
        out: list[dict[str, Any]] = []
        for tc, verdict in rows:
            row = _tc_to_dict(tc)
            row["eligible"] = verdict.eligible
            row["eligibility_reason"] = verdict.reason
            row["reverse_tool"] = verdict.reverse_tool
            row["reverse_params_preview"] = verdict.reverse_params_preview
            out.append(row)
    return out


@router.get("/{tool_call_id}/eligibility")
def get_eligibility(
    tool_call_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Single-row eligibility verdict + reverse-param preview.

    The analyst console calls this immediately before showing the "Undo"
    confirmation modal so the operator sees exactly which reverse tool
    will fire and with what parameters.
    """
    with Session(engine) as s:
        tc = s.get(ToolCall, tool_call_id)
        if tc is None:
            raise HTTPException(status_code=404, detail="tool_call not found")
        ensure_row_visible(ctx, tc.tenant_id)
        verdict = rollback_eligibility(s, tool_call_id)
        return {
            **_tc_to_dict(tc),
            "eligible": verdict.eligible,
            "eligibility_reason": verdict.reason,
            "reverse_tool": verdict.reverse_tool,
            "reverse_params_preview": verdict.reverse_params_preview,
        }


# ──────────────────────────────────────────────────────────────────────
# Write endpoint
# ──────────────────────────────────────────────────────────────────────


class RollbackBody(BaseModel):
    actor: str = Field(
        ...,
        description=(
            "Free-form actor id ('user:42', 'system:sla-timeout', "
            "'soc:on-call-tier2'). Appended to the audit stamp set by "
            "the base agent ('agent:responder') so the rollback "
            "attribution captures both the human and the executor."
        ),
    )
    rationale: str = Field(
        "",
        description=(
            "Operator rationale; recorded on the rollback ToolCall row "
            "and on the AgentTrace for SOC2 / ISO27001 audit."
        ),
    )


@router.post("/{tool_call_id}")
async def do_rollback(
    tool_call_id: int,
    body: RollbackBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Execute the paired reverse action for ``tool_call_id``.

    Authorization model: the caller MUST be able to view the forward
    ``ToolCall`` row's tenant. We enforce that here rather than only in
    the service so the 403 surfaces at the HTTP boundary and analysts
    don't see a misleading 409 INELIGIBLE for what is really an access
    denial.

    HITL: the reverse tool dispatches through ``BaseAgent.call_tool``
    inside the rollback service, so it goes through the *same* HITL
    gate as any other risky action. The analyst who triggered the
    rollback may therefore need to approve the resulting HITL request
    in a separate UI panel — that is intentional, not a bug.
    """
    # Pre-flight tenant check so we never leak existence of a row outside
    # the caller's scope (we want 404 for cross-tenant reads, not 409).
    with Session(engine) as s:
        tc = s.get(ToolCall, tool_call_id)
        if tc is None:
            raise HTTPException(status_code=404, detail="tool_call not found")
        ensure_row_visible(ctx, tc.tenant_id)

    # Use a fresh session for the actual execution so the agent's commits
    # don't share a transaction with the read-only existence check.
    with Session(engine) as s:
        try:
            result = await execute_rollback(
                s,
                tool_call_id=tool_call_id,
                actor=body.actor or ctx.subject,
                rationale=body.rationale,
            )
        except RollbackNotEligible as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": exc.code, "reason": exc.reason},
            ) from exc
    return result
