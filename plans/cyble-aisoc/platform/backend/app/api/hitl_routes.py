"""HITL approval REST API.

Analyst-facing endpoints that drive the blocking HITL gateway:

- `GET  /hitl/pending` — list PENDING requests across cases
- `GET  /hitl/{id}`    — fetch one request (any state)
- `POST /hitl/{id}/approve` — analyst approves (MFA required when configured)
- `POST /hitl/{id}/deny`    — analyst denies (MFA required when configured)
- `GET  /hitl/case/{case_id}` — full HITL history for a case

MFA verification is enforced at the API boundary so the blocked agent
coroutine doesn't need to know anything about analyst identity. The MFA
receipt hash is persisted with the decision for tamper-evident audit.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import engine
from app.hitl import MfaVerificationError, verify_mfa
from app.hitl.dry_run import simulate_action, simulate_runbook
from app.hitl.gateway import gateway
from app.models.hitl import HitlChannel, HitlRequest, HitlState
from app.security.tenant import (
    TenantContext,
    apply_tenant_filter,
    ensure_row_visible,
    require_tenant,
)

router = APIRouter(prefix="/hitl", tags=["hitl"])


class HitlDecisionBody(BaseModel):
    decided_by: str = Field(..., description="Analyst principal id / email")
    mfa_method: str = Field(
        "dev-shared-secret",
        description="MFA method: totp | webauthn | sso-mfa | dev-shared-secret",
    )
    mfa_token: str = Field("", description="MFA token presented by the analyst")
    channel: HitlChannel = Field(HitlChannel.CONSOLE, description="Decision channel")
    reason: str | None = Field(None, description="Optional analyst comment")


def _req_to_dict(req: HitlRequest) -> dict[str, Any]:
    return {
        "id": req.id,
        "tenant_id": req.tenant_id,
        "case_id": req.case_id,
        "trace_id": req.trace_id,
        "tool_call_id": req.tool_call_id,
        "agent": req.agent,
        "tool_name": req.tool_name,
        "integration": req.integration,
        "risk_class": req.risk_class,
        "params": req.params,
        "rationale": req.rationale,
        "blast_radius": req.blast_radius,
        "state": req.state.value if hasattr(req.state, "value") else str(req.state),
        "created_at": _iso(req.created_at),
        "expires_at": _iso(req.expires_at),
        "decided_at": _iso(req.decided_at) if req.decided_at else None,
        "decided_by": req.decided_by,
        "decided_channel": req.decided_channel.value if req.decided_channel else None,
        "decision_reason": req.decision_reason,
        "escalated": req.escalated,
        "escalated_at": _iso(req.escalated_at) if req.escalated_at else None,
        "escalation_target": req.escalation_target,
        "notifications": req.notifications,
    }


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@router.get("/pending")
def list_pending(
    ctx: TenantContext = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """List PENDING HITL requests visible to caller's tenant, oldest first."""
    with Session(engine) as s:
        stmt = select(HitlRequest).where(HitlRequest.state == HitlState.PENDING)
        stmt = apply_tenant_filter(stmt, HitlRequest.tenant_id, ctx)
        stmt = stmt.order_by(HitlRequest.created_at.asc())
        rows = list(s.exec(stmt).all())
    return [_req_to_dict(r) for r in rows]


@router.get("/{request_id}")
def get_request(
    request_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    with Session(engine) as s:
        req = s.get(HitlRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="HITL request not found")
    ensure_row_visible(ctx, req.tenant_id)
    return _req_to_dict(req)


@router.get("/case/{case_id}")
def list_for_case(
    case_id: int,
    ctx: TenantContext = Depends(require_tenant),
) -> list[dict[str, Any]]:
    with Session(engine) as s:
        stmt = select(HitlRequest).where(HitlRequest.case_id == case_id)
        stmt = apply_tenant_filter(stmt, HitlRequest.tenant_id, ctx)
        stmt = stmt.order_by(HitlRequest.created_at.asc())
        rows = list(s.exec(stmt).all())
    return [_req_to_dict(r) for r in rows]


def _enforce_tenant_for_decision(request_id: int, ctx: TenantContext) -> HitlRequest:
    """Block analysts from approving/denying HITLs outside their tenant scope."""
    with Session(engine) as s:
        req = s.get(HitlRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="HITL request not found")
    ensure_row_visible(ctx, req.tenant_id)
    return req


@router.post("/{request_id}/approve")
def approve(
    request_id: int,
    body: HitlDecisionBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _enforce_tenant_for_decision(request_id, ctx)
    try:
        receipt = verify_mfa(body.mfa_method, body.mfa_token, body.decided_by)
    except MfaVerificationError as exc:
        raise HTTPException(status_code=401, detail=f"MFA failed: {exc}") from exc
    try:
        req = gateway.decide(
            request_id=request_id,
            approve=True,
            decided_by=body.decided_by,
            mfa_method=receipt.method,
            mfa_receipt_hash=receipt.receipt_hash,
            channel=body.channel,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _req_to_dict(req)


@router.post("/{request_id}/deny")
def deny(
    request_id: int,
    body: HitlDecisionBody,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    _enforce_tenant_for_decision(request_id, ctx)
    try:
        receipt = verify_mfa(body.mfa_method, body.mfa_token, body.decided_by)
    except MfaVerificationError as exc:
        raise HTTPException(status_code=401, detail=f"MFA failed: {exc}") from exc
    try:
        req = gateway.decide(
            request_id=request_id,
            approve=False,
            decided_by=body.decided_by,
            mfa_method=receipt.method,
            mfa_receipt_hash=receipt.receipt_hash,
            channel=body.channel,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _req_to_dict(req)


# ─── Dry-run / blast-radius preview (t4-dry-run) ─────────────────────


class DryRunStep(BaseModel):
    """One step in a runbook simulation request."""

    tool_name: str = Field(..., description="Registered tool name")
    params: dict[str, Any] = Field(default_factory=dict)


class DryRunRequest(BaseModel):
    """Single-step or multi-step dry-run simulation payload."""

    tool_name: str | None = Field(
        None, description="Single-step convenience: tool to simulate"
    )
    params: dict[str, Any] = Field(default_factory=dict)
    steps: list[DryRunStep] | None = Field(
        None,
        description=(
            "Multi-step runbook; takes precedence over `tool_name` when set."
        ),
    )


@router.post("/dry-run")
def dry_run(
    body: DryRunRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Predict the blast radius of a tool call (or whole runbook).

    Pure read: no DB writes, no external IO, no LLM call. The simulator
    walks the CMDB (per-tenant) and the Threat Graph to surface:

    - canonical target (criticality, environment, owner, compliance)
    - first-hop dependents (logins, observed IOCs, group memberships)
    - reversibility (from the tool registry's reverse-action wiring)
    - severity hint suitable for the HITL traffic-light
    - counterfactual "what happens if you skip this?" line

    The HITL gateway calls the same simulator under the hood when an
    agent files an approval request; this endpoint exposes it for
    runbook authors and operator-console previews so the analyst sees
    the same prediction the agent does before submitting the action.
    """
    if body.steps:
        return simulate_runbook(
            steps=[s.model_dump() for s in body.steps],
            tenant_id=ctx.active_tenant_id,
        )
    if not body.tool_name:
        raise HTTPException(
            status_code=400,
            detail="provide either `tool_name` (+ params) or `steps`",
        )
    sim = simulate_action(
        tool_name=body.tool_name,
        params=body.params,
        tenant_id=ctx.active_tenant_id,
    )
    return sim.to_dict()
