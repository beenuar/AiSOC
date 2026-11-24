"""The co-managed operating model: shifts, responsibility, escalation routes.

Three small surfaces over migrations 173–175:

* **Shifts** — tenant shift definitions and the handoffs the sweep
  generates from real rows. This supersedes the deleted `shifts.py` the
  absence test pinned: that module served three invented shifts from a
  module-level list; this one holds **no data at all** — every row comes
  from Postgres under RLS, and the handoff snapshot is generated from the
  tenant's own alerts, cases, approvals and investigation runs.
* **Responsibility matrix** — which party (provider/customer/shared) owns
  triage, approval and action per alert class, severity and verb.
  Narrow-only; enforcement lives in `app/services/responsibility.py` and
  is called from the dispatch and approval chokepoints.
* **Escalation routes** — per-tenant destinations for overdue-case
  escalations, over the outbound-webhook subsystem.

Route order: every path here is literal (no `/{param}` roots), so there is
nothing to shadow.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.operating_model import (
    EscalationRoute,
    ResponsibilityRule,
    ShiftHandoff,
    SocShift,
)
from app.models.outbound_webhook import OutboundWebhook
from app.services import responsibility as responsibility_svc
from app.services import shift_handoff as shift_svc

router = APIRouter(prefix="/operating-model", tags=["operating-model"])


# ── shifts ──────────────────────────────────────────────────────────────────


class ShiftBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    timezone: str = "UTC"
    start_minute: int = Field(..., ge=0, le=1439)
    end_minute: int = Field(..., ge=0, le=1439)
    weekdays: list[int] = Field(default_factory=lambda: [1, 2, 3, 4, 5, 6, 7])
    enabled: bool = True


class ShiftOut(ShiftBody):
    id: uuid.UUID
    model_config = ConfigDict(from_attributes=True)


class HandoffOut(BaseModel):
    id: uuid.UUID
    shift_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    snapshot: dict[str, Any]
    notes: str
    acked_by: uuid.UUID | None = None
    acked_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


@router.get("/shifts", response_model=list[ShiftOut])
async def list_shifts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[SocShift]:
    rows = await db.execute(select(SocShift).where(SocShift.tenant_id == current_user.tenant_id).order_by(SocShift.name))
    return list(rows.scalars().all())


@router.post("/shifts", response_model=ShiftOut, status_code=201)
async def create_shift(
    body: ShiftBody,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> SocShift:
    try:
        shift_svc.validate_timezone(body.timezone)
    except shift_svc.ShiftConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    bad_days = [d for d in body.weekdays if d not in range(1, 8)]
    if bad_days or not body.weekdays:
        raise HTTPException(status_code=422, detail="weekdays must be ISO numbers 1..7, at least one")
    shift = SocShift(tenant_id=current_user.tenant_id, **body.model_dump())
    db.add(shift)
    await db.commit()
    await db.refresh(shift)
    return shift


@router.patch("/shifts/{shift_id}", response_model=ShiftOut)
async def update_shift(
    shift_id: uuid.UUID,
    body: ShiftBody,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> SocShift:
    shift = await db.get(SocShift, shift_id)
    if shift is None or shift.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="shift not found")
    try:
        shift_svc.validate_timezone(body.timezone)
    except shift_svc.ShiftConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for key, value in body.model_dump().items():
        setattr(shift, key, value)
    await db.commit()
    await db.refresh(shift)
    return shift


@router.get("/handoffs", response_model=list[HandoffOut])
async def list_handoffs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[ShiftHandoff]:
    rows = await db.execute(
        select(ShiftHandoff).where(ShiftHandoff.tenant_id == current_user.tenant_id).order_by(ShiftHandoff.window_end.desc()).limit(30)
    )
    return list(rows.scalars().all())


class HandoffNotesBody(BaseModel):
    notes: str = Field(..., max_length=8000)


@router.patch("/handoffs/{handoff_id}/notes", response_model=HandoffOut)
async def set_handoff_notes(
    handoff_id: uuid.UUID,
    body: HandoffNotesBody,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> ShiftHandoff:
    """The one human-authored field: the outgoing shift's notes."""
    handoff = await db.get(ShiftHandoff, handoff_id)
    if handoff is None or handoff.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="handoff not found")
    handoff.notes = body.notes
    handoff.generated_by = current_user.user_id
    await db.commit()
    await db.refresh(handoff)
    return handoff


@router.post("/handoffs/{handoff_id}/ack", response_model=HandoffOut)
async def ack_handoff(
    handoff_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> ShiftHandoff:
    """The incoming shift acknowledges. Idempotent: the first ack wins and a
    second returns the row unchanged — who actually took the handoff is the
    fact worth keeping."""
    handoff = await db.get(ShiftHandoff, handoff_id)
    if handoff is None or handoff.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="handoff not found")
    if handoff.acked_at is None:
        handoff.acked_by = current_user.user_id
        handoff.acked_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(handoff)
    return handoff


@router.post("/handoffs/generate", response_model=list[HandoffOut])
async def generate_handoffs_now(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> list[ShiftHandoff]:
    """Generate any due handoff for THIS tenant now, without waiting for the
    sweep — the console's refresh button. Idempotent through the
    one-per-occurrence constraint."""
    await shift_svc.generate_due_handoffs(db)
    await db.commit()
    rows = await db.execute(
        select(ShiftHandoff).where(ShiftHandoff.tenant_id == current_user.tenant_id).order_by(ShiftHandoff.window_end.desc()).limit(30)
    )
    return list(rows.scalars().all())


# ── responsibility matrix ───────────────────────────────────────────────────


class RuleBody(BaseModel):
    activity: str = Field(..., pattern="^(triage|approval|action)$")
    alert_class: str = "*"
    severity: str = Field("*", pattern="^(\\*|info|low|medium|high|critical)$")
    verb: str = "*"
    owner: str = Field(..., pattern="^(provider|customer|shared)$")


class RuleOut(RuleBody):
    id: uuid.UUID
    model_config = ConfigDict(from_attributes=True)


@router.get("/responsibility", response_model=list[RuleOut])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[ResponsibilityRule]:
    rows = await db.execute(
        select(ResponsibilityRule)
        .where(ResponsibilityRule.tenant_id == current_user.tenant_id)
        .order_by(ResponsibilityRule.activity, ResponsibilityRule.verb)
    )
    return list(rows.scalars().all())


@router.put("/responsibility", response_model=list[RuleOut])
async def replace_rules(
    body: list[RuleBody],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> list[ResponsibilityRule]:
    """Replace the tenant's matrix wholesale — the matrix is one document a
    tenant administrator reviews as a whole, and row-by-row drift is how
    two contradictory rules accumulate. Narrow-only semantics mean the
    worst a bad PUT can do is refuse acts until it is corrected."""
    if len(body) > 200:
        raise HTTPException(status_code=422, detail="at most 200 matrix rows")
    existing = await db.execute(select(ResponsibilityRule).where(ResponsibilityRule.tenant_id == current_user.tenant_id))
    for row in existing.scalars().all():
        await db.delete(row)
    out: list[ResponsibilityRule] = []
    for rule in body:
        record = ResponsibilityRule(
            tenant_id=current_user.tenant_id,
            created_by=current_user.user_id,
            **rule.model_dump(),
        )
        db.add(record)
        out.append(record)
    await db.commit()
    for record in out:
        await db.refresh(record)
    return out


# ── escalation routes ───────────────────────────────────────────────────────


class RouteBody(BaseModel):
    responsibility: str = Field("*", pattern="^(\\*|provider|customer|shared)$")
    min_severity: str = Field("high", pattern="^(info|low|medium|high|critical)$")
    unacked_minutes: int = Field(30, ge=5, le=1440)
    webhook_id: uuid.UUID
    enabled: bool = True


class RouteOut(RouteBody):
    id: uuid.UUID
    model_config = ConfigDict(from_attributes=True)


@router.get("/escalation-routes", response_model=list[RouteOut])
async def list_routes(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[EscalationRoute]:
    rows = await db.execute(select(EscalationRoute).where(EscalationRoute.tenant_id == current_user.tenant_id))
    return list(rows.scalars().all())


@router.post("/escalation-routes", response_model=RouteOut, status_code=201)
async def create_route(
    body: RouteBody,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> EscalationRoute:
    webhook = await db.get(OutboundWebhook, body.webhook_id)
    if webhook is None or webhook.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=422,
            detail="webhook_id must name one of this tenant's own outbound webhooks",
        )
    route = EscalationRoute(tenant_id=current_user.tenant_id, **body.model_dump())
    db.add(route)
    await db.commit()
    await db.refresh(route)
    return route


@router.delete("/escalation-routes/{route_id}", status_code=204)
async def delete_route(
    route_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> None:
    route = await db.get(EscalationRoute, route_id)
    if route is None or route.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="route not found")
    await db.delete(route)
    await db.commit()


# ── party preview ───────────────────────────────────────────────────────────


@router.get("/responsibility/preview", response_model=dict)
async def preview_decision(
    activity: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    alert_class: str = "*",
    severity: str = "*",
    verb: str = "*",
) -> dict:
    """What would the matrix say for this act, for ME? The settings page's
    dry-run — an administrator editing rules sees the outcome before an
    analyst hits the refusal."""
    party = await responsibility_svc.party_for(db, caller_home_tenant=current_user.tenant_id, target_tenant=current_user.tenant_id)
    decision = await responsibility_svc.check(
        db,
        tenant_id=current_user.tenant_id,
        activity=activity,
        party=party,
        alert_class=alert_class,
        severity=severity,
        verb=verb,
    )
    return {
        "party": decision.party,
        "allowed": decision.allowed,
        "rule": decision.rule,
        "owner": decision.owner,
    }
