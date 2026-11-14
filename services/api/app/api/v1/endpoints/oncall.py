"""On-call status endpoints for the mobile responder PWA.

The PWA needs a lightweight, mobile-first way to ask "who is on-call right
now?" and to flip your own status with a single tap. The full rotation
schedule lives in PagerDuty / Opsgenie / a YAML file — what we store here
is the *current* snapshot per user so:

* the PWA can show a prioritized "page on-call" list,
* push fan-out can target a specific user instead of an entire topic,
* the agent can respect "do not disturb" when an analyst snoozes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser
from app.db.rls import TenantDBSession
from app.models.responder import OnCallStatus
from app.models.tenant import User

router = APIRouter(prefix="/oncall", tags=["responder", "oncall"])


_STATUS_VALUES = {"available", "busy", "offline", "snoozed"}


class OnCallEntry(BaseModel):
    user_id: uuid.UUID
    user_email: str | None = None
    user_name: str | None = None
    status: str
    schedule_ref: str | None = None
    rotation: str | None = None
    note: str | None = None
    until: datetime | None = None
    updated_at: datetime

    model_config = {"from_attributes": True}


class OnCallListResponse(BaseModel):
    items: list[OnCallEntry]
    total: int


class OnCallUpdateRequest(BaseModel):
    status: Literal["available", "busy", "offline", "snoozed"]
    note: str | None = Field(default=None, max_length=500)
    snooze_minutes: int | None = Field(default=None, ge=1, le=24 * 60)
    rotation: str | None = Field(default=None, max_length=80)
    schedule_ref: str | None = Field(default=None, max_length=200)


@router.get("", response_model=OnCallListResponse)
async def list_oncall(
    user: AuthUser,
    db: TenantDBSession,
    status_filter: str | None = Query(default=None, alias="status"),
) -> OnCallListResponse:
    """List on-call status for everyone in the tenant.

    The PWA paging UI lights up everyone marked ``available`` first, then
    ``busy`` (so the next-best person is one tap away), and finally everyone
    else for context.
    """
    stmt = select(OnCallStatus, User).join(User, User.id == OnCallStatus.user_id).where(OnCallStatus.tenant_id == user.tenant_id)
    if status_filter:
        if status_filter not in _STATUS_VALUES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of {_STATUS_VALUES}",
            )
        stmt = stmt.where(OnCallStatus.status == status_filter)

    rows = (await db.execute(stmt)).all()
    items: list[OnCallEntry] = []
    for status_row, user_row in rows:
        items.append(
            OnCallEntry(
                user_id=status_row.user_id,
                user_email=user_row.email,
                user_name=user_row.username,
                status=status_row.status,
                schedule_ref=status_row.schedule_ref,
                rotation=status_row.rotation,
                note=status_row.note,
                until=status_row.until,
                updated_at=status_row.updated_at,
            )
        )

    # Sort: available → busy → snoozed → offline, then most recent first.
    order = {"available": 0, "busy": 1, "snoozed": 2, "offline": 3}
    items.sort(key=lambda e: (order.get(e.status, 99), -e.updated_at.timestamp()))

    return OnCallListResponse(items=items, total=len(items))


@router.get("/me", response_model=OnCallEntry)
async def my_oncall(
    user: AuthUser,
    db: TenantDBSession,
) -> OnCallEntry:
    stmt = (
        select(OnCallStatus, User)
        .join(User, User.id == OnCallStatus.user_id)
        .where(
            OnCallStatus.tenant_id == user.tenant_id,
            OnCallStatus.user_id == user.user_id,
        )
    )
    row = (await db.execute(stmt)).first()
    if row is None:
        # Auto-provision an offline row so /me always returns something.
        new_row = OnCallStatus(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            status="offline",
        )
        db.add(new_row)
        await db.commit()
        await db.refresh(new_row)
        return OnCallEntry(
            user_id=user.user_id,
            user_email=user.email,
            user_name=None,
            status="offline",
            schedule_ref=None,
            rotation=None,
            note=None,
            until=None,
            updated_at=new_row.updated_at,
        )

    status_row, user_row = row
    return OnCallEntry(
        user_id=status_row.user_id,
        user_email=user_row.email,
        user_name=user_row.username,
        status=status_row.status,
        schedule_ref=status_row.schedule_ref,
        rotation=status_row.rotation,
        note=status_row.note,
        until=status_row.until,
        updated_at=status_row.updated_at,
    )


@router.put("/me", response_model=OnCallEntry)
async def update_my_oncall(
    user: AuthUser,
    db: TenantDBSession,
    body: OnCallUpdateRequest,
) -> OnCallEntry:
    """Set my own on-call status.

    Use ``snoozed`` with ``snooze_minutes`` to defer paging temporarily;
    the PWA shows a countdown and the agent uses it to skip you for that
    window.
    """
    until: datetime | None = None
    if body.status == "snoozed":
        minutes = body.snooze_minutes or 60
        until = datetime.now(UTC) + timedelta(minutes=minutes)

    existing = (
        await db.execute(
            select(OnCallStatus).where(
                OnCallStatus.tenant_id == user.tenant_id,
                OnCallStatus.user_id == user.user_id,
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = OnCallStatus(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
        )
        db.add(existing)

    existing.status = body.status
    existing.note = body.note
    existing.rotation = body.rotation
    existing.schedule_ref = body.schedule_ref
    existing.until = until

    await db.commit()
    await db.refresh(existing)

    return OnCallEntry(
        user_id=existing.user_id,
        user_email=user.email,
        user_name=None,
        status=existing.status,
        schedule_ref=existing.schedule_ref,
        rotation=existing.rotation,
        note=existing.note,
        until=existing.until,
        updated_at=existing.updated_at,
    )
