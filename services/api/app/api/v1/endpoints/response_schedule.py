"""A tenant's declaration of when automatic response is acceptable.

Migration 142 created ``aisoc_tenant_response_schedules`` and
``aisoc_tenant_response_windows``, and ``approval_rules.apply_schedule`` was
written and unit-tested to enforce them. Nothing joined the two. The tables
appeared in exactly one file repo-wide — their own migration — with no loader,
no ORM model and no route, so **a tenant could not create a row even by hand**
and a tenant who declared a change freeze got automatic execution right
through it. This module is the write surface; the loader on the dispatch path
is ``services/actions/app/services/response_schedule_store.py``.

Three properties this surface must preserve, each of them a property of the
rule rather than of the API:

* **It can only raise.** ``apply_schedule`` refuses to touch a decision that
  already requires a human and only ever moves AUTOMATIC to ANALYST. There is
  deliberately no field here that relaxes anything — a configuration surface
  that can relax a contract is a configuration surface an attacker wants,
  which is the same reasoning the ``force_auto`` override already lives under.
* **Default off in the strongest sense.** A tenant with no row gets
  byte-identical behaviour to before this existed, because the loader returns
  ``None`` and the rule function returns its input unchanged. Deleting the
  schedule is therefore a real off switch and not a reset to some default.
* **Unknown is never cover.** This platform has no rota integration, so it
  cannot read an on-call state; ``require_human_without_on_call`` therefore
  raises whenever it is set, and the response says so rather than letting an
  operator switch on a condition whose effect they would have to infer.

``settings:read`` / ``settings:write``, same as the autonomy policy surface
next door: choosing when the estate may move without a person is the same
class of decision as choosing the autonomy tier.
"""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.api.v1.deps import AuthUser
from app.db.rls import TenantDBSession

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/response-schedule", tags=["response-schedule"])

#: Mirrors the CHECK constraint on `applies_from_impact`. Kept here so a bad
#: value is a 422 naming the field rather than a 500 out of the driver.
_IMPACTS = ("read_only", "low", "moderate", "high", "severe", "irreversible")

_WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


class BusinessWindowIn(BaseModel):
    """One recurring window in which automatic response is acceptable."""

    weekday: int = Field(ge=0, le=6, description="datetime.weekday(): Monday is 0")
    start_minute: int = Field(ge=0, le=1439, description="minutes from local midnight")
    end_minute: int = Field(ge=0, le=1440, description="1440 means midnight at the end of the day")

    @model_validator(mode="after")
    def _reject_an_empty_window(self) -> BusinessWindowIn:
        if self.start_minute == self.end_minute:
            raise ValueError("start_minute and end_minute are equal, which declares a window of zero length")
        return self


class BusinessWindowOut(BusinessWindowIn):
    id: str
    weekday_name: str


class ScheduleIn(BaseModel):
    timezone_name: str = Field(default="UTC", max_length=64)
    require_human_outside_business_hours: bool = False
    require_human_without_on_call: bool = False
    freeze_active: bool = False
    freeze_reason: str = Field(default="", max_length=500)
    applies_from_impact: str = "moderate"
    windows: list[BusinessWindowIn] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> ScheduleIn:
        if self.applies_from_impact not in _IMPACTS:
            raise ValueError(f"applies_from_impact must be one of {_IMPACTS}")
        try:
            ZoneInfo(self.timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"timezone_name '{self.timezone_name}' is not an IANA timezone") from exc
        if self.require_human_outside_business_hours and not self.windows:
            # Not an error — a tenant who switches the condition on and
            # declares no windows means "never automatic unattended", which
            # `ResponseSchedule.is_business_hours` implements deliberately.
            # Saying so in the response is what stops it being a surprise.
            pass
        return self


class ScheduleOut(ScheduleIn):
    windows: list[BusinessWindowOut] = Field(default_factory=list)
    updated_at: datetime | None = None
    updated_by: str = ""
    #: What this configuration does, computed from it rather than described in
    #: documentation the operator has not got open.
    effect: list[str] = Field(default_factory=list)


def _effect(schedule: ScheduleIn) -> list[str]:
    """Plain sentences for what is actually switched on."""
    out: list[str] = []
    if schedule.freeze_active:
        out.append("A change freeze is in force: every automatic action at or above the impact floor requires an analyst.")
    if schedule.require_human_outside_business_hours:
        if schedule.windows:
            out.append(
                f"Outside the {len(schedule.windows)} declared window(s), in {schedule.timezone_name}, "
                "automatic actions at or above the impact floor require an analyst."
            )
        else:
            out.append(
                "No windows are declared, so this condition means never automatic unattended: an empty window "
                "list is not read as 'always business hours'."
            )
    if schedule.require_human_without_on_call:
        out.append(
            "This platform has no rota integration, so the on-call state cannot be read and is treated as "
            "nobody on call. With this set, automatic actions at or above the impact floor always require an "
            "analyst until a rota source exists."
        )
    if not out:
        out.append("Nothing is switched on: this schedule raises no requirement and grades exactly as no schedule at all.")
    return out


_SELECT_SCHEDULE = """
    SELECT timezone_name, require_human_outside_business_hours, require_human_without_on_call,
           freeze_active, freeze_reason, applies_from_impact, updated_at, updated_by
      FROM aisoc_tenant_response_schedules
     WHERE tenant_id = CAST(:tenant_id AS uuid)
"""

_SELECT_WINDOWS = """
    SELECT id::text AS id, weekday, start_minute, end_minute
      FROM aisoc_tenant_response_windows
     WHERE tenant_id = CAST(:tenant_id AS uuid)
     ORDER BY weekday, start_minute
"""

_UPSERT_SCHEDULE = """
    INSERT INTO aisoc_tenant_response_schedules (
        tenant_id, timezone_name, require_human_outside_business_hours,
        require_human_without_on_call, freeze_active, freeze_reason,
        applies_from_impact, updated_at, updated_by
    ) VALUES (
        CAST(:tenant_id AS uuid), :timezone_name, :outside_hours,
        :without_on_call, :freeze_active, :freeze_reason,
        :applies_from_impact, NOW(), :updated_by
    )
    ON CONFLICT (tenant_id) DO UPDATE SET
        timezone_name = EXCLUDED.timezone_name,
        require_human_outside_business_hours = EXCLUDED.require_human_outside_business_hours,
        require_human_without_on_call = EXCLUDED.require_human_without_on_call,
        freeze_active = EXCLUDED.freeze_active,
        freeze_reason = EXCLUDED.freeze_reason,
        applies_from_impact = EXCLUDED.applies_from_impact,
        updated_at = NOW(),
        updated_by = EXCLUDED.updated_by
"""


async def _read(db: TenantDBSession, tenant_id: str) -> ScheduleOut | None:
    row = (await db.execute(text(_SELECT_SCHEDULE), {"tenant_id": tenant_id})).mappings().first()
    if row is None:
        return None
    windows = (await db.execute(text(_SELECT_WINDOWS), {"tenant_id": tenant_id})).mappings().all()
    body = ScheduleIn(
        timezone_name=row["timezone_name"],
        require_human_outside_business_hours=row["require_human_outside_business_hours"],
        require_human_without_on_call=row["require_human_without_on_call"],
        freeze_active=row["freeze_active"],
        freeze_reason=row["freeze_reason"],
        applies_from_impact=row["applies_from_impact"],
        windows=[BusinessWindowIn(weekday=w["weekday"], start_minute=w["start_minute"], end_minute=w["end_minute"]) for w in windows],
    )
    return ScheduleOut(
        **body.model_dump(exclude={"windows"}),
        windows=[
            BusinessWindowOut(
                id=w["id"],
                weekday=w["weekday"],
                weekday_name=_WEEKDAY_NAMES[int(w["weekday"])],
                start_minute=w["start_minute"],
                end_minute=w["end_minute"],
            )
            for w in windows
        ],
        updated_at=row["updated_at"],
        updated_by=row["updated_by"] or "",
        effect=_effect(body),
    )


@router.get("", response_model=ScheduleOut)
async def get_response_schedule(user: AuthUser, db: TenantDBSession) -> ScheduleOut:
    """The tenant's schedule, or an all-off one when they have declared none.

    An all-off schedule and no row are different states and the difference is
    load-bearing — the loader returns ``None`` for no row, which is the
    byte-identical-to-before path — so ``declared`` says which this is.
    """
    await user.require_permission_db("settings:read", db)
    existing = await _read(db, str(user.tenant_id))
    if existing is not None:
        return existing
    empty = ScheduleIn()
    return ScheduleOut(**empty.model_dump(exclude={"windows"}), windows=[], effect=_effect(empty))


@router.put("", response_model=ScheduleOut)
async def set_response_schedule(payload: ScheduleIn, user: AuthUser, db: TenantDBSession) -> ScheduleOut:
    """Declare the schedule and replace its windows in one transaction.

    Windows are replaced wholesale rather than patched, because a schedule
    half-applied is a schedule nobody declared: a window list that is updated
    in pieces has an instant where Tuesday is covered and Wednesday is not,
    and an automatic containment that lands in that instant is governed by a
    configuration no operator ever wrote down.
    """
    await user.require_permission_db("settings:write", db)
    tenant_id = str(user.tenant_id)
    await db.execute(
        text(_UPSERT_SCHEDULE),
        {
            "tenant_id": tenant_id,
            "timezone_name": payload.timezone_name,
            "outside_hours": payload.require_human_outside_business_hours,
            "without_on_call": payload.require_human_without_on_call,
            "freeze_active": payload.freeze_active,
            "freeze_reason": payload.freeze_reason,
            "applies_from_impact": payload.applies_from_impact,
            "updated_by": str(getattr(user, "email", "") or user.user_id),
        },
    )
    await db.execute(
        text("DELETE FROM aisoc_tenant_response_windows WHERE tenant_id = CAST(:tenant_id AS uuid)"),
        {"tenant_id": tenant_id},
    )
    for window in payload.windows:
        await db.execute(
            text(
                """
                INSERT INTO aisoc_tenant_response_windows (tenant_id, weekday, start_minute, end_minute)
                VALUES (CAST(:tenant_id AS uuid), :weekday, :start_minute, :end_minute)
                """
            ),
            {
                "tenant_id": tenant_id,
                "weekday": window.weekday,
                "start_minute": window.start_minute,
                "end_minute": window.end_minute,
            },
        )
    await db.commit()
    logger.info(
        "response_schedule.updated",
        tenant_id=tenant_id,
        freeze_active=payload.freeze_active,
        windows=len(payload.windows),
        at=datetime.now(UTC).isoformat(),
    )
    result = await _read(db, tenant_id)
    if result is None:  # pragma: no cover — the upsert above just wrote it
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="schedule vanished after write")
    return result


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def clear_response_schedule(user: AuthUser, db: TenantDBSession) -> None:
    """Remove the schedule entirely, returning to no-schedule behaviour.

    Deleting the row is the real off switch. Setting every flag false leaves a
    row the loader still reads and still has to grade; removing it is what
    makes ``apply_schedule`` a no-op again.
    """
    await user.require_permission_db("settings:write", db)
    tenant_id = str(user.tenant_id)
    await db.execute(
        text("DELETE FROM aisoc_tenant_response_windows WHERE tenant_id = CAST(:tenant_id AS uuid)"),
        {"tenant_id": tenant_id},
    )
    await db.execute(
        text("DELETE FROM aisoc_tenant_response_schedules WHERE tenant_id = CAST(:tenant_id AS uuid)"),
        {"tenant_id": tenant_id},
    )
    await db.commit()
    logger.info("response_schedule.cleared", tenant_id=tenant_id)
