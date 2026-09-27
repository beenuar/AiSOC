"""Usage metering: what a tenant did, counted from the rows that record it.

The tenant comes from the credential. There is no tenant parameter on any
route here, which is deliberate: usage is the input to a commercial
conversation, and a surface that let an authenticated user name somebody
else's tenant would publish one customer's volume to another.

No pricing. These are counts and measured model costs. What they are worth
belongs nowhere near the code that answers what happened.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.organization import Organization
from app.services import usage_metering
from app.services.branding.resolver import owning_org_id
from app.services.entitlements import headroom_for_tenant

router = APIRouter(prefix="/usage", tags=["usage"])

#: Longest window a single request may ask for. Each day is a query per
#: meter, so an unbounded range is a slow request an authenticated caller can
#: ask for repeatedly.
MAX_RANGE_DAYS = 186


def _parse_day(raw: str | None, *, default: date) -> date:
    if raw is None:
        return default
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{raw!r} is not an ISO date") from exc


@router.get("")
async def get_usage(
    db: DBSession,
    current_user: AuthUser,
    start: Annotated[str | None, Query()] = None,
    end: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Daily usage for the caller's tenant, defaulting to the last 30 days."""
    today = datetime.now(UTC).date()
    end_day = _parse_day(end, default=today)
    start_day = _parse_day(start, default=end_day - timedelta(days=29))

    if end_day < start_day:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="end is before start")
    if (end_day - start_day).days + 1 > MAX_RANGE_DAYS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"range exceeds {MAX_RANGE_DAYS} days; export a month at a time",
        )

    days = await usage_metering.measure_range(db, current_user.tenant_id, start_day, end_day)
    point_in_time = await usage_metering.measure_point_in_time(db, current_user.tenant_id)

    return {
        "tenant_id": str(current_user.tenant_id),
        "start": start_day.isoformat(),
        "end": end_day.isoformat(),
        "meters": [
            {"key": m.key, "label": m.label, "description": m.description, "source": m.source}
            for m in (*usage_metering.METERS, *usage_metering.POINT_IN_TIME_METERS)
        ],
        "daily": [day.as_dict() for day in days],
        "totals": usage_metering.totals(days),
        "point_in_time": point_in_time,
        # Named with the reason rather than omitted. A missing key reads as
        # zero to anyone charting it, and zero is a measurement.
        "not_measured": usage_metering.UNMEASURED,
        # The limits these counts run against, so a usage screen and a quota
        # screen cannot disagree about the same rows.
        "entitlements": [h.as_dict() for h in await headroom_for_tenant(db, current_user.tenant_id)],
    }


@router.get("/reconciliation")
async def get_reconciliation(
    db: DBSession,
    current_user: Annotated[Any, require_permission("settings:read")],
    start: Annotated[str | None, Query()] = None,
    end: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Compare the daily sum against one query over the whole window.

    Exposed rather than kept in a test so an operator disputing an invoice
    can run the same check the test runs, against their own rows.
    """
    today = datetime.now(UTC).date()
    end_day = _parse_day(end, default=today)
    start_day = _parse_day(start, default=end_day - timedelta(days=29))
    report = await usage_metering.reconcile(db, current_user.tenant_id, start_day, end_day)
    return {
        "start": start_day.isoformat(),
        "end": end_day.isoformat(),
        "meters": report,
        "all_agree": all(entry["agrees"] for entry in report.values()),
    }


@router.get("/export.csv")
async def export_month(
    db: DBSession,
    current_user: Annotated[Any, require_permission("reports:read")],
    month: Annotated[str | None, Query(description="YYYY-MM; defaults to the current month")] = None,
) -> Response:
    """A month of usage as CSV, labelled with the organisation it belongs to."""
    today = datetime.now(UTC).date()
    if month is None:
        year, month_number = today.year, today.month
    else:
        try:
            year, month_number = (int(part) for part in month.split("-", 1))
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="month must be YYYY-MM") from exc

    try:
        first, last = usage_metering.month_bounds(year, month_number)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    days = await usage_metering.measure_range(db, current_user.tenant_id, first, last)
    point_in_time = await usage_metering.measure_point_in_time(db, current_user.tenant_id)
    body = usage_metering.to_csv(
        tenant_id=current_user.tenant_id,
        org_name=await _org_name(db, current_user.tenant_id),
        days=days,
        point_in_time=point_in_time,
    )

    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="aisoc-usage-{year:04d}-{month_number:02d}.csv"'},
    )


async def _org_name(db: Any, tenant_id: uuid.UUID) -> str | None:
    org_id = await owning_org_id(db, tenant_id)
    if org_id is None:
        return None
    return (await db.execute(select(Organization.name).where(Organization.id == org_id))).scalar_one_or_none()
