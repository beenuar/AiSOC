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

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.organization import Organization
from app.models.tenant import Tenant
from app.services import usage_metering
from app.services.branding.resolver import owning_org_id
from app.services.entitlements import headroom_for_tenant
from app.services.org_scope import resolve_portfolio_scope

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
    await _attach_lake_events(days, current_user.tenant_id, start_day, end_day)
    point_in_time = await usage_metering.measure_point_in_time(db, current_user.tenant_id)

    # The per-tenant override, not the plan default. `limit_for` reads this
    # first, so omitting it reports plan headroom to a tenant whose limits were
    # deliberately raised, which is the opposite of what the row says.
    tenant_limits = await db.scalar(select(Tenant.limits).where(Tenant.id == current_user.tenant_id))

    return {
        "tenant_id": str(current_user.tenant_id),
        "start": start_day.isoformat(),
        "end": end_day.isoformat(),
        "meters": [
            {"key": m.key, "label": m.label, "description": m.description, "source": m.source}
            for m in (*usage_metering.METERS, usage_metering.EVENTS_INGESTED, *usage_metering.POINT_IN_TIME_METERS)
        ],
        "daily": [day.as_dict() for day in days],
        "totals": usage_metering.totals(days),
        "point_in_time": point_in_time,
        # Named with the reason rather than omitted. A missing key reads as
        # zero to anyone charting it, and zero is a measurement. Empty on a
        # deployment that can take every meter.
        "not_measured": usage_metering.unmeasured(),
        # The limits these counts run against, so a usage screen and a quota
        # screen cannot disagree about the same rows.
        "entitlements": [h.as_dict() for h in await headroom_for_tenant(db, current_user.tenant_id, tenant_limits)],
    }


@router.get("/reconciliation")
async def get_reconciliation(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
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
    current_user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
    month: Annotated[str | None, Query(description="YYYY-MM; defaults to the current month")] = None,
) -> Response:
    """A month of usage as CSV, labelled with the organisation it belongs to."""
    year, month_number = _month_or_422(month)
    first, last = _bounds_or_422(year, month_number)

    days = await usage_metering.measure_range(db, current_user.tenant_id, first, last)
    await _attach_lake_events(days, current_user.tenant_id, first, last)
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


@router.get("/organization/export.csv")
async def export_organization_month(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
    month: Annotated[str | None, Query(description="YYYY-MM; defaults to the current month")] = None,
) -> Response:
    """A month of usage for every tenant the caller's organisation manages.

    The per-tenant export names an organisation in its header and covers
    one tenant, which left a provider with forty customers making forty
    requests and adding up the columns by hand.

    The tenant list is whatever `resolve_portfolio_scope` returns for this
    principal, and nothing here widens it. A member scoped to three of a
    forty-tenant portfolio exports three, and a principal who belongs to no
    organisation is refused rather than silently handed their own tenant —
    an export that quietly changes scope is worse than one that fails.
    """
    year, month_number = _month_or_422(month)
    first, last = _bounds_or_422(year, month_number)

    scope = await resolve_portfolio_scope(db, current_user.user_id)
    if not scope.is_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this principal does not belong to an operator organisation; use /usage/export.csv",
        )
    if scope.is_empty:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="no tenants are in scope for this principal",
        )

    tenant_ids = scope.ordered_ids()
    rows = await db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_(tenant_ids)))
    names = {uuid.UUID(str(row.id)): str(row.name) for row in rows}
    sections = await usage_metering.measure_organization(db, tenant_ids=tenant_ids, start=first, end=last, names=names)
    body = usage_metering.organization_to_csv(org_name=scope.org_name, sections=sections)

    slug = scope.org_slug or "organisation"
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="aisoc-usage-{slug}-{year:04d}-{month_number:02d}.csv"'},
    )


def _month_or_422(month: str | None) -> tuple[int, int]:
    if month is None:
        today = datetime.now(UTC).date()
        return today.year, today.month
    try:
        year, month_number = (int(part) for part in month.split("-", 1))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="month must be YYYY-MM") from exc
    return year, month_number


def _bounds_or_422(year: int, month_number: int) -> tuple[date, date]:
    try:
        return usage_metering.month_bounds(year, month_number)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


async def _attach_lake_events(days: list[Any], tenant_id: uuid.UUID, start: date, end: date) -> None:
    """Fold the lake's per-day counts onto the Postgres series.

    Left absent rather than zeroed when the lake is not deployed, so
    `unmeasured()` and the daily series agree about what was not taken.
    """
    series = await usage_metering.measure_events_ingested(tenant_id, start, end)
    if series is None:
        return
    for day in days:
        day.values[usage_metering.EVENTS_INGESTED.key] = series.get(day.day, 0)


async def _org_name(db: Any, tenant_id: uuid.UUID) -> str | None:
    org_id = await owning_org_id(db, tenant_id)
    if org_id is None:
        return None
    return (await db.execute(select(Organization.name).where(Organization.id == org_id))).scalar_one_or_none()
