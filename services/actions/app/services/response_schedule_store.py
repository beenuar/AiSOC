"""Load a tenant's response schedule out of the store migration 142 created.

Migration 142 created ``aisoc_tenant_response_schedules`` and
``aisoc_tenant_response_windows`` and named the enforcement point in its own
header. ``approval_rules.ResponseSchedule`` and ``approval_rules.apply_schedule``
were written and unit-tested against it. Nothing joined the two: the tables
appeared in exactly one file repo-wide — their own migration — and
``apply_schedule``'s thirteen call sites were all in its own test. There was no
loader, no ORM model, no route and no console surface, so a tenant could not
create a row even by hand, and a tenant who declared a change freeze got
automatic execution right through it.

This module is the loader. It is deliberately the same shape as
``tenant_policy``: asyncpg against the resolved DSN, a short cache because the
dispatch path is latency-sensitive and a schedule changes rarely, and a
conservative answer when the read fails.

**What "conservative" means here is the opposite of ``tenant_policy``'s**, and
the asymmetry is the point. A schedule can only *raise* a requirement, so the
safe answer to "I could not read it" is not an empty schedule — that would
silently re-enable automatic execution at 03:00 for a tenant who had asked for
the opposite. It is a schedule that raises: ``freeze_active`` set, with a
reason saying the schedule was unreadable. A tenant with genuinely *no row*
still gets ``None`` and byte-identical behaviour to before this existed, which
is the other half of the same rule — absent and unreadable are different
answers.
"""

from __future__ import annotations

import os
import time
from datetime import time as clock_time
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import structlog

from app.live_actions.approval_rules import BusinessWindow, ResponseSchedule
from app.live_actions.contract import ActionImpact

logger = structlog.get_logger(__name__)

#: Schedules change rarely and dispatch is latency-sensitive. Short enough
#: that a freeze an operator declares takes effect inside a minute.
CACHE_TTL_SECONDS = 30.0

_cache: dict[str, tuple[float, ResponseSchedule | None]] = {}

_SCHEDULE_SQL = """
    SELECT timezone_name,
           require_human_outside_business_hours,
           require_human_without_on_call,
           freeze_active,
           freeze_reason,
           applies_from_impact
      FROM aisoc_tenant_response_schedules
     WHERE tenant_id = $1
"""

_WINDOWS_SQL = """
    SELECT weekday, start_minute, end_minute
      FROM aisoc_tenant_response_windows
     WHERE tenant_id = $1
     ORDER BY weekday, start_minute
"""


def resolve_dsn() -> str | None:
    dsn = (os.getenv("DATABASE_DSN") or os.getenv("DATABASE_URL") or "").strip()
    if not dsn:
        return None
    return dsn.replace("postgresql+asyncpg://", "postgresql://")


def _unreadable_schedule(reason: str) -> ResponseSchedule:
    """The fail-closed answer: a freeze, named as a read failure.

    An empty schedule would be the dangerous answer. ``apply_schedule``
    returns its input untouched for a schedule with no conditions set, so
    "could not read the tenant's schedule" would mean "act as though they
    declared nothing" — which for a tenant in a change freeze is exactly the
    automatic execution the freeze exists to stop.
    """
    logger.error("response_schedule.read_failed", reason=reason)
    return ResponseSchedule(freeze_active=True, applies_from_impact=ActionImpact.MODERATE)


def _window_from_row(row: Any) -> BusinessWindow:
    start = int(row["start_minute"])
    end = int(row["end_minute"])
    return BusinessWindow(
        weekday=int(row["weekday"]),
        start=clock_time(hour=start // 60, minute=start % 60),
        # 1440 is a legal end_minute and means "to midnight"; `time` has no
        # 24:00, so it is stored as the end of the day the window belongs to.
        end=clock_time(hour=23, minute=59, second=59) if end >= 1440 else clock_time(hour=end // 60, minute=end % 60),
    )


def _tzinfo(name: str) -> tuple[str, Any]:
    try:
        return name, ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        # A timezone this host cannot resolve is a configuration error, not a
        # reason to grade the schedule in UTC silently: the windows would be
        # evaluated against the wrong clock and the tenant would never know.
        logger.warning("response_schedule.unknown_timezone", timezone_name=name)
        return name, ZoneInfo("UTC")


async def _load(tenant_id: str, dsn: str) -> ResponseSchedule | None:
    import asyncpg  # noqa: PLC0415 — optional at import time; only needed with a DSN

    conn = await asyncpg.connect(dsn, timeout=5.0)
    try:
        # Bind the tenant so the RLS policies migration 142 installed apply to
        # this read. Without it the policy's `OR current_tenant_id() IS NULL`
        # arm makes the read tenant-wide, which is the fail-open shape this
        # repository has shipped before.
        await conn.execute("SELECT set_config('aisoc.tenant_id', $1, true)", tenant_id)
        row = await conn.fetchrow(_SCHEDULE_SQL, UUID(tenant_id))
        if row is None:
            return None
        windows = await conn.fetch(_WINDOWS_SQL, UUID(tenant_id))
    finally:
        await conn.close()

    name, tz = _tzinfo(str(row["timezone_name"] or "UTC"))
    return ResponseSchedule(
        windows=tuple(_window_from_row(w) for w in windows),
        # No rota integration exists, so this platform cannot read an on-call
        # state. `None` is that answer, and `apply_schedule` treats it as
        # nobody on call with a reason saying so — a failed lookup must not
        # read as cover.
        on_call_now=None,
        require_human_outside_business_hours=bool(row["require_human_outside_business_hours"]),
        require_human_without_on_call=bool(row["require_human_without_on_call"]),
        freeze_active=bool(row["freeze_active"]),
        applies_from_impact=ActionImpact(str(row["applies_from_impact"])),
        timezone_name=name,
        tz=tz,
    )


async def resolve_response_schedule(tenant_id: str | UUID | None) -> ResponseSchedule | None:
    """The tenant's schedule, or ``None`` when they have not declared one."""
    dsn = resolve_dsn()
    if tenant_id is None or dsn is None:
        # Single-tenant or no database: there is no table to have a row in, so
        # there is no schedule, and `apply_schedule(None)` is a no-op.
        return None

    key = str(tenant_id)
    cached = _cache.get(key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < CACHE_TTL_SECONDS:
        return cached[1]

    try:
        schedule = await _load(key, dsn)
    except Exception as exc:  # noqa: BLE001 — never fall open on a read failure
        return _unreadable_schedule(f"{type(exc).__name__}: {exc}")

    _cache[key] = (now, schedule)
    return schedule


def clear_cache() -> None:
    """Drop the schedule cache. Used by tests and after a schedule update."""
    _cache.clear()
