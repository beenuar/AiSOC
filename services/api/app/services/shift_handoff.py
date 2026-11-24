"""Shift handoffs generated from real rows.

The previous shift board served three invented shifts from a module-level
list and was deleted, with a test pinning its absence — "a route with no
caller serving data nobody entered is not a feature with a bug". This is
the rebuild that pin invited: shifts are tenant configuration, and a
handoff is a SNAPSHOT of the tenant's real open work at the moment the
shift ends, acknowledged by the shift coming on. Nothing in the snapshot
is typed in; the one human field is the outgoing shift's notes.

Time
----
A shift is a local-clock fact ("06:00–18:00 in Europe/Berlin") stored as
minutes-of-day in an IANA timezone, so it survives DST. The generator asks
"which occurrence of this shift ended most recently?" and resolves it to
instants; an overnight shift (end < start) belongs to the day it STARTED.

Snapshot honesty
----------------
Each section is computed from its own store and carries its own failure:
a store that cannot answer contributes ``{"could_not_check": reason}``
rather than zeros. The attention section reuses the service-review criteria (open
cases that are unowned, or past their next-action deadline) by querying
the same columns the `/cases/attention` endpoint reads.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.shift_handoff")

#: How far past a shift's end the generator still produces its handoff.
#: Beyond this the occurrence is history nobody handed over; generating a
#: week-old handoff on a worker restart would be invented diligence.
GENERATION_GRACE = timedelta(hours=6)


class ShiftConfigError(ValueError):
    pass


def validate_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ShiftConfigError(f"{name!r} is not an IANA timezone") from exc


@dataclass(frozen=True)
class Occurrence:
    """One concrete run of a shift, as instants."""

    start: datetime
    end: datetime


def latest_ended_occurrence(
    *,
    tz_name: str,
    start_minute: int,
    end_minute: int,
    weekdays: list[int],
    now: datetime | None = None,
) -> Occurrence | None:
    """The most recently ENDED occurrence, or None when none ended within
    the generation grace window.

    An overnight shift (end_minute < start_minute) belongs to the local day
    it started: Friday 22:00–06:00 runs when Friday is in ``weekdays`` and
    ends Saturday morning.
    """
    tz = validate_timezone(tz_name)
    now = now or datetime.now(UTC)
    local_now = now.astimezone(tz)
    overnight = end_minute < start_minute

    for days_back in range(0, 9):
        day = (local_now - timedelta(days=days_back)).date()
        if day.isoweekday() not in weekdays:
            continue
        start_local = datetime.combine(day, time(start_minute // 60, start_minute % 60), tzinfo=tz)
        end_day = day + timedelta(days=1) if overnight else day
        end_local = datetime.combine(end_day, time(end_minute // 60, end_minute % 60), tzinfo=tz)
        end_utc = end_local.astimezone(UTC)
        if end_utc <= now:
            if now - end_utc > GENERATION_GRACE:
                return None
            return Occurrence(start=start_local.astimezone(UTC), end=end_utc)
    return None


# ── snapshot sections, one store each ──────────────────────────────────────

_OPEN_ALERTS_SQL = text(
    """
    SELECT severity, count(*) FROM alerts
    WHERE tenant_id = :tenant_id AND status NOT IN ('resolved', 'closed', 'suppressed')
    GROUP BY severity
    """
)

_ATTENTION_CASES_SQL = text(
    """
    SELECT case_number, title, severity,
           (assigned_to_id IS NULL AND owner_agent_run_id IS NULL) AS unowned,
           (next_action_due_at IS NOT NULL AND next_action_due_at < now()) AS overdue
    FROM aisoc_cases
    WHERE tenant_id = :tenant_id
      AND status IN ('new', 'triaged', 'investigating', 'contained')
      AND (
        (assigned_to_id IS NULL AND owner_agent_run_id IS NULL)
        OR (next_action_due_at IS NOT NULL AND next_action_due_at < now())
      )
    ORDER BY severity DESC, created_at
    LIMIT 50
    """
)

_PENDING_APPROVALS_SQL = text(
    """
    SELECT count(*) FROM agent_approvals
    WHERE tenant_id = :tenant_id AND status = 'pending'
    """
)

_RUNNING_INVESTIGATIONS_SQL = text(
    """
    SELECT count(*) FROM investigation_runs
    WHERE tenant_id = :tenant_id AND status = 'running'
    """
)

_WINDOW_THROUGHPUT_SQL = text(
    """
    SELECT
      count(*) FILTER (WHERE created_at >= :start AND created_at < :end) AS alerts_in,
      count(*) FILTER (WHERE status IN ('resolved', 'closed')
                       AND updated_at >= :start AND updated_at < :end) AS alerts_closed
    FROM alerts
    WHERE tenant_id = :tenant_id
    """
)


async def build_snapshot(db: AsyncSession, tenant_id: uuid.UUID, occurrence: Occurrence) -> dict:
    """The handoff body, from the tenant's real rows, per-section honest."""
    snapshot: dict = {
        "window": {"start": occurrence.start.isoformat(), "end": occurrence.end.isoformat()},
        "generated_from": "live rows at generation time; nothing hand-entered",
    }

    try:
        rows = (await db.execute(_OPEN_ALERTS_SQL, {"tenant_id": str(tenant_id)})).fetchall()
        snapshot["open_alerts_by_severity"] = {str(r[0]): int(r[1]) for r in rows}
    except Exception as exc:  # noqa: BLE001 — a section that cannot answer says so
        snapshot["open_alerts_by_severity"] = {"could_not_check": type(exc).__name__}

    try:
        rows = (await db.execute(_ATTENTION_CASES_SQL, {"tenant_id": str(tenant_id)})).fetchall()
        snapshot["attention_cases"] = [
            {
                "case_number": r[0],
                "title": r[1],
                "severity": r[2],
                "unowned": bool(r[3]),
                "overdue": bool(r[4]),
            }
            for r in rows
        ]
    except Exception as exc:  # noqa: BLE001
        snapshot["attention_cases"] = [{"could_not_check": type(exc).__name__}]

    try:
        count = (await db.execute(_PENDING_APPROVALS_SQL, {"tenant_id": str(tenant_id)})).scalar_one()
        snapshot["pending_approvals"] = int(count)
    except Exception as exc:  # noqa: BLE001
        snapshot["pending_approvals"] = {"could_not_check": type(exc).__name__}

    try:
        count = (await db.execute(_RUNNING_INVESTIGATIONS_SQL, {"tenant_id": str(tenant_id)})).scalar_one()
        snapshot["running_investigations"] = int(count)
    except Exception as exc:  # noqa: BLE001
        snapshot["running_investigations"] = {"could_not_check": type(exc).__name__}

    try:
        row = (
            await db.execute(
                _WINDOW_THROUGHPUT_SQL,
                {"tenant_id": str(tenant_id), "start": occurrence.start, "end": occurrence.end},
            )
        ).fetchone()
        snapshot["this_shift"] = {
            "alerts_in": int(row[0]) if row else 0,
            "alerts_closed": int(row[1]) if row else 0,
            "note": "closed = status moved to resolved/closed inside the window, by updated_at",
        }
    except Exception as exc:  # noqa: BLE001
        snapshot["this_shift"] = {"could_not_check": type(exc).__name__}

    return snapshot


_UPSERT_HANDOFF_SQL = text(
    """
    INSERT INTO shift_handoffs (tenant_id, shift_id, window_start, window_end, snapshot)
    VALUES (:tenant_id, :shift_id, :window_start, :window_end, CAST(:snapshot AS jsonb))
    ON CONFLICT (tenant_id, shift_id, window_start)
    DO NOTHING
    RETURNING id
    """
)

_DUE_SHIFTS_SQL = text(
    """
    SELECT id, tenant_id, timezone, start_minute, end_minute, weekdays
    FROM soc_shifts
    WHERE enabled = TRUE
    """
)


@dataclass
class GenerationSummary:
    generated: int = 0
    skipped_existing: int = 0
    errors: int = 0


async def generate_due_handoffs(db: AsyncSession, *, now: datetime | None = None) -> GenerationSummary:
    """One sweep: for every enabled shift whose occurrence just ended and
    has no handoff yet, snapshot and insert. Idempotent through the unique
    constraint — regeneration is DO NOTHING, never a duplicate."""
    import json

    summary = GenerationSummary()
    shifts = (await db.execute(_DUE_SHIFTS_SQL)).fetchall()
    for shift_id, tenant_id, tz_name, start_minute, end_minute, weekdays in shifts:
        try:
            occurrence = latest_ended_occurrence(
                tz_name=tz_name,
                start_minute=start_minute,
                end_minute=end_minute,
                weekdays=list(weekdays or []),
                now=now,
            )
            if occurrence is None:
                continue
            snapshot = await build_snapshot(db, tenant_id, occurrence)
            inserted = (
                await db.execute(
                    _UPSERT_HANDOFF_SQL,
                    {
                        "tenant_id": str(tenant_id),
                        "shift_id": str(shift_id),
                        "window_start": occurrence.start,
                        "window_end": occurrence.end,
                        "snapshot": json.dumps(snapshot),
                    },
                )
            ).scalar_one_or_none()
            if inserted is None:
                summary.skipped_existing += 1
            else:
                summary.generated += 1
        except Exception as exc:  # noqa: BLE001 — one shift's failure must not stop the fleet
            summary.errors += 1
            logger.warning(
                "shift_handoff.generation_failed shift=%s tenant=%s err=%s",
                shift_id,
                tenant_id,
                type(exc).__name__,
            )
    return summary
