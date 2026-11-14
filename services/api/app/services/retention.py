"""Configurable data-retention policies (Wave 5, W5.1).

Per-tenant retention windows for each data class, plus the bounded, tenant-
scoped purge SQL that enforces them. Pure functions — the scheduler/worker that
runs the purge composes these; the API exposes get/set. Bounds keep a
misconfiguration (0 days / 100 years) from nuking or never-purging data.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import text

from app.services import governance

MIN_DAYS = 1
MAX_DAYS = 3650  # 10 years

#: The longest lake window a tenant may choose, and the number the lake's
#: own `TTL` must not delete before.
#:
#: Separate from ``MAX_DAYS`` because the two bound different stores. Alerts
#: and audit rows live in Postgres and are small; raw events live in
#: ClickHouse and are the expensive ones, so the ceiling that decides how
#: much disk a deployment can be asked to hold is stated on its own rather
#: than inherited from a cap meant for a different table.
#:
#: Raising it is two edits that must land together, which is why they are
#: named here: this constant, and the `MODIFY TTL` migration in
#: ``app/db/lake_migrations.py``. Changing one alone either lets a tenant
#: choose a window ClickHouse will not honour, or holds rows nobody asked
#: for. ``scripts/check_retention_window.py`` fails when they disagree.
MAX_LAKE_DAYS = 400

# Data classes we retain, with sane defaults (days).
DEFAULT_RETENTION: dict[str, int] = {
    "raw_events": 90,  # ClickHouse lake
    "alerts": 365,  # Postgres alerts
    "audit": 730,  # audit/ledger — longer for compliance
}


@dataclass(frozen=True)
class RetentionPolicy:
    raw_events_days: int = DEFAULT_RETENTION["raw_events"]
    alerts_days: int = DEFAULT_RETENTION["alerts"]
    audit_days: int = DEFAULT_RETENTION["audit"]

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def _clamp(value: int, ceiling: int = MAX_DAYS) -> int:
    return max(MIN_DAYS, min(ceiling, int(value)))


def resolve_policy(config: dict[str, int] | None) -> RetentionPolicy:
    """Merge a tenant's stored config over defaults, clamped to safe bounds."""
    cfg = dict(config or {})
    return RetentionPolicy(
        raw_events_days=_clamp(cfg.get("raw_events_days", DEFAULT_RETENTION["raw_events"]), MAX_LAKE_DAYS),
        alerts_days=_clamp(cfg.get("alerts_days", DEFAULT_RETENTION["alerts"])),
        audit_days=_clamp(cfg.get("audit_days", DEFAULT_RETENTION["audit"])),
    )


def build_lake_purge_sql(tenant_id: uuid.UUID, days: int) -> str:
    """Tenant-scoped ClickHouse purge of lake events older than ``days``.

    Uses a lightweight ``ALTER TABLE … DELETE`` (ClickHouse mutation). The
    tenant predicate is mandatory so a purge can never cross tenants; the day
    count is clamped and interpolated as an integer literal (never string)."""
    days = _clamp(days, MAX_LAKE_DAYS)
    tid = str(tenant_id)
    # tenant_id is a UUID (validated by type); days is an int literal.
    return f"ALTER TABLE aisoc.raw_events DELETE WHERE tenant_id = '{tid}' AND event_time < now() - INTERVAL {days} DAY"


async def alerts_under_legal_hold(db: Any, tenant_id: uuid.UUID) -> list[governance.LegalHold]:
    """Live legal holds for this tenant, which outrank the purge.

    Read before every purge rather than cached: a hold placed between
    two runs of the worker must take effect on the next one, and a
    cache measured in hours is a cache that deletes evidence placed
    under hold this morning.
    """
    rows = await db.execute(
        text("""
            SELECT id, subject_kind, subject_value, matter_ref
              FROM legal_holds
             WHERE tenant_id = CAST(:t AS uuid) AND released_at IS NULL
        """).bindparams(t=str(tenant_id))
    )
    return [governance.LegalHold(id=str(r[0]), subject_kind=str(r[1]), subject_value=str(r[2]), matter_ref=r[3]) for r in rows.all()]


def may_purge(
    *,
    expired: bool,
    subjects: dict[str, str],
    holds: list[governance.LegalHold],
) -> governance.RetentionDecision:
    """Whether retention may remove this record.

    Delegates to `governance.retention_decision` rather than
    re-implementing the comparison, so there is one place where a hold
    can beat a purge — and it returns the decision object, not a
    boolean, so a caller cannot treat "held" as "not expired".
    """
    return governance.retention_decision(expired=expired, subjects=subjects, holds=holds)


def build_alert_purge_sql(days: int) -> tuple[str, dict[str, int]]:
    """Postgres purge of alerts older than ``days`` (RLS scopes the tenant).

    Returns parameterised SQL + params — never string-interpolate the cutoff."""
    days = _clamp(days)
    sql = "DELETE FROM alerts WHERE created_at < now() - make_interval(days => :days)"
    return sql, {"days": days}
