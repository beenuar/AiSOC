"""Departing-employee / insider watchlist: expiry, elevation, lookback.

What existed and what was missing
---------------------------------
`user_risk_profiles` has carried `is_watchlisted` / `watchlist_reason` /
`watchlisted_at` / `watchlisted_by` since migration 014, and the console
PATCH wrote them — and that was the whole feature. Nothing consumed the
flag: no alert was elevated, nothing expired, and no review of the user's
recent activity happened. A watchlist nothing reads is a checkbox, not a
control.

The three halves this module adds:

* **Expiry.** A watchlist row is never indefinite: watchlisting requires
  `expires_at` in the future, and an expired row stops elevating — first
  because the managed-rule rebuild excludes it, and belt-and-braces because
  the sweep worker flips `is_watchlisted` off and rebuilds. Migration 168
  backfills the handful of legacy rows with a 90-day horizon rather than
  letting "no expiry" keep meaning "forever".

* **Elevation through the existing business-context path.** The brief is
  explicit: do not invent a parallel elevation mechanism. Watchlisted
  identities become *managed* business-context rules — a tag rule and a
  severity-floor rule per identity — written to the machine-owned
  ``managed_yaml`` column beside the analyst's verbatim ``yaml_text``
  (same row, same engine, same application point in the auto-triage
  worker). The floor can only raise `info`/`low` to `medium`; a `high` or
  `critical` alert is never touched, because `set_severity` is a fixed
  assignment and a blanket rule would *downgrade* the alerts that matter
  most. The two-column split exists because ``yaml_text`` is the analyst's
  artifact (kept verbatim for round-tripping); a console save must never
  clobber machine rules and a watchlist change must never clobber analyst
  comments.

* **Lookback.** Watchlisting an identity (either door) opens a review
  case over the trailing window: exfil-shaped activity from the lake
  (uploads, shares, forwards, downloads, exports — matched by reviewable
  patterns, counted per event type so the analyst sees exactly what
  matched) plus the identity's recent alerts from Postgres. An
  unreachable lake is reported as *could not check*, never as zero.

Two doors onto the list
-----------------------
Manual (console PATCH, reason + expiry required) and HR-driven: when a
tenant opts in (``insider_watchlist_policies.hr_sync_enabled``, default
off), the sweep watches ``workforce_members`` — the HR store the
connectors service already syncs — for members whose status is
``terminated`` or whose ``end_date`` falls inside the horizon, and
watchlists the matching identity with the HR fact as the reason and
``end_date + grace`` as the expiry. The HR door never shortens or
overwrites a manual row.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.clickhouse import execute_lake_query
from app.models.case import Case
from app.models.insider_threat import InsiderIndicator, UserRiskProfile
from app.services import case_status

logger = logging.getLogger("aisoc.insider_watchlist")

#: The severity floor only ever raises these. `set_severity` is a fixed
#: assignment, so a rule without this guard would downgrade `high` and
#: `critical` alerts — the opposite of elevation.
FLOOR_FROM = ("info", "low")
FLOOR_TO = "medium"

#: Exfil-shaped event types, matched case-insensitively as substrings of
#: `raw_events.action`. Deliberately a reviewable module-level constant:
#: the set is a heuristic, and a heuristic hidden inside SQL is one nobody
#: audits. Counts are grouped per concrete event type so the analyst sees
#: what actually matched, not only that "something" did.
EXFIL_EVENT_PATTERNS: tuple[str, ...] = (
    "%upload%",
    "%download%",
    "%share%",
    "%anonymouslink%",
    "%forward%",
    "%export%",
    "%masscopy%",
)

#: Hard bounds for the lookback window and result size.
MAX_LOOKBACK_DAYS = 90
_LOOKBACK_ROW_LIMIT = 200


# ---------------------------------------------------------------------------
# Managed-rule generation (pure)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WatchEntry:
    """One active watchlisted identity, as the rule generator sees it."""

    ref: str
    reason: str
    expires_at: datetime


def _yaml_quote(value: str) -> str:
    """Single-quote a scalar for YAML (the grammar's values are strings).

    YAML single-quoted style has exactly one escape: a quote doubles.
    Newlines cannot appear in a single-quoted flow scalar, so they are
    flattened to spaces — a watchlist reason is display text, not markup.
    """
    flat = " ".join(str(value).split())
    return "'" + flat.replace("'", "''") + "'"


def managed_rules_yaml(entries: list[WatchEntry]) -> str:
    """Render the managed rule document for the active watchlist.

    Two rules per identity, ids prefixed ``managed-insider-watchlist-`` so
    they are recognisable in the console's diff view and in the applier's
    matched-rule list:

    * a tag rule (every alert for the identity carries
      ``insider-watchlist``, which the triage prompt and routing can read),
    * a severity floor (`info`/`low` → `medium`) that never touches
      `medium` and above.
    """
    if not entries:
        return ""
    lines: list[str] = [
        "# Managed by the insider watchlist — do not edit by hand.",
        "# Regenerated whenever the watchlist changes; expired rows are excluded.",
        "rules:",
    ]
    for n, entry in enumerate(sorted(entries, key=lambda e: e.ref)):
        ref = _yaml_quote(entry.ref)
        desc = _yaml_quote(f"Insider watchlist: {entry.reason} (expires {entry.expires_at.date().isoformat()})")
        lines += [
            f"  - id: managed-insider-watchlist-{n}-tag",
            f"    description: {desc}",
            "    priority: 10",
            "    when:",
            "      field: username",
            "      op: eq",
            f"      value: {ref}",
            "    then:",
            "      tag: insider-watchlist",
            f"  - id: managed-insider-watchlist-{n}-floor",
            f"    description: {desc}",
            "    priority: 11",
            "    when:",
            "      all:",
            "        - field: username",
            "          op: eq",
            f"          value: {ref}",
            "        - field: severity",
            "          op: in",
            f"          value: [{', '.join(FLOOR_FROM)}]",
            "    then:",
            f"      set_severity: {FLOOR_TO}",
        ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Rebuild: watchlist rows -> managed_yaml upsert
# ---------------------------------------------------------------------------

_ACTIVE_WATCHLIST_SQL = text(
    """
    SELECT external_user_ref, watchlist_reason, watchlist_expires_at
    FROM user_risk_profiles
    WHERE tenant_id = :tenant_id
      AND is_watchlisted = TRUE
      AND watchlist_expires_at IS NOT NULL
      AND watchlist_expires_at > :now
      AND external_user_ref IS NOT NULL
      AND external_user_ref != ''
    ORDER BY external_user_ref
    """
)

_UPSERT_MANAGED_YAML_SQL = text(
    """
    INSERT INTO aisoc_business_context_rule_sets (tenant_id, yaml_text, managed_yaml, updated_at)
    VALUES (:tenant_id, '', :managed_yaml, :now)
    ON CONFLICT (tenant_id)
    DO UPDATE SET managed_yaml = EXCLUDED.managed_yaml, updated_at = EXCLUDED.updated_at
    """
)


async def rebuild_managed_rules(db: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Regenerate the tenant's managed rules from the active watchlist.

    Returns the number of identities covered. Expired, cleared and
    ref-less rows are excluded *here*, which is what makes expiry
    effective even before the sweep flips the flag: the applier re-reads
    the row on a short TTL, so a rebuild is the moment elevation stops.
    """
    now = datetime.now(UTC)
    rows = (await db.execute(_ACTIVE_WATCHLIST_SQL, {"tenant_id": str(tenant_id), "now": now})).fetchall()
    entries = [WatchEntry(ref=r[0], reason=r[1] or "watchlisted", expires_at=r[2]) for r in rows]
    await db.execute(
        _UPSERT_MANAGED_YAML_SQL,
        {"tenant_id": str(tenant_id), "managed_yaml": managed_rules_yaml(entries), "now": now},
    )
    return len(entries)


# ---------------------------------------------------------------------------
# The two doors
# ---------------------------------------------------------------------------


class WatchlistValidationError(ValueError):
    """Raised with a message naming exactly which requirement is unmet."""


def validate_watchlist_request(*, reason: str | None, expires_at: datetime | None, now: datetime | None = None) -> None:
    """Watchlisting requires a reason and a future expiry — never indefinite."""
    now = now or datetime.now(UTC)
    if not (reason or "").strip():
        raise WatchlistValidationError("watchlisting requires a reason")
    if expires_at is None:
        raise WatchlistValidationError("watchlisting requires expires_at — a watchlist row is never indefinite")
    if expires_at.tzinfo is None:
        raise WatchlistValidationError("expires_at must be timezone-aware")
    if expires_at <= now:
        raise WatchlistValidationError("expires_at must be in the future")


@dataclass
class WatchlistOutcome:
    profile_id: uuid.UUID
    elevation_active: bool
    #: Populated when elevation could NOT be set up, naming why — an
    #: identity with no `external_user_ref` has nothing for the username
    #: rule to match, and saying so beats silently not elevating.
    elevation_gap: str | None = None
    lookback_case_id: uuid.UUID | None = None


async def apply_watchlist(
    db: AsyncSession,
    profile: UserRiskProfile,
    *,
    reason: str,
    expires_at: datetime,
    source: str,
    actor_id: uuid.UUID | None,
    lookback_days: int = 30,
) -> WatchlistOutcome:
    """Watchlist a profile: set the row, rebuild managed rules, run lookback.

    The lookback runs on the transition onto the list (not on refresh), so
    re-saving a watchlist does not open a duplicate review case.
    """
    validate_watchlist_request(reason=reason, expires_at=expires_at)
    was_watchlisted = bool(profile.is_watchlisted)
    now = datetime.now(UTC)
    profile.is_watchlisted = True
    profile.watchlist_reason = reason
    profile.watchlist_expires_at = expires_at
    profile.watchlist_source = source
    profile.watchlisted_at = now
    if actor_id is not None:
        profile.watchlisted_by = actor_id
    await db.flush()

    tenant_id = profile.tenant_id
    await rebuild_managed_rules(db, tenant_id)

    ref = (profile.external_user_ref or "").strip()
    gap = (
        None
        if ref
        else (
            "no external_user_ref on the profile — the managed username rule has "
            "nothing to match, so alerts for this identity are not elevated"
        )
    )

    case_id: uuid.UUID | None = None
    if not was_watchlisted:
        case_id = await run_lookback(
            db,
            tenant_id=tenant_id,
            profile=profile,
            reason=reason,
            lookback_days=lookback_days,
        )
    return WatchlistOutcome(
        profile_id=profile.id,
        elevation_active=bool(ref),
        elevation_gap=gap,
        lookback_case_id=case_id,
    )


async def clear_watchlist(db: AsyncSession, profile: UserRiskProfile) -> None:
    """Take a profile off the list and withdraw its managed rules."""
    profile.is_watchlisted = False
    profile.watchlist_expires_at = None
    await db.flush()
    await rebuild_managed_rules(db, profile.tenant_id)


# ---------------------------------------------------------------------------
# Lookback: the review case
# ---------------------------------------------------------------------------

_LOOKBACK_LAKE_SQL = """
    SELECT action, connector_type, count() AS events,
           min(event_time) AS first_seen, max(event_time) AS last_seen
    FROM aisoc.raw_events
    WHERE tenant_id = %(tenant_id)s
      AND event_time >= %(window_start)s
      AND lower(user_name) = %(ref)s
      AND multiSearchAnyCaseInsensitive(action, %(patterns)s)
    GROUP BY action, connector_type
    ORDER BY events DESC
    LIMIT %(limit)s
"""

_LOOKBACK_ALERTS_SQL = text(
    """
    SELECT count(*) FROM alerts
    WHERE tenant_id = :tenant_id
      AND created_at >= :window_start
      AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(coalesce(affected_users, '[]'::jsonb)) AS u(name)
        WHERE lower(u.name) = :ref
      )
    """
)


async def run_lookback(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    profile: UserRiskProfile,
    reason: str,
    lookback_days: int,
) -> uuid.UUID | None:
    """Open the departing-employee review case from real rows.

    Two sources, each reported honestly:

    * the lake — exfil-shaped event counts per concrete event type; an
      unreachable lake is recorded as ``could_not_check`` with the error
      class named, never as zero;
    * the alerts table — how many alerts already name this identity in
      the window.

    The case is opened even when both sources are quiet: the point of the
    watchlist is that a human reviews the departure, and "nothing matched
    in the window we could see" is a reviewable statement.
    """
    days = max(1, min(int(lookback_days), MAX_LOOKBACK_DAYS))
    window_start = datetime.now(UTC) - timedelta(days=days)
    ref = (profile.external_user_ref or "").strip().lower()

    lake_rows: list[tuple] = []
    could_not_check: list[str] = []
    if not ref:
        could_not_check.append("lake: no external_user_ref to match on")
        could_not_check.append("alerts: no external_user_ref to match on")
    else:
        try:
            result = await execute_lake_query(
                _LOOKBACK_LAKE_SQL,
                params={
                    "tenant_id": str(tenant_id),
                    "window_start": window_start,
                    "ref": ref,
                    "patterns": [p.strip("%") for p in EXFIL_EVENT_PATTERNS],
                    "limit": _LOOKBACK_ROW_LIMIT,
                },
            )
            lake_rows = [tuple(r) for r in result.rows]
        except Exception as exc:  # noqa: BLE001 — an unreachable lake is not an empty one
            logger.warning(
                "insider_watchlist.lookback_lake_unavailable tenant=%s error=%s",
                tenant_id,
                type(exc).__name__,
            )
            could_not_check.append(f"lake: could not be queried ({type(exc).__name__}) — activity is unknown, not zero")

    alert_count: int | None = None
    if ref:
        try:
            alert_count = (
                await db.execute(
                    _LOOKBACK_ALERTS_SQL,
                    {"tenant_id": str(tenant_id), "window_start": window_start, "ref": ref},
                )
            ).scalar_one()
        except Exception as exc:  # noqa: BLE001 — a failed count is unknown, not zero
            logger.warning(
                "insider_watchlist.lookback_alerts_failed tenant=%s error=%s",
                tenant_id,
                type(exc).__name__,
            )
            could_not_check.append(f"alerts: count failed ({type(exc).__name__})")

    display = profile.external_user_ref or str(profile.id)
    summary_lines = [
        f"Departing-employee review for {display!r} — {reason}.",
        f"Lookback window: last {days} day(s).",
        "",
    ]
    if lake_rows:
        summary_lines.append("Exfil-shaped activity in the lake (per event type):")
        for event_type, connector_type, events, first_seen, last_seen in lake_rows[:25]:
            summary_lines.append(f"- {event_type} via {connector_type}: {events} event(s), {first_seen} → {last_seen}")
    elif ref and not any(c.startswith("lake:") for c in could_not_check):
        summary_lines.append(
            "Exfil-shaped activity in the lake: none matched the reviewed patterns "
            f"({', '.join(p.strip('%') for p in EXFIL_EVENT_PATTERNS)}) in the window."
        )
    summary_lines.append(
        f"Alerts naming this identity in the window: {alert_count}"
        if alert_count is not None
        else "Alerts naming this identity in the window: not measured"
    )
    for item in could_not_check:
        summary_lines.append(f"Could not check — {item}")

    case = Case(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        case_number=f"INSIDER-{uuid.uuid4().hex[:8].upper()}",
        title=f"Departing-employee review: {display}",
        description="\n".join(summary_lines),
        case_type="insider_review",
        priority="medium",
        severity="medium",
        status=case_status.NEW,
        tags=["insider-watchlist", f"profile:{profile.id}"],
    )
    db.add(case)
    await db.flush()

    db.add(
        InsiderIndicator(
            tenant_id=tenant_id,
            profile_id=profile.id,
            indicator_type="departure_lookback",
            severity="medium",
            description=f"Lookback over {days} day(s) at watchlisting; see case {case.case_number}.",
            evidence={
                "window_days": days,
                "lake_event_types": [{"event_type": r[0], "connector_type": r[1], "events": int(r[2])} for r in lake_rows],
                "alerts_in_window": alert_count,
                "could_not_check": could_not_check,
                "patterns": list(EXFIL_EVENT_PATTERNS),
                "case_id": str(case.id),
            },
        )
    )
    await db.flush()
    return case.id


# ---------------------------------------------------------------------------
# Sweep: expiry + the HR door
# ---------------------------------------------------------------------------

_EXPIRE_SQL = text(
    """
    UPDATE user_risk_profiles
    SET is_watchlisted = FALSE
    WHERE is_watchlisted = TRUE
      AND watchlist_expires_at IS NOT NULL
      AND watchlist_expires_at <= :now
    RETURNING tenant_id
    """
)

_HR_TENANTS_SQL = text(
    """
    SELECT tenant_id, hr_grace_days, default_expiry_days, lookback_days
    FROM insider_watchlist_policies
    WHERE hr_sync_enabled = TRUE
    """
)

_HR_DEPARTING_SQL = text(
    """
    SELECT external_id, email, display_name, status, end_date
    FROM workforce_members
    WHERE tenant_id = :tenant_id
      AND (
        status = 'terminated'
        OR (end_date IS NOT NULL AND end_date <= :horizon)
      )
      AND email IS NOT NULL AND email != ''
    """
)

_PROFILE_BY_REF_SQL = text(
    """
    SELECT id FROM user_risk_profiles
    WHERE tenant_id = :tenant_id AND lower(external_user_ref) = :ref
    LIMIT 1
    """
)

#: How far ahead of a known last day the HR door starts watching.
HR_HORIZON_DAYS = 30


@dataclass
class SweepSummary:
    expired: int = 0
    hr_watchlisted: int = 0
    tenants_rebuilt: int = 0
    hr_tenants: int = 0
    errors: list[str] = field(default_factory=list)


async def sweep_expired(db: AsyncSession) -> SweepSummary:
    """Flip expired rows off the list and rebuild each affected tenant."""
    summary = SweepSummary()
    now = datetime.now(UTC)
    rows = (await db.execute(_EXPIRE_SQL, {"now": now})).fetchall()
    summary.expired = len(rows)
    for tenant_id in {r[0] for r in rows}:
        await rebuild_managed_rules(db, tenant_id)
        summary.tenants_rebuilt += 1
    return summary


async def sweep_hr(db: AsyncSession) -> SweepSummary:
    """The HR door: watchlist departing workforce members, per opted-in tenant.

    Idempotent: an identity already on the list (either source) is left
    exactly as it is — in particular the HR door never shortens a manual
    expiry. The reason names the HR fact; the expiry is the member's last
    day plus the tenant's grace, or now plus grace when HR has a
    termination status with no date.
    """
    summary = SweepSummary()
    tenants = (await db.execute(_HR_TENANTS_SQL)).fetchall()
    summary.hr_tenants = len(tenants)
    now = datetime.now(UTC)
    for tenant_id, grace_days, _default_days, lookback_days in tenants:
        horizon: date = (now + timedelta(days=HR_HORIZON_DAYS)).date()
        try:
            members = (await db.execute(_HR_DEPARTING_SQL, {"tenant_id": str(tenant_id), "horizon": horizon})).fetchall()
        except Exception as exc:  # noqa: BLE001 — a tenant without the HR table synced
            summary.errors.append(f"{tenant_id}: workforce query failed ({type(exc).__name__})")
            continue
        for _external_id, email, display_name, status, end_date in members:
            ref = email.strip().lower()
            existing_id = (await db.execute(_PROFILE_BY_REF_SQL, {"tenant_id": str(tenant_id), "ref": ref})).scalar_one_or_none()
            profile: UserRiskProfile | None = None
            if existing_id is not None:
                profile = await db.get(UserRiskProfile, existing_id)
            if profile is not None and profile.is_watchlisted:
                continue  # already listed — never overwrite, never shorten
            if profile is None:
                profile = UserRiskProfile(
                    tenant_id=tenant_id,
                    external_user_ref=email.strip(),
                )
                db.add(profile)
                await db.flush()
            last_day = end_date or now.date()
            expires = datetime(last_day.year, last_day.month, last_day.day, tzinfo=UTC) + timedelta(days=max(int(grace_days), 1))
            if expires <= now:
                expires = now + timedelta(days=max(int(grace_days), 1))
            reason = f"HR: {display_name or email} status {status!r}, last day {end_date.isoformat() if end_date else 'unknown'}"
            await apply_watchlist(
                db,
                profile,
                reason=reason,
                expires_at=expires,
                source="hr_sync",
                actor_id=None,
                lookback_days=int(lookback_days),
            )
            summary.hr_watchlisted += 1
    return summary
