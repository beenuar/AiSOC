"""Turn one published indicator into at most one alert per tenant.

Gap-closure Phase 8.1.

This is the module the phase's noise budget lives in. A feed publishes
thousands of indicators a day; each one asks a question of every opted-in
tenant's month of history. Without the three controls below that is a machine
for generating alerts nobody reads, which is the failure mode an AI SOC is
supposed to remove rather than add to.

**Budget, checked before the work.** :func:`_consume_budget` is the first
thing that runs, so an exhausted tenant costs one small UPDATE rather than a
warehouse scan. It counts a sweep rather than an alert, because the cost is in
the sweeping: a tenant with no matches at all still paid for the query.

**Dedup, enforced twice, in different places.** ``retro_hunt_sightings`` has a
UNIQUE constraint on (tenant, type, value), so the second sweep that finds the
same indicator updates a row instead of opening an alert. The alert insert
additionally carries an ``idempotency_key`` that the ``alerts`` table has a
per-tenant partial unique index on, so even a bug in this module's
branching cannot produce a duplicate row. One of those is the mechanism and
the other is the seatbelt, and it is worth being explicit about which is
which: the sightings row is what stops the alert being *attempted*, and the
index is what stops it *landing*.

**Aggregation, in the query.** The sweep returns one row whatever the match
count. See :mod:`app.services.retro_hunt.sweep`.

The provenance an alert carries is the plan's list and one addition. The feed,
when the feed first saw the indicator, and where it matched are required.
``intel_first_seen_at`` and ``first_sighting_at`` are kept as separate facts
rather than collapsed into "first seen", because an indicator published this
morning and last seen in the tenant's estate five weeks ago is a materially
different finding from one published and seen the same day, and a single
field would make those read identically.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.retro_hunt import RetroHuntSettings, RetroHuntSighting
from app.services.agent_tools.indicators import IndicatorTypeError
from app.services.retro_hunt.sweep import (
    DEFAULT_LOOKBACK_DAYS,
    SweepOutcome,
    sweep_indicator,
)

logger = logging.getLogger(__name__)

#: Severity a retro-hunt alert opens at.
#:
#: Deliberately not `critical`. A match means an indicator somebody published
#: appears somewhere in this tenant's recorded history, which is a strong
#: reason to look and not on its own a reason to page: public feeds carry
#: sinkholes, shared CDN addresses and hashes of files that are malicious in
#: one context and ordinary in another. Overstating it is how a feature like
#: this gets muted in week two, and a muted alert is worth less than no alert.
DEFAULT_SEVERITY = "medium"

#: Alert category, matching the vocabulary the console already filters on.
ALERT_CATEGORY = "threat-intel"


@dataclass(frozen=True)
class IntelIndicator:
    """One indicator lifted out of a ``NEW_IOC`` event.

    Deliberately a small typed record rather than the raw payload dict. The
    payload comes off a Kafka topic fed by third-party feeds, so every field
    is untrusted, and narrowing it here means the rest of the module cannot
    accidentally reach a key nobody validated.
    """

    indicator_type: str
    value: str
    feed_source: str
    first_seen_at: datetime | None = None
    description: str = ""


@dataclass
class TenantSweepReport:
    """What happened for one tenant and one indicator."""

    tenant_id: uuid.UUID
    #: One of: swept, skipped_disabled, skipped_budget, skipped_unsupported, failed.
    outcome: str
    matched: bool = False
    alert_id: uuid.UUID | None = None
    deduplicated: bool = False
    detail: str = ""


def alert_idempotency_key(indicator_type: str, value: str) -> str:
    """A stable per-tenant key for the alert this indicator would open.

    Hashed rather than embedded because an indicator value can be a 2 KB URL
    or an attacker-chosen hostname, and the column is 128 characters. The
    prefix keeps retro-hunt keys legible in the table and prevents a collision
    with the CLI submit path that also uses this column.
    """
    digest = hashlib.sha256(f"{indicator_type}:{value}".encode()).hexdigest()
    return f"retro-hunt:{indicator_type}:{digest[:32]}"


def _window_reset(anchor: datetime, now: datetime, span: timedelta) -> bool:
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=UTC)
    return now - anchor >= span


async def _consume_budget(
    db: AsyncSession,
    settings_row: RetroHuntSettings,
    *,
    now: datetime,
) -> bool:
    """Spend one sweep from this tenant's budget, or refuse.

    Rolling windows are reset lazily on read rather than by a scheduled job:
    a tenant whose feed went quiet for a day should get a full budget on the
    next indicator, and nothing needs to have been running in between for
    that to be true.
    """
    if _window_reset(settings_row.hour_started_at, now, timedelta(hours=1)):
        settings_row.sweeps_this_hour = 0
        settings_row.hour_started_at = now
    if _window_reset(settings_row.day_started_at, now, timedelta(days=1)):
        settings_row.sweeps_today = 0
        settings_row.day_started_at = now

    if settings_row.sweeps_this_hour >= settings_row.max_sweeps_per_hour:
        settings_row.sweeps_skipped_budget += 1
        settings_row.updated_at = now
        return False
    if settings_row.sweeps_today >= settings_row.max_sweeps_per_day:
        settings_row.sweeps_skipped_budget += 1
        settings_row.updated_at = now
        return False

    settings_row.sweeps_this_hour += 1
    settings_row.sweeps_today += 1
    settings_row.updated_at = now
    return True


def _matched_surfaces(outcome: SweepOutcome) -> list[dict[str, Any]]:
    """Where the indicator matched, as the alert and the ledger record it."""
    surfaces: list[dict[str, Any]] = []
    if outcome.lake.matched:
        surfaces.append(
            {
                "surface": "event_lake",
                "sightings": outcome.lake.sightings,
                "columns": list(outcome.lake.columns_searched),
                "connector_types": outcome.lake.connector_types,
                "hosts": outcome.lake.hosts,
                "users": outcome.lake.users,
            }
        )
    if outcome.federated.matched:
        surfaces.append(
            {
                "surface": "federated_siem",
                "sightings": outcome.federated.sightings,
                "sources": outcome.federated.sources_ok,
            }
        )
    return surfaces


def _build_description(indicator: IntelIndicator, outcome: SweepOutcome) -> str:
    """The provenance block, written so a reader can act without pivoting.

    Three questions in order: what was published and by whom, what we found,
    and what we could not check. The third is last but never omitted, because
    a retro-hunt that swept one of two sources and says nothing about the
    other is claiming coverage it does not have.
    """
    lines = [
        f"A retro-hunt matched a {indicator.indicator_type} published by {indicator.feed_source}.",
        "",
        "Intelligence provenance",
        f"  Feed: {indicator.feed_source}",
        f"  Indicator: {indicator.indicator_type} {indicator.value}",
    ]
    if indicator.first_seen_at:
        lines.append(f"  First seen by the feed: {indicator.first_seen_at.isoformat()}")
    else:
        lines.append("  First seen by the feed: not published by this feed")
    if indicator.description:
        lines.append(f"  Feed description: {indicator.description}")

    lines += ["", "Where it matched", f"  Lookback window: {outcome.lookback_days} days"]
    if outcome.lake.matched:
        lines.append(f"  Event lake: {outcome.lake.sightings} sighting(s) in columns {', '.join(outcome.lake.columns_searched)}")
        if outcome.lake.first_sighting_at:
            lines.append(f"    First sighting in your data: {outcome.lake.first_sighting_at}")
            lines.append(f"    Most recent sighting: {outcome.lake.last_sighting_at}")
        if outcome.lake.connector_types:
            lines.append(f"    Sources: {', '.join(outcome.lake.connector_types)}")
        if outcome.lake.hosts:
            lines.append(f"    Hosts: {', '.join(outcome.lake.hosts)}")
        if outcome.lake.users:
            lines.append(f"    Users: {', '.join(outcome.lake.users)}")
    if outcome.federated.matched:
        lines.append(f"  Connected SIEMs: {outcome.federated.sightings} matching row(s) from {', '.join(outcome.federated.sources_ok)}")

    gaps = outcome.gaps
    if gaps:
        lines += ["", "What was NOT checked"]
        lines += [f"  {gap}" for gap in gaps]
        lines.append("  A gap is not evidence of absence. These surfaces were not searched.")

    return "\n".join(lines)


async def _open_alert(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    indicator: IntelIndicator,
    outcome: SweepOutcome,
) -> Alert:
    """Open the one alert this indicator gets for this tenant."""
    now = datetime.now(UTC)
    event_time = outcome.lake.last_sighting_at or now
    if isinstance(event_time, datetime) and event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=UTC)

    alert = Alert(
        tenant_id=tenant_id,
        title=f"Retro-hunt: {indicator.indicator_type} {indicator.value} seen in your history",
        description=_build_description(indicator, outcome),
        severity=DEFAULT_SEVERITY,
        status="new",
        category=ALERT_CATEGORY,
        connector_type="retro-hunt",
        rule_id=f"retro-hunt:{indicator.indicator_type}",
        rule_name=f"Threat-intel retro-hunt ({indicator.feed_source})",
        entities=[{"type": indicator.indicator_type, "value": indicator.value}],
        raw_event={
            "retro_hunt": {
                "feed_source": indicator.feed_source,
                "indicator_type": indicator.indicator_type,
                "indicator_value": indicator.value,
                "intel_first_seen_at": (indicator.first_seen_at.isoformat() if indicator.first_seen_at else None),
                "lookback_days": outcome.lookback_days,
                "total_sightings": outcome.total_sightings,
                "matched_surfaces": _matched_surfaces(outcome),
                "not_checked": outcome.gaps,
            }
        },
        tags=["retro-hunt", f"feed:{indicator.feed_source}"],
        idempotency_key=alert_idempotency_key(indicator.indicator_type, indicator.value),
        event_time=event_time,
        first_seen=outcome.lake.first_sighting_at or now,
        last_seen=event_time,
    )
    db.add(alert)
    await db.flush()
    return alert


async def sweep_tenant(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    indicator: IntelIndicator,
    settings_row: RetroHuntSettings | None = None,
    now: datetime | None = None,
) -> TenantSweepReport:
    """Sweep one tenant for one indicator and open at most one alert.

    The caller is responsible for the transaction. Nothing here commits, so a
    batch of tenants can be swept and committed together, and a failure on one
    tenant does not half-write another.
    """
    now = now or datetime.now(UTC)

    if settings_row is None:
        settings_row = await db.get(RetroHuntSettings, tenant_id)
    if settings_row is None or not settings_row.enabled:
        return TenantSweepReport(
            tenant_id=tenant_id,
            outcome="skipped_disabled",
            detail="This tenant has not opted in to retro-hunts.",
        )

    if not await _consume_budget(db, settings_row, now=now):
        logger.info("retro_hunt.budget_exhausted tenant=%s", tenant_id)
        return TenantSweepReport(
            tenant_id=tenant_id,
            outcome="skipped_budget",
            detail=("The tenant's retro-hunt budget for this window is spent, so the sweep did not run. This is not a result."),
        )

    try:
        outcome = await sweep_indicator(
            db,
            tenant_id=tenant_id,
            indicator_type=indicator.indicator_type,
            value=indicator.value,
            lookback_days=settings_row.lookback_days or DEFAULT_LOOKBACK_DAYS,
            include_federated=settings_row.include_federated,
        )
    except IndicatorTypeError as exc:
        # The feed published a value that is not the type it claims. Surfaced
        # as its own outcome rather than as "no match", because it is a
        # data-quality problem an operator can fix and a silent zero hides it.
        logger.info(
            "retro_hunt.indicator_refused tenant=%s type=%s reason=%s",
            tenant_id,
            str(indicator.indicator_type).replace("\r", "").replace("\n", " ")[:32],
            str(exc).replace("\r", "").replace("\n", " ")[:160],
        )
        return TenantSweepReport(
            tenant_id=tenant_id,
            outcome="skipped_unsupported",
            detail=str(exc),
        )

    if not outcome.matched:
        return TenantSweepReport(
            tenant_id=tenant_id,
            outcome="swept",
            matched=False,
            detail="; ".join(outcome.gaps) if outcome.gaps else "No sightings in the lookback window.",
        )

    existing = (
        await db.execute(
            select(RetroHuntSighting).where(
                RetroHuntSighting.tenant_id == tenant_id,
                RetroHuntSighting.indicator_type == indicator.indicator_type,
                RetroHuntSighting.indicator_value == indicator.value,
            )
        )
    ).scalar_one_or_none()

    surfaces = _matched_surfaces(outcome)

    if existing is not None:
        # Already known. Refresh what we learned and open nothing: this is the
        # branch that keeps a daily-republished indicator from becoming a
        # daily alert.
        existing.last_matched_at = now
        existing.sightings = outcome.total_sightings
        existing.last_sighting_at = outcome.lake.last_sighting_at
        existing.matched_surfaces = surfaces
        existing.times_seen += 1
        existing.updated_at = now
        return TenantSweepReport(
            tenant_id=tenant_id,
            outcome="swept",
            matched=True,
            alert_id=existing.alert_id,
            deduplicated=True,
            detail=(
                f"Already alerted on this indicator for this tenant "
                f"({existing.times_seen} sweeps have now matched it); no new alert opened."
            ),
        )

    alert = await _open_alert(db, tenant_id=tenant_id, indicator=indicator, outcome=outcome)
    db.add(
        RetroHuntSighting(
            tenant_id=tenant_id,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            feed_source=indicator.feed_source,
            intel_first_seen_at=indicator.first_seen_at,
            first_matched_at=now,
            last_matched_at=now,
            first_sighting_at=outcome.lake.first_sighting_at,
            last_sighting_at=outcome.lake.last_sighting_at,
            sightings=outcome.total_sightings,
            matched_surfaces=surfaces,
            alert_id=alert.id,
            times_seen=1,
            created_at=now,
            updated_at=now,
        )
    )
    logger.info(
        "retro_hunt.alert_opened tenant=%s type=%s sightings=%d",
        tenant_id,
        str(indicator.indicator_type).replace("\r", "").replace("\n", " ")[:32],
        outcome.total_sightings,
    )
    return TenantSweepReport(
        tenant_id=tenant_id,
        outcome="swept",
        matched=True,
        alert_id=alert.id,
        detail=f"Opened one alert for {outcome.total_sightings} sighting(s).",
    )


async def opted_in_tenants(db: AsyncSession) -> list[RetroHuntSettings]:
    """Every tenant that has asked for retro-hunts.

    Read on an unbound (cross-tenant) session by the consumer, which then
    binds each tenant before writing. Same shape as the hunt scheduler's
    sweep, and for the same reason: the read is genuinely cross-tenant and
    every write after it is not.
    """
    rows = (await db.execute(select(RetroHuntSettings).where(RetroHuntSettings.enabled.is_(True)))).scalars().all()
    return list(rows)


__all__ = [
    "ALERT_CATEGORY",
    "DEFAULT_SEVERITY",
    "IntelIndicator",
    "TenantSweepReport",
    "alert_idempotency_key",
    "opted_in_tenants",
    "sweep_tenant",
]
