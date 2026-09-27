"""Sweep one tenant's recorded history for one indicator.

Gap-closure Phase 8.1.

A retro-hunt is somebody else's intelligence pointed at a customer's own
past. That shape makes it expensive by construction: a feed publishes
thousands of indicators a day, each one asks a question of thirty days of a
tenant's telemetry, and the question arrives on a schedule nobody in the SOC
chose. Every design decision here is about the two ways that goes wrong.

**It must not become a row firehose.** The query below is an aggregate, not a
selection. It returns exactly one row whatever the match count is: how many
sightings, when the first and last were, and bounded sets of the hosts, users
and connectors involved. An indicator that appears in a million events and an
indicator that appears in one produce the same amount of work above this
layer and the same amount of context in an alert. There is no code path here
that returns a row per match, so the "one IOC, a thousand alerts" failure is
not something callers have to remember to avoid.

**It must not become a warehouse denial of service.** ClickHouse is the only
thing that can actually stop a runaway scan, so the budget is expressed in
its own settings rather than as an intention on this side: a bytes-to-read
ceiling and an execution-time ceiling travel with every query. A sweep that
exceeds them fails as a sweep that could not be completed, which is reported
as such and never as zero sightings.

**Tenant scoping is structural.** The predicate is part of the generated
WHERE clause and its value is bound as a query parameter, following
``app.services.lake_hunt`` rather than ``app.services.lake_sql``. That is
deliberate and the reasoning is recorded in both: ``rewrite_for_tenant``
exists to constrain SQL an *operator* wrote, and handing it platform-authored
SQL is how every fresh tenant once came to see the same global figures on the
funnel. :func:`build_sweep_sql` additionally refuses to return a statement
that does not carry its own tenant predicate, so the guarantee does not rest
on a reviewer noticing.

**The lake is not the whole estate.** A tenant with a SIEM has years of data
AiSOC never ingested, so a sweep also goes through the Phase 4 federated
search. The three outcomes that module keeps apart are kept apart here too: a
source that answered and found nothing, a source that could not be checked,
and a source with no field mapping for this indicator type are different
facts, and a sweep that collapses them reports "you were not exposed" on
evidence nobody gathered.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.clickhouse import (
    LakeQueryError,
    LakeQueryNotConfiguredError,
    LakeQueryTimeoutError,
    execute_lake_query,
)
from app.services.agent_tools import siem_search
from app.services.agent_tools.indicators import IndicatorTypeError, validate_value
from app.services.retro_hunt.ioc_fields import UnmappedIndicator, mapping_for
from app.services.retro_hunt.sql import build_sweep_sql

logger = logging.getLogger(__name__)

#: Default history a sweep looks back over, in days. The plan's default.
DEFAULT_LOOKBACK_DAYS = 30

#: Hard ceiling on the lookback regardless of what a tenant configures. A
#: sweep is a scheduled background cost paid by every new indicator, so an
#: unbounded window is a way to make the warehouse unusable by writing a
#: number into a settings row.
MAX_LOOKBACK_DAYS = 365

#: Bytes ClickHouse may read for one sweep before it refuses. This is the
#: budget, and it is here rather than in a comment because only the server
#: can enforce it. Chosen so a bloom-indexed needle over a month of a
#: mid-sized tenant completes comfortably while a full scan of a large
#: tenant's ZSTD blobs does not.
MAX_BYTES_PER_SWEEP = 8 * 1024 * 1024 * 1024

#: Wall-clock ceiling for one sweep, in seconds. Shorter than the lake API's
#: default because a sweep runs unattended on a queue: a slow one delays every
#: indicator behind it, and there is no human waiting who would rather wait
#: than get an answer.
SWEEP_TIMEOUT_SECONDS = 20.0


class SweepBudgetExceeded(RuntimeError):
    """The warehouse refused the sweep on cost. Never a zero-sighting result."""


@dataclass
class LakeSweepResult:
    """What the lake said about one indicator, or why it could not say."""

    indicator_type: str
    value: str
    #: False when the lake could not be asked at all. A caller must not read
    #: ``sightings == 0`` without checking this first, which is why the count
    #: is not an Optional that could be treated as falsy.
    checked: bool
    sightings: int = 0
    first_sighting_at: Any | None = None
    last_sighting_at: Any | None = None
    connector_types: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    columns_searched: tuple[str, ...] = ()
    #: Set when ``checked`` is False. Names what stopped the sweep in terms an
    #: operator can act on.
    unavailable_reason: str | None = None

    @property
    def matched(self) -> bool:
        return self.checked and self.sightings > 0


@dataclass
class FederatedSweepResult:
    """What the tenant's own SIEMs said, keeping the three outcomes apart."""

    checked: bool
    sightings: int = 0
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)
    sources_unmapped: list[str] = field(default_factory=list)
    unavailable_reason: str | None = None

    @property
    def matched(self) -> bool:
        return self.checked and self.sightings > 0


@dataclass
class SweepOutcome:
    """The whole answer for one indicator against one tenant."""

    indicator_type: str
    value: str
    lookback_days: int
    lake: LakeSweepResult
    federated: FederatedSweepResult

    @property
    def matched(self) -> bool:
        return self.lake.matched or self.federated.matched

    @property
    def total_sightings(self) -> int:
        return self.lake.sightings + self.federated.sightings

    @property
    def gaps(self) -> list[str]:
        """Everything that was not checked, in words an alert can carry.

        Present on a matching sweep as well as a non-matching one: an
        indicator found in the lake while the SIEM sweep failed is a
        different finding from one found in both.
        """
        out: list[str] = []
        if not self.lake.checked and self.lake.unavailable_reason:
            out.append(f"Event lake: {self.lake.unavailable_reason}")
        if not self.federated.checked and self.federated.unavailable_reason:
            out.append(f"Federated SIEM search: {self.federated.unavailable_reason}")
        for source in self.federated.sources_failed:
            out.append(f"SIEM source {source} could not be searched, so it was NOT checked.")
        for source in self.federated.sources_unmapped:
            out.append(f"SIEM source {source} has no field mapping for a {self.indicator_type}, so it was NOT checked.")
        return out


async def sweep_lake(
    *,
    tenant_id: uuid.UUID,
    indicator_type: str,
    value: str,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
) -> LakeSweepResult:
    """Ask the event lake whether it has seen one indicator.

    Never raises for an operational failure. The lake being unreachable, the
    budget being exceeded and the indicator type having no lake column are all
    returned as ``checked=False`` with a reason, because the caller's next step
    is to record a visibility gap rather than to stop.
    """
    window = max(1, min(int(lookback_days), MAX_LOOKBACK_DAYS))
    mapping = mapping_for(indicator_type)

    if mapping is None:
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            unavailable_reason=f"{indicator_type!r} is not an indicator type AiSOC knows how to sweep.",
        )
    if isinstance(mapping, UnmappedIndicator):
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            unavailable_reason=mapping.reason,
        )

    sql, columns = build_sweep_sql(mapping)
    params = {"tenant_id": str(tenant_id), "lookback_days": window, "needle": value}

    try:
        result = await execute_lake_query(
            sql,
            params=params,
            timeout_seconds=SWEEP_TIMEOUT_SECONDS,
            extra_settings={
                # The budget. `max_bytes_to_read` is what makes an
                # unselective sweep fail instead of reading the partition.
                "max_bytes_to_read": MAX_BYTES_PER_SWEEP,
                "max_result_rows": 1,
            },
        )
    except LakeQueryNotConfiguredError:
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            columns_searched=columns,
            unavailable_reason="No event lake is configured on this deployment, so the tenant's own history was NOT searched.",
        )
    except LakeQueryTimeoutError:
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            columns_searched=columns,
            unavailable_reason=(
                f"The sweep exceeded its {SWEEP_TIMEOUT_SECONDS:.0f}s budget, so the tenant's history was NOT fully searched."
            ),
        )
    except LakeQueryError as exc:
        logger.warning(
            "retro_hunt.lake_sweep_failed tenant=%s type=%s err=%s",
            tenant_id,
            str(indicator_type).replace("\r", "").replace("\n", " ")[:32],
            type(exc).__name__,
        )
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            columns_searched=columns,
            unavailable_reason="The event lake refused or failed the sweep, so the tenant's history was NOT searched.",
        )

    if not result.rows:
        # An aggregate with no GROUP BY always returns one row. No rows means
        # something returned a shape this code does not understand, and
        # reading that as zero sightings is the failure this module is built
        # to avoid.
        return LakeSweepResult(
            indicator_type=indicator_type,
            value=value,
            checked=False,
            columns_searched=columns,
            unavailable_reason="The event lake returned an unreadable result, so the sweep outcome is unknown.",
        )

    row = result.rows[0]
    return LakeSweepResult(
        indicator_type=indicator_type,
        value=value,
        checked=True,
        sightings=int(row[0] or 0),
        first_sighting_at=row[1] if int(row[0] or 0) else None,
        last_sighting_at=row[2] if int(row[0] or 0) else None,
        connector_types=[str(v) for v in (row[3] or []) if v],
        hosts=[str(v) for v in (row[4] or []) if v],
        users=[str(v) for v in (row[5] or []) if v],
        columns_searched=columns,
    )


async def sweep_federated(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    indicator_type: str,
    value: str,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
) -> FederatedSweepResult:
    """Ask the tenant's own SIEMs, through the Phase 4 typed search.

    Reuses ``agent_tools.siem_search`` rather than calling the federated
    endpoint directly, because that module already enforces the property this
    surface needs most: the caller names an indicator *type* and the platform
    resolves the field per backend, so no query text is ever composed from a
    value a public feed supplied.
    """
    if not siem_search.feature_enabled():
        return FederatedSweepResult(
            checked=False,
            unavailable_reason="Federated SIEM search is switched off on this deployment, so connected SIEMs were NOT searched.",
        )

    # The federated layer takes hours and caps the window at a week. A
    # thirty-day retro-hunt therefore gets seven days of SIEM coverage, and
    # saying so is the difference between a bounded answer and a wrong one.
    hours = min(int(lookback_days) * 24, 7 * 24)

    try:
        result = await siem_search.search_indicator(
            db,
            tenant_id=tenant_id,
            indicator_type=indicator_type,
            value=value,
            since_hours=hours,
            actor="aisoc-retro-hunt",
        )
    except IndicatorTypeError as exc:
        return FederatedSweepResult(
            checked=False,
            unavailable_reason=f"The indicator was refused before any SIEM was searched: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 - an unreachable SIEM is a gap, not a crash
        logger.warning(
            "retro_hunt.federated_sweep_failed tenant=%s err=%s",
            tenant_id,
            type(exc).__name__,
        )
        return FederatedSweepResult(
            checked=False,
            unavailable_reason="The federated search failed, so connected SIEMs were NOT searched.",
        )

    if not result.sources:
        return FederatedSweepResult(
            checked=False,
            unavailable_reason="This tenant has no SIEM connected to AiSOC, so there was nothing to search beyond the event lake.",
        )

    ok = [s.connector_type for s in result.sources if s.status == "ok"]
    failed = [s.connector_type for s in result.sources if s.status == "error"]
    unmapped = [s.connector_type for s in result.sources if s.status == "no_field_mapping"]

    return FederatedSweepResult(
        # Checked when at least one backend actually answered. A sweep where
        # every source errored is not a zero.
        checked=bool(ok),
        sightings=len(result.rows),
        sources_ok=ok,
        sources_failed=failed,
        sources_unmapped=unmapped,
        unavailable_reason=(None if ok else "Every connected SIEM failed to answer, so none of them were searched."),
    )


async def sweep_indicator(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    indicator_type: str,
    value: str,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    include_federated: bool = True,
) -> SweepOutcome:
    """Sweep one tenant's history for one indicator, lake and SIEMs.

    Raises ``IndicatorTypeError`` when the indicator itself is malformed. That
    is deliberately not folded into a non-matching outcome: a feed publishing
    a value that is not the type it claims is a data-quality problem an
    operator should see, and rendering it as "no sightings" hides it forever.
    """
    checked_value = validate_value(indicator_type, value)

    lake = await sweep_lake(
        tenant_id=tenant_id,
        indicator_type=indicator_type,
        value=checked_value,
        lookback_days=lookback_days,
    )

    if include_federated:
        federated = await sweep_federated(
            db,
            tenant_id=tenant_id,
            indicator_type=indicator_type,
            value=checked_value,
            lookback_days=lookback_days,
        )
    else:
        federated = FederatedSweepResult(
            checked=False,
            unavailable_reason="Federated SIEM search was not requested for this sweep.",
        )

    return SweepOutcome(
        indicator_type=indicator_type,
        value=checked_value,
        lookback_days=max(1, min(int(lookback_days), MAX_LOOKBACK_DAYS)),
        lake=lake,
        federated=federated,
    )


__all__ = [
    "DEFAULT_LOOKBACK_DAYS",
    "MAX_BYTES_PER_SWEEP",
    "MAX_LOOKBACK_DAYS",
    "SWEEP_TIMEOUT_SECONDS",
    "FederatedSweepResult",
    "LakeSweepResult",
    "SweepBudgetExceeded",
    "SweepOutcome",
    "build_sweep_sql",
    "sweep_federated",
    "sweep_indicator",
    "sweep_lake",
]
