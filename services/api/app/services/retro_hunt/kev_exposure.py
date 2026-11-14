"""When CISA says a vulnerability is being exploited, check whether we have it.

Gap-closure Phase 8.2.

The CISA Known Exploited Vulnerabilities catalogue is the one threat-intel
feed in this deployment that needs no API key and ships on by default, and it
flows through the same pipeline as every other indicator: an entry becomes a
``NEW_IOC`` event with ``type: "vulnerability"``. Until Phase 8.1 nothing
consumed those events at all. This module is what happens to the ones that
carry a CVE.

Why a CVE takes a different path from every other indicator
-----------------------------------------------------------

A hash, an address or a domain is something that appears in event telemetry,
so the question "have we seen this" is a question for the event lake. A CVE
is not. It never appears in a process-creation event or a firewall log, and
sweeping the lake for the string "CVE-2024-3400" would return zero on every
tenant forever while looking exactly like a sweep that worked. The question a
CVE asks is "do we run the affected thing", and the only surfaces that can
answer it are the asset inventory and whatever vulnerability scanner feeds it.

So ``intel_types.route_feed_type`` routes a vulnerability here instead, and
records that as a decision rather than as an omission.

What "exposed" means, and what it deliberately does not
--------------------------------------------------------

Exposed means the tenant's own vulnerability data has an **unremediated**
finding whose CVE matches. That is a narrow definition on purpose.

It does not mean "an asset runs software CISA named". Matching a KEV entry's
vendor and product strings against an asset's OS field would produce a
plausible-looking answer built on string similarity, and a case task that
claims a host is exposed when it is not is worse than no task: it costs an
analyst the time to disprove it, and the second one they disprove is the last
one they read. If a tenant has no vulnerability data, this reports that it
could not check rather than reporting no exposure, which is the same rule the
lake sweep follows.

The KEV catalogue is authoritative about exploitation, so a matching finding
also has ``is_exploited`` set. That is a real change to the tenant's data and
it is the one write here that is not a case task: a scanner that has not
caught up on exploitation status is the ordinary case, and CISA is a better
source for that field than most scanners.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetVulnerability
from app.models.case import Case, CaseTask
from app.models.retro_hunt import RetroHuntSettings, RetroHuntSighting

logger = logging.getLogger(__name__)

#: The indicator type CVE sightings are recorded under in
#: ``retro_hunt_sightings``. Not one of the Phase 4 searchable types, because
#: nothing searches telemetry for it; it shares the table so one indicator
#: opens one case task per tenant under the same UNIQUE constraint that stops
#: an IOC opening a second alert.
CVE_INDICATOR_TYPE = "cve"

#: Assets above this count are summarised rather than listed. A case task is
#: read by a person, and a task body naming nine hundred hosts is not.
_MAX_LISTED_ASSETS = 25

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: What a tenant with no vulnerability data is told.
#:
#: A module constant rather than an inline string because the last sentence is
#: the load-bearing one and it has to be assertable. "No unremediated findings"
#: and "nothing has ever scanned you" both render as zero exposed assets, and
#: only one of them is reassuring.
NO_VULN_DATA_REASON = (
    "This tenant has no vulnerability data in AiSOC, so exposure could NOT be checked. "
    "Connect a vulnerability scanner or import an asset inventory. "
    "This is not a statement that the tenant is unaffected."
)


@dataclass
class ExposureResult:
    """What the tenant's own data said about one KEV entry."""

    cve_id: str
    #: False when the tenant has no vulnerability data at all. A caller must
    #: not read ``exposed_assets == []`` without checking this: "we scanned and
    #: you are clean" and "nothing has ever scanned you" are different answers
    #: and only one of them is reassuring.
    checked: bool
    exposed_asset_names: list[str] = field(default_factory=list)
    exposed_asset_count: int = 0
    findings_updated: int = 0
    case_id: uuid.UUID | None = None
    task_id: uuid.UUID | None = None
    deduplicated: bool = False
    unavailable_reason: str | None = None

    @property
    def exposed(self) -> bool:
        return self.checked and self.exposed_asset_count > 0


def is_cve(value: str) -> bool:
    """Whether a feed's value has the shape of a CVE identifier.

    Checked rather than trusted. A feed publishing ``type: vulnerability``
    with a free-text advisory title in the value would otherwise produce a
    query for a string no scanner ever records, and the zero rows would read
    as "not exposed".
    """
    return bool(_CVE.match(str(value or "").strip()))


async def _tenant_has_vulnerability_data(db: AsyncSession, tenant_id: uuid.UUID) -> bool:
    """Whether anything has ever written a vulnerability finding for a tenant.

    This is the difference between a clean answer and no answer, so it is a
    separate query rather than an inference from an empty result set.
    """
    row = await db.execute(select(AssetVulnerability.id).where(AssetVulnerability.tenant_id == tenant_id).limit(1))
    return row.scalar_one_or_none() is not None


async def check_exposure(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    cve_id: str,
    feed_source: str,
    intel_first_seen_at: datetime | None = None,
    now: datetime | None = None,
) -> ExposureResult:
    """Check one tenant's vulnerability data for one KEV entry.

    Opens at most one case task per (tenant, CVE), enforced by the same
    ``retro_hunt_sightings`` UNIQUE constraint that keeps an IOC from opening
    a second alert. The caller owns the transaction.
    """
    now = now or datetime.now(UTC)
    cve = str(cve_id).strip().upper()

    if not is_cve(cve):
        return ExposureResult(
            cve_id=cve,
            checked=False,
            unavailable_reason=(
                f"{cve_id!r} does not have the shape of a CVE identifier, so the tenant's vulnerability data was NOT checked."
            ),
        )

    if not await _tenant_has_vulnerability_data(db, tenant_id):
        return ExposureResult(
            cve_id=cve,
            checked=False,
            unavailable_reason=NO_VULN_DATA_REASON,
        )

    rows = (
        await db.execute(
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(
                AssetVulnerability.tenant_id == tenant_id,
                Asset.tenant_id == tenant_id,
                AssetVulnerability.cve_id.ilike(cve),
                AssetVulnerability.remediated_at.is_(None),
            )
        )
    ).all()

    if not rows:
        return ExposureResult(cve_id=cve, checked=True)

    # Order by asset criticality so a truncated list shows the ones that
    # matter. `critical` first, then high, then the rest.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assets = sorted({(a.name, a.criticality) for _v, a in rows}, key=lambda pair: (order.get(str(pair[1]).lower(), 9), pair[0]))
    names = [name for name, _crit in assets]

    # CISA is authoritative on exploitation, and most scanners lag it. This is
    # the one write here that is not a case task.
    updated = await db.execute(
        update(AssetVulnerability)
        .where(
            AssetVulnerability.tenant_id == tenant_id,
            AssetVulnerability.cve_id.ilike(cve),
            AssetVulnerability.remediated_at.is_(None),
            AssetVulnerability.is_exploited.is_(False),
        )
        .values(is_exploited=True)
    )

    existing = (
        await db.execute(
            select(RetroHuntSighting).where(
                RetroHuntSighting.tenant_id == tenant_id,
                RetroHuntSighting.indicator_type == CVE_INDICATOR_TYPE,
                RetroHuntSighting.indicator_value == cve,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_matched_at = now
        existing.sightings = len(assets)
        existing.times_seen += 1
        existing.updated_at = now
        return ExposureResult(
            cve_id=cve,
            checked=True,
            exposed_asset_names=names[:_MAX_LISTED_ASSETS],
            exposed_asset_count=len(assets),
            findings_updated=int(updated.rowcount or 0),
            deduplicated=True,
            unavailable_reason=None,
        )

    case, task = await _open_case_task(
        db,
        tenant_id=tenant_id,
        cve=cve,
        feed_source=feed_source,
        assets=assets,
        intel_first_seen_at=intel_first_seen_at,
        now=now,
    )

    db.add(
        RetroHuntSighting(
            tenant_id=tenant_id,
            indicator_type=CVE_INDICATOR_TYPE,
            indicator_value=cve,
            feed_source=feed_source,
            intel_first_seen_at=intel_first_seen_at,
            first_matched_at=now,
            last_matched_at=now,
            sightings=len(assets),
            matched_surfaces=[{"surface": "vulnerability_inventory", "assets": len(assets)}],
            times_seen=1,
            created_at=now,
            updated_at=now,
        )
    )
    logger.info("retro_hunt.kev_exposure tenant=%s assets=%d", tenant_id, len(assets))

    return ExposureResult(
        cve_id=cve,
        checked=True,
        exposed_asset_names=names[:_MAX_LISTED_ASSETS],
        exposed_asset_count=len(assets),
        findings_updated=int(updated.rowcount or 0),
        case_id=case.id,
        task_id=task.id,
    )


async def _open_case_task(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    cve: str,
    feed_source: str,
    assets: list[tuple[str, str]],
    intel_first_seen_at: datetime | None,
    now: datetime,
) -> tuple[Case, CaseTask]:
    """Open the case and the one task this CVE gets for this tenant."""
    listed = assets[:_MAX_LISTED_ASSETS]
    overflow = len(assets) - len(listed)

    lines = [
        f"{feed_source} published {cve} as a known exploited vulnerability.",
        "",
        "Provenance",
        f"  Feed: {feed_source}",
        (
            f"  Added to the catalogue: {intel_first_seen_at.date().isoformat()}"
            if intel_first_seen_at
            else "  Added to the catalogue: not published by this feed"
        ),
        "",
        f"Exposure in your own data: {len(assets)} unremediated finding(s)",
    ]
    lines += [f"  {name} ({criticality})" for name, criticality in listed]
    if overflow:
        lines.append(f"  and {overflow} more asset(s), listed on the vulnerability page")
    lines += [
        "",
        "This is drawn from your vulnerability findings, not inferred from software names.",
        "Assets with no scan coverage will not appear here, so this is a floor rather than a total.",
    ]

    case = Case(
        tenant_id=tenant_id,
        case_number=f"KEV-{cve.replace('CVE-', '')}-{int(now.timestamp())}",
        title=f"Known exploited vulnerability {cve} affects {len(assets)} asset(s)",
        description="\n".join(lines),
        case_type="vulnerability_exposure",
        priority="high" if any(c in {"critical", "high"} for _n, c in assets) else "medium",
        severity="high",
        # `new`, not `open`. The `aisoc_cases_status_check` constraint allows
        # exactly new/triaged/investigating/contained/resolved/closed, so the
        # previous value meant this insert raised a CheckViolationError on
        # every deployment -- which nothing noticed, because reaching it needs
        # a tenant with real vulnerability data, and until fix-pass item 5.2
        # the only writer of that table was a route a human calls by hand.
        status="new",
        tags=["kev", f"cve:{cve}", f"feed:{feed_source}"],
    )
    db.add(case)
    await db.flush()

    # `aisoc_case_tasks` has no `description` column, so the detail lives in
    # the case description above and the task carries the instruction. The
    # model used to declare one, against a table name no migration creates, so
    # this insert had never succeeded.
    task = CaseTask(
        case_id=case.id,
        tenant_id=tenant_id,
        title=(
            f"Patch or mitigate {cve} on {len(assets)} asset(s): CISA lists it as actively "
            f"exploited and your scan data shows unremediated findings"
        ),
        status="todo",
        created_by=feed_source,
    )
    db.add(task)
    await db.flush()
    return case, task


async def handle_kev_entry(
    db: AsyncSession,
    *,
    settings_row: RetroHuntSettings,
    cve_id: str,
    feed_source: str,
    intel_first_seen_at: datetime | None = None,
    now: datetime | None = None,
) -> ExposureResult:
    """Entry point from the intel consumer for one tenant and one CVE.

    Gated on the same per-tenant opt-in as a lake sweep. Deliberately not on
    the sweep *budget*: an exposure check is two indexed queries against the
    tenant's own Postgres rows rather than a warehouse scan, so charging it
    against a budget sized for the latter would starve the cheap check to
    protect against the expensive one.
    """
    if not settings_row.enabled:
        return ExposureResult(
            cve_id=str(cve_id),
            checked=False,
            unavailable_reason="This tenant has not opted in to retro-hunts.",
        )
    return await check_exposure(
        db,
        tenant_id=settings_row.tenant_id,
        cve_id=cve_id,
        feed_source=feed_source,
        intel_first_seen_at=intel_first_seen_at,
        now=now,
    )


__all__ = [
    "CVE_INDICATOR_TYPE",
    "ExposureResult",
    "NO_VULN_DATA_REASON",
    "check_exposure",
    "handle_kev_entry",
    "is_cve",
]
