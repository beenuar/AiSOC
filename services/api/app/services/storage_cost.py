"""A tenant's storage $/mo, beside its LLM $/mo (ADR-0005 follow-up, 6b).

Phase 6 computed a storage cost model and gated it. Both halves were real:
``scripts/storage_cost_model.py`` computes ≈$902/mo and ≈$30 per raw TB at
1 TB/day, ``docs/decisions/storage-cost-model.json`` is the committed worked
example, and ``.github/workflows/perf.yml`` fails when the two diverge.

Nothing read it. ADR-0005 asked for the tenant's storage $/mo to show next to
its LLM $/mo, and outside the ADR, the CHANGELOG and the perf workflow the
model's only readers were two ClickHouse tiering files citing it in a comment.
A cost model whose only consumer is the gate that checks the cost model is a
well-tested constant.

What this is, and what it is not
--------------------------------
This is a **projection**, not a bill. It takes one measurement — the
uncompressed bytes a tenant's events occupied in the lake over the window —
and runs the committed model's arithmetic over it at **reference list
prices**. It is not that tenant's spend, it is not their provider's invoice,
and it is not this deployment's actual retention shape (the shipped tiering
SQL is two tiers over 90 days; the model's scenario is three over 365). Every
one of those distinctions is carried on the wire so the console can say it,
because a modelled number rendered beside a measured one without a label is
how a guess stops looking like one — the defect the rest of
``cost_dashboard`` exists to prevent.

Absence is not zero
-------------------
The lake runs in the ``full`` profile. On a CORE deployment there is no
ClickHouse, so there is no measurement, and the projection is reported as
**not measured with the reason** rather than as ``$0.00``. This is the same
contract ``usage_metering.UNMEASURED`` already holds for ``events_ingested``,
and for the same reason: a confident zero for a tenant nobody measured reads
as free storage.

Why the rate card is duplicated here
------------------------------------
``scripts/storage_cost_model.py`` calls ``repo_root()`` at module scope, which
shells out to git. The API container has neither ``scripts/`` nor a checkout,
so it cannot be imported — the same constraint that put a second copy of the
LLM price table in ``cost_dashboard._PUBLIC_PRICING``. A second copy of a
number is a second place for it to drift, so ``storage_cost_model.py --check``
now reads these constants back and fails when they disagree. The duplication
is deliberate; the divergence is gated.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

logger = logging.getLogger("aisoc.storage_cost")

# ---------------------------------------------------------------------------
# The model. Mirrored from scripts/storage_cost_model.py and gated against it
# by `python3 scripts/storage_cost_model.py --check`.
# ---------------------------------------------------------------------------

#: USD per GB-month, by tier. Reference list prices.
RATE_CARD_USD_PER_GB_MONTH: dict[str, float] = {
    "hot_block": 0.080,  # gp3-class block storage backing the ClickHouse hot tier
    "warm_object": 0.023,  # standard object storage
    "cold_archive": 0.0125,  # infrequent-access / archive object storage
}

#: Days resident in each tier. Sums to 365.
RETENTION_DAYS: dict[str, int] = {"hot_block": 30, "warm_object": 60, "cold_archive": 275}

#: What the lake's ZSTD(3) columns achieve on OCSF-shaped JSON.
COMPRESSION_RATIO: float = 8.0

_GB_PER_TB = 1000
_BYTES_PER_GB = 1_000_000_000

#: Carried on every projection so a reader cannot take it for a bill.
DISCLAIMER = (
    "Projected from your measured ingest volume using the committed storage cost model "
    "(docs/decisions/storage-cost-model.json) at reference list prices. This is a model, "
    "not your provider's bill — verify against your own region and negotiated rates."
)

#: Said out loud when the lake is absent, rather than reporting a zero.
NO_LAKE_REASON = (
    "Ingest volume is counted in the ClickHouse event lake, which runs in the `full` profile. "
    "Not measured on a deployment without it, so no storage projection is possible."
)


class StorageTierProjection(BaseModel):
    """One retention tier's share of the projected monthly storage cost."""

    tier: str
    retention_days: int
    resident_gb: float
    rate_usd_per_gb_month: float
    monthly_usd: float


class StorageCostProjection(BaseModel):
    """Projected storage cost for a tenant, or an honest statement that there is none.

    ``measured`` is the field that matters. When it is false every money field
    is ``None`` — not ``0.0`` — and ``unmeasured_reason`` says why.
    """

    measured: bool
    #: Why there is no projection. ``None`` when there is one.
    unmeasured_reason: str | None = None

    #: The one measurement this rests on: uncompressed bytes the tenant's
    #: events occupied over the window, and how many events that was.
    raw_bytes_measured: int | None = None
    events_measured: int | None = None

    #: The measurement, expressed as the model's input.
    raw_tb_per_day: float | None = None

    #: The projection.
    monthly_usd: float | None = None
    usd_per_raw_tb_ingested: float | None = None
    tiers: list[StorageTierProjection] = Field(default_factory=list)

    #: Model parameters, echoed so the console can show what produced the number.
    compression_ratio: float = COMPRESSION_RATIO
    disclaimer: str = DISCLAIMER


def project(raw_bytes: int, *, window_days: int, events: int | None = None) -> StorageCostProjection:
    """Run the committed model over a measured ingest volume.

    Pure. ``raw_bytes`` is uncompressed bytes observed over ``window_days``;
    the arithmetic below is the same as ``storage_cost_model.compute`` with
    the scenario's fixed 1 TB/day replaced by the tenant's own rate.
    """
    days = max(window_days, 1)
    raw_tb_per_day = (raw_bytes / _BYTES_PER_GB) / _GB_PER_TB / days

    stored_gb_per_day = (raw_tb_per_day * _GB_PER_TB) / COMPRESSION_RATIO
    tiers: list[StorageTierProjection] = []
    total_monthly = 0.0
    for tier, retention in RETENTION_DAYS.items():
        resident_gb = stored_gb_per_day * retention
        rate = RATE_CARD_USD_PER_GB_MONTH[tier]
        monthly = resident_gb * rate
        total_monthly += monthly
        tiers.append(
            StorageTierProjection(
                tier=tier,
                retention_days=retention,
                resident_gb=round(resident_gb, 2),
                rate_usd_per_gb_month=rate,
                monthly_usd=round(monthly, 2),
            )
        )

    raw_tb_per_month = raw_tb_per_day * 30
    # A tenant that ingested nothing has a real, measured zero — it is not the
    # same as a tenant nobody measured, and `measured` is what tells them apart.
    per_tb = round(total_monthly / raw_tb_per_month, 2) if raw_tb_per_month else 0.0

    return StorageCostProjection(
        measured=True,
        raw_bytes_measured=raw_bytes,
        events_measured=events,
        raw_tb_per_day=round(raw_tb_per_day, 6),
        monthly_usd=round(total_monthly, 2),
        usd_per_raw_tb_ingested=per_tb,
        tiers=tiers,
    )


def not_measured(reason: str) -> StorageCostProjection:
    """A projection that could not be made, carrying why."""
    return StorageCostProjection(measured=False, unmeasured_reason=reason)


#: The tenant predicate is bound as a query parameter rather than formatted
#: in. ``rewrite_for_tenant`` exists for untrusted operator SQL; this SQL is
#: the API's own, and the isolation lesson from ``_events_of_interest`` was
#: that handing API-authored SQL to the rewriter and trusting the predicate
#: survived is how every tenant came to see the same global figure.
_VOLUME_SQL = """
SELECT count() AS events,
       sum(length(raw_payload) + length(ocsf_json)) AS raw_bytes
FROM aisoc.raw_events
WHERE tenant_id = %(tenant_id)s
  AND ingest_time >= %(start_at)s
  AND ingest_time < %(end_at)s
"""


async def measure_and_project(
    tenant_id: uuid.UUID,
    *,
    start: datetime,
    end: datetime,
    window_days: int,
) -> StorageCostProjection:
    """Measure the tenant's ingest volume and project its storage cost.

    Never raises: an unreachable or unconfigured lake is reported as *not
    measured* with the reason, because a storage panel that 500s the whole
    cost dashboard would trade a missing number for a missing page.
    """
    # Imported here rather than at module scope, deliberately. Everything
    # above this function is the model itself — constants and arithmetic over
    # them — and importing the lake pulls in `app.core.config`, the settings
    # stack and the ClickHouse driver. `cost_dashboard`'s own test suite is
    # pure by design (rows in, dashboard out, no database), and a module-level
    # import here would have made the pure builder untestable without a
    # driver, which is the coupling the split in `cost_dashboard` exists to
    # avoid. The same reasoning as `retro_hunt_consumer._build_consumer`.
    from app.db.clickhouse import (  # noqa: PLC0415
        LakeQueryError,
        LakeQueryNotConfiguredError,
        execute_lake_query,
    )

    try:
        result = await execute_lake_query(
            _VOLUME_SQL,
            timeout_seconds=10.0,
            params={"tenant_id": str(tenant_id), "start_at": start, "end_at": end},
        )
    except LakeQueryNotConfiguredError:
        return not_measured(NO_LAKE_REASON)
    except LakeQueryError as exc:
        logger.warning("storage_cost lake query failed: %s", str(exc).replace("\r", "").replace("\n", " ")[:200])
        return not_measured(f"The event lake did not answer, so ingest volume was not measured this run ({type(exc).__name__}).")

    if not result.rows or result.rows[0][1] is None:
        return not_measured("The event lake returned no rows for this tenant and window, so there is nothing to project from.")

    events = int(result.rows[0][0] or 0)
    raw_bytes = int(result.rows[0][1] or 0)
    return project(raw_bytes, window_days=window_days, events=events)


__all__ = [
    "COMPRESSION_RATIO",
    "DISCLAIMER",
    "NO_LAKE_REASON",
    "RATE_CARD_USD_PER_GB_MONTH",
    "RETENTION_DAYS",
    "StorageCostProjection",
    "StorageTierProjection",
    "measure_and_project",
    "not_measured",
    "project",
]
