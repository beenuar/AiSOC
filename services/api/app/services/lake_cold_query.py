"""Estimating and pacing a query that has to read the cold tier.

Depth plan 4.3, third bullet: *a query over cold data through ``/lake/sql``
or a hunt reports an estimated cost and a progress state instead of timing
out silently.*

What was wrong
--------------
``/lake/sql`` already reported a ``cost``, but it was the rate limiter's
token price — a number about how often you may ask, not about how much the
asking will read. And there was no progress state at all: a query over the
cold volume either came back inside the published 30-second default or
raised ``LakeQueryTimeoutError``, which tells an analyst nothing about
whether a longer timeout would have helped, how much data was involved, or
what it would have cost to find out.

Where the numbers come from
---------------------------
Every figure here is ClickHouse's, not ours.

* Rows and parts come from ``EXPLAIN ESTIMATE``, which is the planner's
  own answer after partition pruning.
* The warm/cold split comes from ``system.parts`` joined to
  ``system.disks``, matched against the volume names the tiering storage
  policy declares. A part is cold because ClickHouse says it is on the
  cold volume, not because of its age — the two disagree whenever a move
  is in flight or the TTL has been changed, and the disk is the one that
  decides what the read costs.
* Progress comes from ``system.processes`` keyed on the query id we set,
  so ``rows_read`` and ``total_rows_approx`` are the server's counters.

There is deliberately **no invented throughput constant**. A predicted
"this will take N seconds" would need a bytes-per-second figure, and the
only honest source for one is a measurement on the deployment's own
hardware, which this code has not got. The routing rule therefore does not
predict a duration: a query is routed to a job when the estimate says it
must read the **cold volume**, which is the case the plan names, and the
synchronous bound stays the published 30-second default and 60-second
maximum that ``/lake/sql`` already documents.

Money
-----
``estimated_usd`` is ``None`` unless an operator has configured a
retrieval price. ``docs/decisions/storage-cost-model.json`` is a *storage*
rate card — dollars per GB-month resident — and using it to price a read
would be quoting the wrong number confidently. A deployment that knows its
provider's retrieval price sets ``AISOC_LAKE_COLD_RETRIEVAL_USD_PER_GB``
and gets a figure derived from it; one that does not gets ``None`` and the
reason, which is more useful than a plausible invention.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: Volume names the tiering storage policy declares
#: (``services/api/clickhouse/tiering/storage-policy.xml``). A part on one
#: of these is a part whose read leaves local disk.
COLD_VOLUME_NAMES = frozenset({"cold"})

#: The table the lake stores events in. Estimating is scoped to the
#: allowlisted tables the rewriter already permits; this is the only one
#: that is tiered today, and a table absent from the parts query
#: contributes zero cold bytes rather than being guessed at.
LAKE_DATABASE = "aisoc"

#: Environment variable carrying the deployment's own retrieval price. No
#: default: see the module docstring.
RETRIEVAL_PRICE_ENV = "AISOC_LAKE_COLD_RETRIEVAL_USD_PER_GB"

_BYTES_PER_GB = 1024**3


class ColdEstimateUnavailable(RuntimeError):
    """The estimate could not be produced.

    Raised rather than returning a zero. A scan estimate of zero and "we
    could not estimate" are opposite answers, and returning the first for
    the second is how a query over 400 days of cold data gets waved
    through as free.
    """


@dataclass(frozen=True)
class ScanEstimate:
    """What a query is expected to read, split by where the data lives."""

    estimated_rows: int
    estimated_parts: int
    estimated_bytes: int
    cold_bytes: int
    warm_bytes: int
    tables: list[str] = field(default_factory=list)
    #: ``None`` when no retrieval price is configured, with ``cost_basis``
    #: saying so. Never 0.0, which would read as "free".
    estimated_usd: float | None = None
    cost_basis: str = ""

    @property
    def touches_cold(self) -> bool:
        return self.cold_bytes > 0

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["touches_cold"] = self.touches_cold
        return payload


def _retrieval_price() -> float | None:
    raw = os.environ.get(RETRIEVAL_PRICE_ENV, "").strip()
    if not raw:
        return None
    try:
        price = float(raw)
    except ValueError:
        # Loud: an operator who set a price and got no figure would
        # reasonably conclude the feature does not work.
        logger.error(
            "%s is set to %r, which is not a number; no cost figure will be reported",
            RETRIEVAL_PRICE_ENV,
            raw,
        )
        return None
    if price < 0:
        logger.error("%s is negative (%s); ignoring it", RETRIEVAL_PRICE_ENV, price)
        return None
    return price


def price_cold_bytes(cold_bytes: int) -> tuple[float | None, str]:
    """Turn cold bytes into a money figure, or say why there is none."""
    price = _retrieval_price()
    if price is None:
        return None, (
            "no retrieval price is configured, so no money figure is reported. "
            f"docs/decisions/storage-cost-model.json is a storage rate card (dollars per GB-month "
            f"resident) and pricing a read from it would be quoting the wrong number. Set "
            f"{RETRIEVAL_PRICE_ENV} to your provider's retrieval price to get one."
        )
    gb = cold_bytes / _BYTES_PER_GB
    return round(gb * price, 4), (f"{gb:.3f} GB from the cold volume at the configured {RETRIEVAL_PRICE_ENV}={price} USD/GB")


# ``EXPLAIN ESTIMATE`` returns one row per table with the columns
# (database, table, parts, rows, marks). Column order is stable across the
# versions this project supports, but the rows are read by name where the
# driver gives names and by position only as a fallback — a silent column
# reorder would otherwise swap parts and rows, and both are plausible
# integers.
_ESTIMATE_COLUMNS = ("database", "table", "parts", "rows", "marks")


def parse_explain_estimate(columns: list[str], rows: list[list[Any]]) -> tuple[int, int, list[str]]:
    """Fold ``EXPLAIN ESTIMATE`` output into (rows, parts, tables)."""
    if not rows:
        return 0, 0, []
    index = {name: i for i, name in enumerate(columns)}
    if not {"rows", "parts"} <= set(index):
        if len(columns) != len(_ESTIMATE_COLUMNS):
            raise ColdEstimateUnavailable(f"EXPLAIN ESTIMATE returned columns {columns!r}, which this build cannot read")
        index = {name: i for i, name in enumerate(_ESTIMATE_COLUMNS)}

    total_rows = 0
    total_parts = 0
    tables: list[str] = []
    for row in rows:
        total_rows += int(row[index["rows"]] or 0)
        total_parts += int(row[index["parts"]] or 0)
        if "table" in index:
            name = str(row[index["table"]] or "")
            if name and name not in tables:
                tables.append(name)
    return total_rows, total_parts, tables


# The parts query. Scoped to the lake database and to the tables the
# estimate named, so a tenant's estimate does not read the whole cluster's
# part list. ``active`` matters: inactive parts are merge leftovers that
# no query reads, and counting them would inflate every estimate.
PARTS_SQL = (
    "SELECT disks.name AS disk, "
    "sum(parts.bytes_on_disk) AS bytes_on_disk "
    "FROM system.parts AS parts "
    "LEFT JOIN system.disks AS disks ON disks.name = parts.disk_name "
    "WHERE parts.active AND parts.database = %(database)s AND parts.table IN %(tables)s "
    "GROUP BY disks.name"
)


def split_bytes_by_volume(
    rows: list[list[Any]],
    *,
    cold_disk_names: frozenset[str],
) -> tuple[int, int]:
    """Split ``(disk, bytes)`` pairs into (cold, warm).

    A disk name this deployment does not recognise as cold counts as warm.
    That direction is deliberate: over-reporting cold bytes would route
    ordinary queries into the job path and make the feature feel broken,
    while under-reporting routes a genuinely cold query to the
    synchronous path where it fails the way it always did — no worse than
    before, and visible.
    """
    cold = 0
    warm = 0
    for row in rows:
        disk = str(row[0] or "")
        size = int(row[1] or 0)
        if disk in cold_disk_names:
            cold += size
        else:
            warm += size
    return cold, warm


def cold_disk_names_from_policy(policy_rows: list[list[Any]]) -> frozenset[str]:
    """Which disks belong to a cold volume, per ``system.storage_policies``.

    Read from the server rather than hardcoded, because the volume is
    named in a mounted XML file an operator owns. The constant above is
    the fallback for a deployment that has not applied the tiering
    migration, where there is no cold volume and the answer is empty
    anyway.
    """
    names: set[str] = set()
    for row in policy_rows:
        volume = str(row[0] or "")
        if volume not in COLD_VOLUME_NAMES:
            continue
        disks = row[1]
        if isinstance(disks, (list, tuple)):
            names.update(str(d) for d in disks)
        elif disks:
            names.add(str(disks))
    return frozenset(names)


#: A query id is echoed into logs and into ``system.processes``; keeping it
#: to a known-safe alphabet means it can never carry anything that would
#: need escaping wherever it is rendered.
_QUERY_ID_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def validate_query_id(query_id: str) -> str:
    if not _QUERY_ID_SAFE.match(query_id):
        raise ValueError(f"query id {query_id!r} is not of the expected shape")
    return query_id


@dataclass(frozen=True)
class QueryProgress:
    """A running query's own counters, from ``system.processes``.

    ``total_rows_approx`` is ClickHouse's estimate and can move while the
    query runs, so ``ratio`` is clamped and is explicitly ``None`` when
    the server has not published a total — a progress bar that invents
    100% because the denominator was zero is worse than one that says it
    does not know.
    """

    rows_read: int
    bytes_read: int
    total_rows_approx: int
    elapsed_seconds: float

    @property
    def ratio(self) -> float | None:
        if self.total_rows_approx <= 0:
            return None
        return min(1.0, self.rows_read / self.total_rows_approx)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rows_read": self.rows_read,
            "bytes_read": self.bytes_read,
            "total_rows_approx": self.total_rows_approx,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "ratio": self.ratio,
        }


PROGRESS_SQL = "SELECT read_rows, read_bytes, total_rows_approx, elapsed FROM system.processes WHERE query_id = %(query_id)s"

#: Which disks each storage volume holds, per the server.
POLICY_SQL = "SELECT arrayJoin(volume_name) AS volume, disks FROM system.storage_policies"


async def estimate_scan(rewritten_sql: str) -> ScanEstimate:
    """Ask ClickHouse what a query will read, and where it lives.

    Every number here is the server's. This function does no arithmetic
    beyond summing what it is told and converting bytes to a price when
    one is configured.

    Raises :class:`ColdEstimateUnavailable` when the server cannot be
    asked, rather than returning zeros — a scan estimate of zero and "we
    could not estimate" are opposite answers, and returning the first for
    the second waves a 400-day cold scan through as free.
    """
    # Imported here rather than at module scope: app.db.clickhouse imports
    # the driver lazily and importing it at module load would pull the
    # soft dependency into every process that imports this module, which
    # includes the pure-function tests.
    from app.db.clickhouse import (  # noqa: PLC0415
        LakeQueryError,
        LakeQueryNotConfiguredError,
        execute_lake_query,
    )

    try:
        explained = await execute_lake_query(f"EXPLAIN ESTIMATE {rewritten_sql}", timeout_seconds=10.0)
    except LakeQueryNotConfiguredError as exc:
        raise ColdEstimateUnavailable("the lake backend is not configured") from exc
    except LakeQueryError as exc:
        raise ColdEstimateUnavailable(f"EXPLAIN ESTIMATE failed: {exc}") from exc

    rows, parts, tables = parse_explain_estimate(explained.columns, explained.rows)
    if not tables:
        # A query the planner attributes to no table reads nothing from
        # the lake — a constant select, say. Zero is the right answer
        # here and is distinguishable from the failure above, which
        # raises.
        return ScanEstimate(
            estimated_rows=rows,
            estimated_parts=parts,
            estimated_bytes=0,
            cold_bytes=0,
            warm_bytes=0,
            tables=[],
            estimated_usd=None,
            cost_basis="this query reads no lake table",
        )

    try:
        policies = await execute_lake_query(POLICY_SQL, timeout_seconds=10.0)
        cold_disks = cold_disk_names_from_policy(policies.rows)
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        # A deployment that has not applied the tiering migration has no
        # cold volume and no storage_policies row for one. Treated as
        # "nothing is cold" rather than as a failure, because that is the
        # truth on an untiered deployment and refusing to estimate would
        # make this feature unusable there.
        logger.info("lake.estimate.no_storage_policy reason=%s", exc)
        cold_disks = frozenset()

    try:
        parts_result = await execute_lake_query(
            PARTS_SQL,
            timeout_seconds=10.0,
            params={"database": LAKE_DATABASE, "tables": tuple(tables)},
        )
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        raise ColdEstimateUnavailable(f"could not read system.parts: {exc}") from exc

    cold_bytes, warm_bytes = split_bytes_by_volume(parts_result.rows, cold_disk_names=cold_disks)
    estimated_usd, basis = price_cold_bytes(cold_bytes)

    return ScanEstimate(
        estimated_rows=rows,
        estimated_parts=parts,
        estimated_bytes=cold_bytes + warm_bytes,
        cold_bytes=cold_bytes,
        warm_bytes=warm_bytes,
        tables=tables,
        estimated_usd=estimated_usd,
        cost_basis=basis,
    )
