"""Tiered cold storage with query-on-cold (t6-cold-storage).

Three tiers, three retention horizons, one query interface:

* **Hot** — events are still in the operational store (SQLite +
  ClickHouse). Queryable via the existing realtime endpoints.
* **Warm** — events older than ``warm_threshold_days`` are
  evicted from the hot path and rolled up into a per-day Parquet-
  shaped batch. Still locally accessible, predicate push-down on
  day boundaries.
* **Cold** — events older than ``cold_threshold_days`` are stored
  in the cold tier (S3 / GCS in production, on-disk JSON Lines in
  the dev runner). Queryable through Athena / Presto / DuckDB —
  the platform never re-hydrates cold data into the operational
  store. Instead the agent fires a query through the
  :func:`query_cold_archive` tool and gets back a result set.

The runtime here is a *façade* over whichever query engine the
deployment configures. The default ``LocalQueryEngine`` reads
JSON Lines from a directory and supports a small SQL-like grammar
(see :mod:`app.cold_storage.query`); production swaps in a
``PrestoQueryEngine`` that submits to Athena/Presto.

The ``cold_archive.query`` tool is the agent-facing surface. It is
registered with the tool registry so the Hunter / Investigator /
Reporter agents can pull historical evidence on cases without the
operator having to wire up a custom integration.
"""
from app.cold_storage.archive import (
    ArchiveBatch,
    ArchiveStats,
    StorageTier,
    TieredArchive,
    archive_event,
    cold_archive,
    write_demo_archive,
)
from app.cold_storage.query import (
    LocalQueryEngine,
    QueryEngine,
    QueryResult,
    parse_query,
    query_cold_archive,
)

__all__ = [
    "ArchiveBatch",
    "ArchiveStats",
    "LocalQueryEngine",
    "QueryEngine",
    "QueryResult",
    "StorageTier",
    "TieredArchive",
    "archive_event",
    "cold_archive",
    "parse_query",
    "query_cold_archive",
    "write_demo_archive",
]
