"""Registry of datastores and their tenant-isolation coverage.

Table-driven so a new store or read path cannot ship without an entry. The
registry test (`test_registry.py`) fails if any store is left `unset`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StoreCoverage:
    name: str
    # one of: offline_gated | rls | container_gated | container_pending | unset
    status: str
    note: str


STORES: tuple[StoreCoverage, ...] = (
    StoreCoverage(
        "postgres",
        "rls",
        "migrations/002_rls.sql + query-layer WHERE tenant_id; services/api/tests/test_*_tenant_isolation.py",
    ),
    StoreCoverage(
        "qdrant",
        "offline_gated",
        "tests/isolation/test_qdrant_isolation.py — search always tenant-scoped; writes stamp tenant_id",
    ),
    StoreCoverage(
        "neo4j",
        "container_gated",
        "tenant_id property filter; live-replay test_live_stores.py::test_neo4j_scoped_match_as_A_excludes_B (isolation-live.yml)",
    ),
    StoreCoverage(
        "clickhouse",
        "container_gated",
        "lake_sql.rewrite_for_tenant injects tenant predicate; live-replay test_live_stores.py::test_clickhouse_lake_query_as_A_excludes_B (isolation-live.yml)",
    ),
    StoreCoverage(
        "redis",
        "container_gated",
        "aisoc:t:<tenant>:* keyspace namespacing; live-replay test_live_stores.py::test_redis_scan_as_A_excludes_B (isolation-live.yml)",
    ),
    StoreCoverage(
        "kafka",
        "container_gated",
        "per-tenant envelope filter (graph_ws); live-replay test_live_stores.py::test_kafka_subscriber_A_never_receives_B (isolation-live.yml)",
    ),
)

VALID_STATUSES = {"offline_gated", "rls", "container_gated"}
