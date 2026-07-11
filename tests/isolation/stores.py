"""Registry of datastores and their tenant-isolation coverage.

Table-driven so a new store or read path cannot ship without an entry. The
registry test (`test_registry.py`) fails if any store is left `unset`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StoreCoverage:
    name: str
    # one of: offline_gated | rls | container_pending | unset
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
        "container_pending",
        "write-time tenant_id tagging exists (ingest/internal/graph/writer.go); live-replay in Phase 3",
    ),
    StoreCoverage(
        "clickhouse",
        "container_pending",
        "lake_sql.rewrite_for_tenant injects tenant predicate; live-replay in Phase 3",
    ),
    StoreCoverage(
        "redis",
        "container_pending",
        "cache-key namespacing; live-replay in Phase 3",
    ),
    StoreCoverage(
        "kafka",
        "container_pending",
        "topic/consumer-group scoping; live-replay in Phase 3",
    ),
)

VALID_STATUSES = {"offline_gated", "rls", "container_pending"}
