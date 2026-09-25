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
        "query-layer WHERE tenant_id (the primary control, gated by check_tenant_query_predicates.py) with RLS "
        "beneath it: migrations/002_rls.sql covered six tables, 060_rls_coverage.sql plus one alembic revision in "
        "each of honeytokens / osquery-tls / purple-team / ueba take it to 92 of 95 tenant-scoped tables. "
        "test_postgres_rls.py replays two tenants through every covered table against live Postgres "
        "(integration.yml) as a NOSUPERUSER NOBYPASSRLS role — and asserts that the role the services actually "
        "ship with bypasses RLS entirely, so the coverage figure is never read as a live guarantee. "
        "services/api/tests/test_*_tenant_isolation.py; deliberate cross-tenant reads (MSSP portfolio) resolve "
        "their tenant list through org_scope and are replayed by test_mssp_portfolio_isolation.py",
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
        "lake_sql.rewrite_for_tenant injects tenant predicate and refuses (LakeSqlIsolationError) when it cannot prove "
        "it did; live-replay test_live_stores.py::test_clickhouse_lake_query_as_A_excludes_B (isolation-live.yml); "
        "rewriter run against the shipped sqlglot range and against the newest release above it "
        "+ pin agreement gate (lake-isolation.yml)",
    ),
    StoreCoverage(
        "redis",
        "container_gated",
        "aisoc:t:<tenant>:* keyspace namespacing; live-replay test_live_stores.py::test_redis_scan_as_A_excludes_B (isolation-live.yml); "
        "the RBA entity rollup (aisoc:fusion:rba:*) is additionally replayed at the route layer by "
        "test_route_tenant_scope.py, because key prefixing isolates whichever tenant it is handed and the "
        "fusion routes used to take that tenant from the query string",
    ),
    StoreCoverage(
        "kafka",
        "container_gated",
        "per-tenant envelope filter (graph_ws); live-replay "
        "test_live_stores.py::test_kafka_subscriber_A_never_receives_B (isolation-live.yml)",
    ),
)

VALID_STATUSES = {"offline_gated", "rls", "container_gated"}
