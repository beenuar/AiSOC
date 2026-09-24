# Cross-store tenant-isolation suite

Phase 1.3 of the world-class program. Postgres row-level security covers one of
six datastores; every other store is a potential silent cross-tenant leak. This
suite is table-driven (see `stores.py`) so a new datastore or a new read path
cannot ship without an isolation entry.

## Two layers

1. **Offline (gated on every PR, `.github/workflows/isolation.yml`).** Asserts
   that each store's read path *constructs* a tenant scope — e.g. that
   `QdrantStore.semantic_search` always passes a tenant filter, that a search as
   tenant A can never include tenant B in its filter, and that writes stamp
   `tenant_id` with non-colliding, tenant-scoped ids. These run without any live
   datastore by mocking the client.
2. **Live-container replay (`.github/workflows/isolation-live.yml`,
   `test_live_stores.py`).** Seeds tenant A + B in real containers (Neo4j,
   Redis, ClickHouse, Kafka) and asserts a read as A returns zero B
   rows/nodes/keys/messages. ClickHouse runs the *production*
   `lake_sql.rewrite_for_tenant` rewriter against a live warehouse. Each test
   also asserts the unscoped read sees both tenants, so a scoped pass can't be
   vacuous. Tests skip cleanly with no containers, so a local run stays green.

## Coverage

See `stores.py::STORES`. Each store is one of:

- `offline_gated` — query-construction isolation asserted here, every PR
  (Qdrant).
- `rls` — enforced by Postgres RLS + query-layer filters (tested in
  `services/api/tests/test_*_tenant_isolation.py`).
- `container_gated` — live-container A-vs-B replay in `isolation-live.yml`
  (Neo4j, Redis, ClickHouse, Kafka).

## The parser that enforces ClickHouse isolation is itself a dependency

ClickHouse scoping is produced by `sqlglot` walking a parse tree, so the
guarantee is only as stable as that tree's shape. It is not stable: sqlglot 27
renamed the SELECT's FROM clause arg, the walk stopped finding tables, and the
rewriter returned every single-table query unscoped *and* unfiltered by the
allowlist while reporting success. Two gates in
`.github/workflows/lake-isolation.yml` close that off — `check_sqlglot_pin.py`
requires all seven install paths to declare one identical range, and the
rewriter suites run against the shipped range and the next major. The rewriter
also audits its own output now and raises `LakeSqlIsolationError` rather than
returning SQL it cannot prove is scoped; `services/api/tests/test_lake_sql_fail_closed.py`
blinds the table walk deliberately to assert that refusal on any sqlglot
version.
