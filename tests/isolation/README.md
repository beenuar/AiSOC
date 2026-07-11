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
2. **Live-container replay (Phase 3 `integration.yml`).** Seeds tenant A + B in
   real containers (Qdrant, Neo4j, Redis, ClickHouse, Kafka) and asserts a read
   as A returns zero B rows/vectors/nodes/keys. Promoted to a required check on
   `main` when the integration tier lands.

## Coverage

See `stores.py::STORES`. Each store is one of:

- `offline_gated` — query-construction isolation asserted here, every PR.
- `rls` — enforced by Postgres RLS + query-layer filters (tested in
  `services/api/tests/test_*_tenant_isolation.py`).
- `container_pending` — needs the live-container replay in Phase 3.
