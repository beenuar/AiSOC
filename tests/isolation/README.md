# Cross-store tenant-isolation suite

Phase 1.3 of the world-class program. Postgres row-level security covers one of
six datastores; every other store is a potential silent cross-tenant leak. This
suite is table-driven (see `stores.py`) so a new datastore or a new read path
cannot ship without an isolation entry.

## Where the tenant came from

The store suites below all answer the same question — *given* a tenant, can a
read see another one's rows? They cannot answer the question above them: where
did that tenant come from in the first place?

For `/fusion/entity-risk/*` the answer was "the query string", with no auth
dependency on the route, on both the API gateway and the fusion service. The
console reaches fusion directly through a Next rewrite when `FUSION_URL` is
set, so the parameter was reachable from any browser and naming somebody
else's tenant UUID returned their entity-risk queue. Redis key prefixing did
not help and never could: `aisoc:fusion:rba:topn:{tenant}` isolates whichever
tenant it is handed. Fixing the parameter's *value* would not have helped
either — a UUID that parses is still a UUID the caller chose.

`test_route_tenant_scope.py` covers that layer in three parts: the vendored
HS256 verifier and intersection rule offline; a two-tenant replay driving the
real fusion routes over ASGI against a live Redis; and a meta-assertion that
`scripts/check_route_tenant_scope.py` finds no violations anywhere in
`services/`. The gate is an AST pass over every route decorator and signature
in the tree, and it fails in two directions — a route that takes a tenant
identifier without an auth dependency, and a route that accepts one without
intersecting it with the caller's scope. `--self-test` injects a violation of
each kind plus a stale exemption and asserts all three are caught, because a
gate nobody has seen fail is indistinguishable from one that cannot.

The resolver is vendored into eight services (each is built with its own
directory as its Docker context, the same reason `service_auth.py` and
`cors.py` are vendored), so `sync_vendored_tenant_scope.py --check` runs
alongside it: a fix that lands in one copy and not the others is a fix in
none.

## The two shapes that question could not reach

`test_route_auth_default_deny.py` covers the rest of the surface, because the
gate above asks a *conditional* question and two shapes fall outside it.

**A route that takes no tenant was never in its reach.** 37 routes in
`services/agents` took none, and they included create, delete and *execute* a
response playbook. The suite drives the real routers over ASGI with credential
material configured — so a refusal is about the credential, not about an
unconfigured service — and asserts an anonymous caller is refused on every one
of them, that a valid console session still gets a non-empty response, that a
service token declaring no tenant is a 403, and that forged, expired,
`alg: none` and refresh tokens are each refused. `scripts/check_route_auth.py`
holds the line repo-wide: every route authenticates or appears in one of three
tables with its reason, and an entry that no longer matches an unauthenticated
route fails as stale.

**A route that matches on an id takes no tenant, which is exactly why it was
missing the filter.** `scripts/check_tenant_query_predicates.py` asks the
predicate question instead, deriving both the tenant-scoped models and the
tenant-scoped tables from the tree rather than from a list. The live half
seeds two tenants against a real database and asserts both hold rows *before*
asserting either absence — a scoped read against an empty table passes for the
wrong reason — then has tenant B name tenant A's `query_id` and get nothing.

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
- `rls` — query-layer filters with Postgres RLS beneath them, replayed live in
  `integration.yml` (`test_postgres_rls.py`, plus
  `services/api/tests/test_*_tenant_isolation.py`).
- `container_gated` — live-container A-vs-B replay in `isolation-live.yml`
  (Neo4j, Redis, ClickHouse, Kafka).

## What "RLS" is worth, stated where somebody will read it

Two conditions have to hold before a policy does anything, and in the shipped
configuration the second does not.

**The session must have bound a tenant.** A policy reads
`app.current_tenant_id`, and permits everything when it is unset. That is
deliberate — ingest, fusion, the hunt scheduler and the retention purge all
work across tenants and would otherwise process nothing, silently — but it
means RLS only engages on `TenantDBSession` and the agents' `_set_rls_context`
paths. Everywhere else the query predicate is the only control, which is why
`scripts/check_tenant_query_predicates.py` is the gate that matters and RLS is
the layer under it.

**The role must not bypass RLS.** A superuser, or any role with `BYPASSRLS`,
ignores policies even under `FORCE ROW LEVEL SECURITY` — FORCE binds the table
*owner*, not a superuser. `docker-compose.yml` and the CI service containers
run every service as `POSTGRES_USER=aisoc`, which the postgres image creates
as a superuser. So out of the box **no policy in this database is doing
anything**, and `test_postgres_rls.py` asserts that rather than footnoting it:
if the connecting role ever stops bypassing RLS, that test tells you, and the
docs should stop hedging. Everything else in that file reads as a
purpose-made `NOSUPERUSER NOBYPASSRLS` role, which is the configuration the
policies are written for and the one
`apps/docs/docs/operations/security.md` gives the grants for.

The suite also holds the line on three things that made policies inert before
anyone noticed: a tenant-scoped table with no policy at all, a policy without
`FORCE`, and a policy keyed on a session variable nothing sets (four read
`app.tenant_id` or `app.current_tenant`; two raised
`unrecognized configuration parameter` on an unbound session).

## Deliberate cross-tenant reads

The MSSP portfolio surface reads several tenants at once by design, which
makes it the one place where "filter by the caller's tenant" is not the rule
and therefore the one place a bypass would look like a feature. It is scoped
in one place — `services/api/app/services/org_scope.py` — and the aggregates
in `mssp_portfolio.py` take that scope as a parameter and pass it through
`require_scope`, which raises on an empty portfolio rather than running SQL
with no filter. Two gates:

- `services/api/tests/test_org_scope.py` (every PR) — an empty scope refuses,
  a `?tenant_id=` filter can only narrow, and an AST check fails the build if
  a new cross-tenant function is added that never calls `require_scope`.
- `services/api/tests/test_mssp_portfolio_isolation.py` (live Postgres, in
  `integration.yml`) — seeds two organisations plus an unmanaged tenant and
  asserts an aggregate run as one operator never returns the others, that an
  operator with no grants resolves to empty rather than to everything, and
  that the database itself rejects a grant naming a tenant outside the
  portfolio.

## The parser that enforces ClickHouse isolation is itself a dependency

ClickHouse scoping is produced by `sqlglot` walking a parse tree, so the
guarantee is only as stable as that tree's shape. It is not stable: sqlglot 27
renamed the SELECT's FROM clause arg, the walk stopped finding tables, and the
rewriter returned every single-table query unscoped *and* unfiltered by the
allowlist while reporting success. Two gates in
`.github/workflows/lake-isolation.yml` close that off — `check_sqlglot_pin.py`
requires all seven install paths to declare one identical range, and the
rewriter suites run against the shipped range and against whatever sqlglot
publishes above it. The second leg carries no upper bound on purpose, so it
begins testing the next major the day one exists rather than when somebody
remembers to widen it; while no such release exists it re-runs the shipped
version and says so in a warning annotation rather than passing a duplicate
green off as forward coverage. The rewriter
also audits its own output now and raises `LakeSqlIsolationError` rather than
returning SQL it cannot prove is scoped; `services/api/tests/test_lake_sql_fail_closed.py`
blinds the table walk deliberately to assert that refusal on any sqlglot
version.
