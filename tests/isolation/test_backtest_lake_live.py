"""The backtest's lake fetch, proven against a real ClickHouse.

The claim is: *a candidate detection can be backtested over historical lake
data before promotion, and it sees only the backtesting tenant's history.*
Everything below exists to make the second half of that provable rather than
asserted.

Why this test is shaped the way it is
-------------------------------------

``fetch_lake_events`` was the one step of the backtest with no coverage at
all. Its own unit suite says so in its docstring, and the claim-to-gate row
said the live fetch was "exercised by the integration gate" — no gate ran it.
So the three things it does were all unproven against a warehouse:

* ``rewrite_for_tenant`` injects the tenant predicate. This is the only thing
  standing between a backtest and another tenant's history, and this
  repository has a recorded scar exactly here: sqlglot 27 renamed the
  ``SELECT``'s FROM argument key, the rewriter's table walk found nothing, and
  every single-table query came back with no tenant predicate, no allowlist
  check and no table-function ban — reported as success, with every offline
  suite green. A rendered SQL string cannot tell you whether rows crossed.
* the ``window_days`` and ``limit`` clamps bound what a backtest reads. Both
  were checked by substring against a generated string, which is the assertion
  that survives a rewriter that silently drops the clause.
* ``rows_to_events`` maps lake columns onto the event dicts the rule engine
  matches. Asserting that against a hand-written column list is circular, and
  it was: the list named a ``raw_data`` column, ``aisoc.raw_events`` has no
  such column, and the payload expansion the docstring promises had therefore
  never run on a real lake row.

So no part of the chain below is re-implemented here:

* the table is created from ``services/api/clickhouse/001_init.sql``, the DDL
  a deployment actually runs;
* the rows come from ``lake_writer.event_to_row``, the only function in
  production that writes to ``aisoc.raw_events``;
* the read is the production ``fetch_lake_events``, which reaches the real
  rewriter and the real ``execute_lake_query``, settings singleton and all.

Refusing to pass vacuously
--------------------------

A test that reads zero rows and then asserts "no other tenant's rows" passes
trivially, which would make this file worse than nothing. Three guards:

* every seeded row is counted back out of the warehouse before anything is
  asserted about scoping, and the fixture fails if the writer refused an event;
* the *unscoped* form of the very same statement is executed alongside the
  scoped one and asserted to return both tenants, so the scoped result is
  known to be a filter rather than an empty partition;
* ``BACKTEST_LAKE_LIVE_REQUIRED=1`` turns an unreachable warehouse into a
  failure. ``isolation-live.yml`` sets it, so the job cannot go green by
  skipping. Without it the file skips with the host named, the way the rest of
  this directory does, so a local run stays usable.

Every module is loaded by path and unregistered afterwards, because
``services/api``, ``services/agents`` and ``services/fusion`` all package
their code as a top-level ``app`` and only one of them can own that name in
one interpreter. Putting ``services/api`` on ``sys.path`` was tried first and
it works for this file while breaking ``test_route_auth_default_deny.py`` ten
tests later with ``No module named 'app.api.contextual'`` — the API's ``app``
stays cached in ``sys.modules`` and the agents service never gets to load its
own. Each file in ``isolation-live.yml`` is its own pytest invocation, so CI
would not have shown it; ``pytest tests/isolation`` would.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import os
import re
import sys
import types
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API_ROOT = REPO_ROOT / "services" / "api"

#: Parent packages the dotted names below need to resolve through. Created as
#: empty modules only when the name is free, and handed back afterwards.
API_PACKAGES: tuple[str, ...] = ("app", "app.core", "app.db", "app.services")

#: Every module the call under test reaches, in dependency order, under the
#: real dotted name so the ``from app...`` statements inside them resolve.
#: ``fetch_lake_events`` imports two of these *inside* the function body, so
#: they have to stay registered while the call runs, not just while it loads.
API_MODULES: tuple[tuple[str, str], ...] = (
    ("app.core.config", "app/core/config.py"),
    ("app.services.rule_engine", "app/services/rule_engine.py"),
    ("app.services.lake_sql", "app/services/lake_sql.py"),
    ("app.db.clickhouse", "app/db/clickhouse.py"),
    ("app.services.backtest", "app/services/backtest.py"),
)

# `ISOLATION_*` is what `isolation-live.yml` sets, so this file behaves like
# the rest of the directory in CI; the unprefixed names are the local
# fallback. Chained `or` with the default last so a variable set to the empty
# string falls through rather than reaching `int("")`.
CLICKHOUSE_HOST = os.getenv("ISOLATION_CLICKHOUSE_HOST") or os.getenv("CLICKHOUSE_HOST") or "localhost"
CLICKHOUSE_PORT = int(os.getenv("ISOLATION_CLICKHOUSE_PORT") or os.getenv("CLICKHOUSE_PORT") or "9000")

# `app.core.config` builds its settings singleton at import, and
# `app.db.clickhouse` reads `settings.CLICKHOUSE_HOST` from it to construct the
# client. That import happens inside the call under test, so the environment
# has to be right before any test runs rather than before a particular one.
# Set unconditionally: pydantic-settings ranks the environment above its
# `.env` file, so this is what the production client will dial.
os.environ["CLICKHOUSE_HOST"] = CLICKHOUSE_HOST
os.environ["CLICKHOUSE_PORT"] = str(CLICKHOUSE_PORT)

#: When set, an unreachable warehouse fails instead of skipping. This is the
#: difference between a job that proves the fetch and a job that reports
#: success having run nothing.
REQUIRED = os.getenv("BACKTEST_LAKE_LIVE_REQUIRED", "").strip() not in ("", "0", "false")

# Two tenants. Tenant-scoping is a statement about the pair, so neither is
# meaningful alone: A's rows must come back and B's must not, and B must hold
# rows at every window A is read at or its absence proves nothing.
TENANT_A = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000ba01")
TENANT_B = uuid.UUID("bbbbbbbb-0000-4000-8000-00000000ba02")

CONNECTOR = "aws_cloudtrail"
OTHER_CONNECTOR = "okta_system_log"

# Ages chosen against the two clamps `build_backtest_sql` applies. The 200-day
# row sits between the default window and the 365-day ceiling; the 400-day row
# sits beyond it. A request for 9999 days therefore has one row that proves the
# clamp bit (the 400-day row must not come back) and one that proves it did not
# over-clamp (the 200-day row must), which is not observable in a rendered
# string. Hours rather than a whole day for the freshest rows, so a 1-day
# window is not asserted against its own boundary.
AGE_FRESH = timedelta(hours=2)
AGE_RECENT = timedelta(days=2)
AGE_MID = timedelta(days=200)
AGE_ANCIENT = timedelta(days=400)

#: ``(label, tenant, age, connector)``. The label is written to ``user_name``
#: so every assertion below can name the rows it expects instead of counting
#: them. Three fresh rows for A so a limit below the available row count is
#: testable against real data.
SEED: tuple[tuple[str, uuid.UUID, timedelta, str], ...] = (
    ("a-fresh-1", TENANT_A, AGE_FRESH, CONNECTOR),
    ("a-fresh-2", TENANT_A, AGE_FRESH, CONNECTOR),
    ("a-fresh-3", TENANT_A, AGE_FRESH, CONNECTOR),
    ("a-okta-fresh", TENANT_A, AGE_FRESH, OTHER_CONNECTOR),
    ("a-recent", TENANT_A, AGE_RECENT, CONNECTOR),
    ("a-mid", TENANT_A, AGE_MID, CONNECTOR),
    ("a-ancient", TENANT_A, AGE_ANCIENT, CONNECTOR),
    ("b-fresh", TENANT_B, AGE_FRESH, CONNECTOR),
    ("b-recent", TENANT_B, AGE_RECENT, CONNECTOR),
    ("b-mid", TENANT_B, AGE_MID, CONNECTOR),
    ("b-ancient", TENANT_B, AGE_ANCIENT, CONNECTOR),
)

A_LABELS = frozenset(label for label, tenant, _age, _conn in SEED if tenant == TENANT_A)
B_LABELS = frozenset(label for label, tenant, _age, _conn in SEED if tenant == TENANT_B)

# What each window must return for tenant A, derived from SEED rather than
# typed out, so adding a row cannot leave an expectation stale.
WITHIN_1_DAY = frozenset(label for label, t, age, _c in SEED if t == TENANT_A and age < timedelta(days=1))
WITHIN_30_DAYS = frozenset(label for label, t, age, _c in SEED if t == TENANT_A and age < timedelta(days=30))
WITHIN_365_DAYS = frozenset(label for label, t, age, _c in SEED if t == TENANT_A and age < timedelta(days=365))

# A marker only reachable by expanding the JSON payload column. It is not any
# column of `aisoc.raw_events`, so a rule matching it can only fire if
# `rows_to_events` expanded the payload the writer stored.
PAYLOAD_EVENT_NAME = "ConsoleLogin"
PAYLOAD_MARKER_FIELD = "eventName"


def _load_by_path(rel: str, alias: str) -> Any:
    """Import one module by file path, leaving ``sys.modules`` as it found it.

    Registered before ``exec_module`` because ``@dataclass`` resolves
    annotations through ``sys.modules``, and removed afterwards because a
    synthetic name left behind has previously broken unrelated tests in this
    repository while every test in its own file passed.
    """
    spec = importlib.util.spec_from_file_location(alias, REPO_ROOT / rel)
    if spec is None or spec.loader is None:  # pragma: no cover - path is fixed
        raise RuntimeError(f"cannot load {rel}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(alias, None)
    return module


def _raw_events_ddl() -> str:
    """The production DDL for ``aisoc.raw_events``, read from the file.

    The match runs to the ``ORDER BY`` clause, so the engine, the partition
    key and every column type come from the deployed schema while the ``TTL``
    and ``SETTINGS`` tails do not. That is load-bearing rather than
    incidental: the shipped table drops rows 90 days past ``event_time``, and
    two of the rows below are deliberately older than that because they are
    what the window clamps are measured against. ``INDEX`` clauses are dropped
    too — bloom filters change the plan, never the result.
    """
    sql = (REPO_ROOT / "services/api/clickhouse/001_init.sql").read_text(encoding="utf-8")
    match = re.search(r"(CREATE TABLE IF NOT EXISTS aisoc\.raw_events.*?ORDER BY \([^)]*\))", sql, re.DOTALL)
    assert match, "could not find the raw_events DDL; this test must not invent one"
    body = match.group(1)
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith(("INDEX ", "--")))


def _ocsf_event(*, label: str, tenant: uuid.UUID, age: timedelta, connector: str) -> dict[str, Any]:
    """One normalized OCSF event, shaped the way ``services/ingest`` emits one.

    The nesting is the point. The writer reads ``actor.user.name``,
    ``metadata.product.name`` and ``raw_data`` from these positions, and a
    pre-flattened fixture would pass here while production wrote empty
    columns.
    """
    when = datetime.now(UTC) - age
    return {
        "id": str(uuid.uuid4()),
        "tenant_id": str(tenant),
        "connector_type": connector,
        "ocsf_event": {
            "class_uid": 3002,
            "category_uid": 3,
            "severity_id": 3,
            "severity": "medium",
            "time": when.isoformat().replace("+00:00", "Z"),
            "src_endpoint": {"ip": "203.0.113.10", "port": 44321},
            "dst_endpoint": {"ip": "198.51.100.20", "port": 443, "hostname": "console.example.invalid"},
            "device": {"name": "host-01"},
            # The label rides in `user_name`, which is an ordinary indexed
            # column, so naming rows costs the test nothing structural.
            "actor": {"user": {"name": label}},
            "process": {"name": "curl"},
            "metadata": {"product": {"name": connector}},
            # Stored by the writer into the column it calls `raw_payload`.
            "raw_data": f'{{"{PAYLOAD_MARKER_FIELD}": "{PAYLOAD_EVENT_NAME}", "label": "{label}"}}',
        },
    }


def _unavailable(detail: str) -> NoReturn:
    """Name what is missing, and decide whether missing is allowed.

    One helper so the skip reason and the required-mode failure can never
    drift apart or describe different things.
    """
    if REQUIRED:
        pytest.fail(f"BACKTEST_LAKE_LIVE_REQUIRED is set and {detail}")
    pytest.skip(detail)


@pytest.fixture(scope="module")
def clickhouse_client() -> Any:
    """A live warehouse, or a named skip — never a silent one.

    The driver is probed with ``find_spec`` and then imported
    unconditionally, rather than imported inside a ``try``. Both forms work;
    this one also keeps the binding provably defined on the path that uses
    it, which the ``try`` form did not — ``pytest.skip`` ends the test but is
    not a return, so static analysis read the client construction below as
    reachable with the module unbound.
    """
    if importlib.util.find_spec("clickhouse_driver") is None:  # pragma: no cover - environment-specific
        _unavailable("clickhouse-driver is not installed")

    import clickhouse_driver  # noqa: PLC0415 - soft dependency, probed on the line above

    try:
        client = clickhouse_driver.Client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            user=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            connect_timeout=5,
        )
        client.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - absence is a skip unless the job requires the store
        _unavailable(f"no ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT} ({type(exc).__name__}: {exc})")
        raise exc from None  # unreachable: `_unavailable` always raises
    return client


@pytest.fixture(scope="module")
def seeded_lake(clickhouse_client: Any, api_modules: Any) -> Any:
    """A real lake holding rows the production writer produced.

    Both tenants are seeded at every age, so a scoped read of A can be
    compared against an unscoped read that sees B.

    Every test that reads the lake requests this, which is how they all get
    ``api_modules`` without it having to be autouse.
    """
    lake_writer = _load_by_path("services/fusion/app/services/lake_writer.py", "_aisoc_backtest_lake_writer")

    client = clickhouse_client
    client.execute("CREATE DATABASE IF NOT EXISTS aisoc")
    client.execute("DROP TABLE IF EXISTS aisoc.raw_events")
    client.execute(_raw_events_ddl())

    rows = []
    for label, tenant, age, connector in SEED:
        message = _ocsf_event(label=label, tenant=tenant, age=age, connector=connector)
        row = lake_writer.event_to_row(message)
        assert row is not None, f"the production writer refused {label}, an event this test must be able to record"
        out = {k: v for k, v in row.items() if not (k == "event_id" and v is None)}
        # The columns are `IPv6`; the writer keeps them as strings in the row
        # dict and converts at insert time, so the test converts the same way
        # rather than inventing a second representation.
        out["source_ip"] = lake_writer._to_ip_obj(row["source_ip"])
        out["dest_ip"] = lake_writer._to_ip_obj(row["dest_ip"])
        rows.append(out)

    client.execute(lake_writer._INSERT_SQL, rows, types_check=True)

    # Nothing below is allowed to run until the warehouse is known to hold
    # what was seeded. A ReplacingMergeTree collapsing rows, a TTL eating the
    # old ones or a writer returning a row the driver rejects would otherwise
    # surface as a scoping assertion that passes on an empty table.
    stored = client.execute("SELECT count() FROM aisoc.raw_events")[0][0]
    assert stored == len(SEED), f"seeded {len(SEED)} rows but the warehouse holds {stored}; every assertion below would be vacuous"

    yield client
    client.execute("DROP TABLE IF EXISTS aisoc.raw_events")


@pytest.fixture(scope="module")
def api_modules(clickhouse_client: Any) -> Any:
    """Register the API service's ``app`` tree, then hand the name back.

    Module-scoped because the two lazy imports inside ``fetch_lake_events``
    resolve at call time, so the registration has to outlive module import and
    still be gone before the next file runs. Names that were already taken are
    saved and restored rather than overwritten, so this works whichever
    service loaded ``app`` first.

    It takes ``clickhouse_client`` so the skip is decided before any of this
    is imported. ``isolation.yml`` runs this whole directory offline with only
    ``qdrant-client structlog pytest pytest-asyncio`` installed, and an
    autouse version of this fixture turned that job's clean skip into
    ``ModuleNotFoundError: No module named 'pydantic_settings'`` on thirteen
    tests — a live-store test has to be absent-tolerant in the same job the
    rest of the directory is.
    """
    installed: list[str] = []
    saved = {name: sys.modules[name] for name, _rel in API_MODULES if name in sys.modules}
    try:
        for package in API_PACKAGES:
            if package not in sys.modules:
                sys.modules[package] = types.ModuleType(package)
                installed.append(package)
        for dotted, rel in API_MODULES:
            spec = importlib.util.spec_from_file_location(dotted, API_ROOT / rel)
            if spec is None or spec.loader is None:  # pragma: no cover - paths are fixed
                raise RuntimeError(f"cannot load {rel}")
            module = importlib.util.module_from_spec(spec)
            # Registered before exec so the from-imports inside each module
            # find their siblings, and so `@dataclass` can resolve annotations.
            sys.modules[dotted] = module
            installed.append(dotted)
            try:
                spec.loader.exec_module(module)
            except ImportError as exc:
                # A dependency of the service, not of the test. Named either
                # way: skipped where the warehouse is optional, failed where
                # the job declares it is not.
                _unavailable(f"{rel} needs a dependency this environment lacks ({exc})")
        yield sys.modules["app.services.backtest"]
    finally:
        for name in reversed(installed):
            sys.modules.pop(name, None)
        sys.modules.update(saved)


def _backtest() -> Any:
    """The production backtest module, as ``api_modules`` registered it."""
    return sys.modules["app.services.backtest"]


def _fetch(tenant: uuid.UUID, *, window_days: int, limit: int, source: str | None = None) -> list[dict[str, Any]]:
    """Call the real ``fetch_lake_events`` and return what it returned.

    Driven with ``asyncio.run`` rather than an async test so this file needs
    no pytest-asyncio mode to be configured for it. The ClickHouse client is a
    module-level singleton that only the first call constructs, so a fresh
    loop per call does not re-enter the lock that guards it.
    """
    return asyncio.run(_backtest().fetch_lake_events(tenant, window_days=window_days, limit=limit, source=source))


def _labels(events: list[dict[str, Any]]) -> set[str]:
    return {str(event.get("user_name")) for event in events}


def _unscoped(client: Any, *, window_days: int, limit: int, source: str | None = None) -> set[str]:
    """The same statement the fetch builds, run without the tenant rewrite.

    This is the control. It proves the rows the scoped read declined to return
    were sitting in the table, reachable by the identical query, which is the
    only way "zero rows from the other tenant" means anything.
    """
    sql = _backtest().build_backtest_sql(window_days=window_days, limit=limit, source=source)
    columns = [name for name, _type in client.execute(sql, with_column_types=True)[1]]
    rows = client.execute(sql)
    return {str(dict(zip(columns, row, strict=False)).get("user_name")) for row in rows}


# --------------------------------------------------------------------------
# The warehouse really holds both tenants' history
# --------------------------------------------------------------------------


def test_both_tenants_have_recorded_rows_so_a_scoped_read_can_be_a_filter(seeded_lake: Any) -> None:
    """Without this, every assertion about scoping below is vacuous."""
    counts = dict(seeded_lake.execute("SELECT tenant_id, count() FROM aisoc.raw_events GROUP BY tenant_id"))
    by_tenant = {str(tenant): count for tenant, count in counts.items()}
    assert by_tenant.get(str(TENANT_A)) == len(A_LABELS)
    assert by_tenant.get(str(TENANT_B)) == len(B_LABELS)
    assert len(A_LABELS) > 0 and len(B_LABELS) > 0


def test_the_unscoped_statement_reaches_both_tenants(seeded_lake: Any) -> None:
    """The control for the scoping test, asserted rather than assumed.

    The backtest's own generated SQL, executed with no tenant predicate,
    returns rows from both tenants. Everything the scoped read excludes was
    therefore excluded by the rewriter and not by the data.
    """
    reachable = _unscoped(seeded_lake, window_days=365, limit=1000)
    assert WITHIN_365_DAYS <= reachable, "the generated statement cannot see tenant A's own rows"
    assert B_LABELS & reachable, "the generated statement cannot see tenant B, so scoping it proves nothing"


# --------------------------------------------------------------------------
# The property: a backtest reads one tenant's history
# --------------------------------------------------------------------------


def test_the_fetch_returns_the_requesting_tenants_rows_and_none_of_the_others(seeded_lake: Any) -> None:
    """The reason ``rewrite_for_tenant`` is on this path.

    Run as A against a warehouse that holds B. A wrong predicate, a predicate
    the rewriter dropped, or an AST rename that turned the table walk into a
    no-op all fail here — which is what no offline assertion about the
    rendered string could do.
    """
    events = _fetch(TENANT_A, window_days=30, limit=1000)

    assert events, "the fetch returned nothing; a no-rows result cannot demonstrate scoping"
    assert _labels(events) == set(WITHIN_30_DAYS)
    # Asserted on the column as well as on the labels: the label is this
    # test's own convention, `tenant_id` is the isolation key itself.
    assert {str(event["tenant_id"]) for event in events} == {str(TENANT_A)}
    assert not (_labels(events) & B_LABELS), f"tenant B leaked into A's backtest: {sorted(_labels(events) & B_LABELS)}"


def test_the_other_tenant_reads_its_own_history_through_the_same_call(seeded_lake: Any) -> None:
    """Scoping must be a filter on the caller, not a filter to one tenant.

    A rewriter hard-wired to A would pass the test above and fail here.
    """
    events = _fetch(TENANT_B, window_days=30, limit=1000)

    assert events
    assert {str(event["tenant_id"]) for event in events} == {str(TENANT_B)}
    assert not (_labels(events) & A_LABELS)


def test_a_tenant_with_no_history_reads_nothing_rather_than_everything(seeded_lake: Any) -> None:
    """The fail-open shape, stated as its own assertion.

    An unscoped query returns every row for every caller, so the tenant with
    no rows is the one that most clearly distinguishes a working predicate
    from a missing one.
    """
    stranger = uuid.UUID("cccccccc-0000-4000-8000-00000000ba03")
    assert _fetch(stranger, window_days=365, limit=1000) == []


# --------------------------------------------------------------------------
# The clamps, measured against recorded rows
# --------------------------------------------------------------------------


def test_the_window_ceiling_holds_against_a_row_older_than_the_ceiling(seeded_lake: Any) -> None:
    """``window_days`` is clamped to 365, proven by a 400-day-old row.

    The precondition is asserted first: the row is in the table and the
    identical unscoped statement can reach it at a wide enough window. So its
    absence from the result is the clamp, not the seed.
    """
    reachable = _unscoped(seeded_lake, window_days=365, limit=1000)
    assert "a-ancient" not in reachable, "the 400-day row is inside a 365-day window; the ages in SEED are wrong"
    stored = seeded_lake.execute("SELECT count() FROM aisoc.raw_events WHERE user_name = 'a-ancient'")[0][0]
    assert stored == 1, "the row the ceiling is measured against is not in the warehouse"

    events = _fetch(TENANT_A, window_days=9999, limit=1000)

    assert _labels(events) == set(WITHIN_365_DAYS)
    assert "a-ancient" not in _labels(events), "window_days was not clamped: a row 400 days old came back"
    # And the clamp did not over-clamp: the 200-day row is outside the default
    # window and inside the ceiling, so it distinguishes 365 from 30.
    assert "a-mid" in _labels(events), "window_days clamped below its documented 365-day ceiling"


def test_the_window_floor_holds_against_a_two_day_old_row(seeded_lake: Any) -> None:
    """``window_days`` is clamped up to 1, so 0 is a one-day window."""
    events = _fetch(TENANT_A, window_days=0, limit=1000)

    assert _labels(events) == set(WITHIN_1_DAY)
    assert "a-recent" not in _labels(events), "a 2-day-old row came back from a window clamped to 1 day"
    assert events, "the floor clamped to zero days rather than to one"


def test_the_limit_bounds_the_rows_that_come_back(seeded_lake: Any) -> None:
    """``limit`` is honoured against real rows, not just rendered into SQL."""
    available = _fetch(TENANT_A, window_days=9999, limit=1000)
    assert len(available) > 2, "the limit assertion needs more available rows than the limit it applies"

    capped = _fetch(TENANT_A, window_days=9999, limit=2)
    assert len(capped) == 2, f"limit=2 returned {len(capped)} rows"
    # Still one tenant's rows: the limit must not be the only thing bounding
    # the result. A row cap on an unscoped query returns other tenants' rows.
    assert {str(event["tenant_id"]) for event in capped} == {str(TENANT_A)}
    # ORDER BY event_time DESC, so a cap takes the newest rows.
    assert _labels(capped) <= set(WITHIN_1_DAY)


def test_the_limit_floor_returns_one_row_rather_than_none(seeded_lake: Any) -> None:
    """``limit`` is clamped up to 1, so 0 is not "no rows"."""
    events = _fetch(TENANT_A, window_days=9999, limit=0)
    assert len(events) == 1
    assert str(events[0]["tenant_id"]) == str(TENANT_A)


# --------------------------------------------------------------------------
# The source filter and the column mapping
# --------------------------------------------------------------------------


def test_the_source_filter_selects_by_connector_against_recorded_rows(seeded_lake: Any) -> None:
    """The filter names a real column holding a real value.

    ``connector_type`` is written by the writer from ``metadata.product.name``,
    so a filter built against a different spelling returns nothing here rather
    than passing as a substring of generated SQL.
    """
    only_okta = _fetch(TENANT_A, window_days=30, limit=1000, source=OTHER_CONNECTOR)
    assert _labels(only_okta) == {"a-okta-fresh"}

    only_cloudtrail = _fetch(TENANT_A, window_days=30, limit=1000, source=CONNECTOR)
    assert _labels(only_cloudtrail) == set(WITHIN_30_DAYS) - {"a-okta-fresh"}
    assert only_cloudtrail, "the connector every seeded row carries matched nothing"

    # A sanitised-away source must not silently widen to every connector.
    assert _labels(_fetch(TENANT_A, window_days=30, limit=1000, source="!!!")) == set(WITHIN_30_DAYS)


def test_the_lake_payload_column_is_expanded_so_flat_field_rules_can_match(seeded_lake: Any) -> None:
    """``rows_to_events`` must expand the payload column the lake actually has.

    The writer stores the OCSF ``raw_data`` field into a column it names
    ``raw_payload``, and ``aisoc.raw_events`` has no ``raw_data`` column at
    all. The expansion list named only the OCSF-side spellings, so on a real
    lake row it expanded nothing and every rule matching a connector-flat
    field scanned events that did not carry it. The unit test could not see
    this because it supplied its own column list, and the list named a column
    the warehouse does not have.
    """
    events = _fetch(TENANT_A, window_days=30, limit=1000)
    assert events

    columns_from_the_warehouse = set(events[0])
    assert "raw_payload" in columns_from_the_warehouse, "the lake stopped returning the payload column this asserts about"
    assert "raw_data" not in columns_from_the_warehouse, "aisoc.raw_events grew a raw_data column; the expansion list should follow"

    fresh = next(event for event in events if event["user_name"] == "a-fresh-1")
    assert fresh.get(PAYLOAD_MARKER_FIELD) == PAYLOAD_EVENT_NAME, (
        f"{PAYLOAD_MARKER_FIELD!r} is not a column of aisoc.raw_events, so it can only be present if the "
        f"payload column was expanded. It was not, which means a rule matching a connector-flat field "
        f"cannot fire in a backtest."
    )
    # The expansion must not cost the OCSF columns beside it.
    assert fresh["connector_type"] == CONNECTOR
    assert str(fresh["tenant_id"]) == str(TENANT_A)


def test_an_expanded_payload_does_not_carry_another_tenants_row(seeded_lake: Any) -> None:
    """Expansion happens after scoping, so it cannot reintroduce B.

    Stated separately because the expansion merges attacker-influenced keys
    over the OCSF columns, and ``tenant_id`` is one of the keys it could
    overwrite.
    """
    events = _fetch(TENANT_A, window_days=9999, limit=1000)
    assert {event["label"] for event in events} == set(WITHIN_365_DAYS)
    assert not ({event["label"] for event in events} & B_LABELS)


# --------------------------------------------------------------------------
# One implementation, so this proof covers both backtest endpoints
# --------------------------------------------------------------------------


def _lake_fetch_definitions() -> dict[str, list[str]]:
    """Every ``*fetch_lake_events`` definition in the API service, by file.

    Read off the syntax tree rather than imported, because the endpoint
    modules pull in FastAPI and SQLAlchemy and this job installs neither. The
    direction matters: the check asks the tree what exists, so a second copy
    reappearing is what fails it.
    """
    found: dict[str, list[str]] = {}
    for path in sorted((REPO_ROOT / "services/api/app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name.endswith("fetch_lake_events")
        ]
        if names:
            found[path.relative_to(REPO_ROOT).as_posix()] = names
    return found


def test_one_lake_fetch_serves_every_backtest_endpoint() -> None:
    """The duplicate this file was written to cover, held deleted.

    ``detection_rules.py`` carried its own near-identical ``_fetch_lake_events``
    with its own inline rewriter and ``execute_lake_query`` call, so the
    tenant-scoping path existed twice and neither copy was covered. Proving
    one implementation and letting both endpoints import it is what makes the
    live proof above cover the rule endpoint as well as the proposal one — so
    a copy coming back has to fail rather than quietly go unproven.
    """
    definitions = _lake_fetch_definitions()
    assert definitions == {"services/api/app/services/backtest.py": ["fetch_lake_events"]}, (
        f"expected exactly one lake-fetch implementation; found {definitions}. "
        f"A second copy is a second tenant-scoping path, and this file only proves one."
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "services/api/app/api/v1/endpoints/detection_rules.py",
        "services/api/app/api/v1/endpoints/detection_proposals.py",
    ],
)
def test_each_backtest_endpoint_imports_the_shared_fetch(endpoint: str) -> None:
    """Named per endpoint, so a failure says which one stopped sharing."""
    tree = ast.parse((REPO_ROOT / endpoint).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "app.services.backtest"
        for alias in node.names
    }
    assert "fetch_lake_events" in imported, f"{endpoint} does not import the shared lake fetch; it has its own path again"
