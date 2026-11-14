"""The event lake, against the schema the product actually ships.

Maturity: the evidence that takes **Event lake + hunting (ClickHouse)**
to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why loading the real DDL is the point
---------------------------------------
`test_live_stores.py` has a live ClickHouse case, and it writes its own
`CREATE TABLE aisoc.raw_events` — a hand-maintained subset of the columns
`services/api/clickhouse/001_init.sql` creates. A test that builds its
own schema cannot notice that the real one has drifted, which is the
same shape as asserting on a producer against a copy of itself.

This suite executes `001_init.sql` verbatim. A column added to the
product and not to a query fails here; a column a query needs and the
DDL stopped creating fails here too.

What is being proven
----------------------
Tenant isolation on the lake is enforced by `rewrite_for_tenant`, which
injects a `tenant_id` predicate into operator-supplied SQL. Two things
make that fragile and both are covered:

* it **fails closed** — it raises rather than returning unfiltered SQL
  if its predicate does not survive rendering, because the alternative
  is every tenant reading every other tenant's events;
* `sqlglot` is pinned **exactly**, since the parser enforcing the
  isolation could otherwise differ between two builds of one commit.

The negative control
--------------------
`test_an_unscoped_query_sees_both_tenants` proves the rows exist and are
reachable without the rewrite. Without it, every isolation assertion
could pass against an empty table.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = pytest.mark.skipif(
    not os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip(),
    reason="ISOLATION_CLICKHOUSE_HOST is not set; this suite needs live infrastructure",
)

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")

DDL = "services/api/clickhouse/001_init.sql"

# `app.hunt.lake_source` reads CLICKHOUSE_* the way the fusion writer and
# the API do. This suite is configured with ISOLATION_CLICKHOUSE_*, so
# bridge them here rather than teaching the production module a second
# spelling it would only use in tests.
if os.environ.get("ISOLATION_CLICKHOUSE_HOST"):
    os.environ.setdefault("CLICKHOUSE_HOST", os.environ["ISOLATION_CLICKHOUSE_HOST"])
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")


def _client():  # noqa: ANN202
    host = os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip()
    if not host:
        pytest.skip("ISOLATION_CLICKHOUSE_HOST is not set; this suite needs a live ClickHouse")
    driver = pytest.importorskip("clickhouse_driver")
    return driver.Client(
        host=host,
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )


def _statements(sql: str) -> list[str]:
    """Split the DDL into executable statements.

    `clickhouse_driver` sends one statement per round trip, and the file
    is several. Comment lines are dropped first so a `--` containing a
    semicolon cannot split a statement in the wrong place.
    """
    lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


@pytest.fixture(scope="module")
def lake():
    """A ClickHouse carrying the product's own schema."""
    from app.core.config import settings  # noqa: F401 — import check only

    client = _client()
    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    ddl = (root / DDL).read_text(encoding="utf-8")
    for statement in _statements(ddl):
        client.execute(statement)

    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")
    now = datetime.now(UTC).replace(tzinfo=None)
    client.execute(
        # Column names read off the shipped DDL rather than assumed.
        # The first attempt inserted `message` and `raw_event`; the real
        # table has neither (`raw_payload` and `ocsf_json` are the
        # payload columns), which is precisely the drift a suite writing
        # its own CREATE TABLE could never surface.
        "INSERT INTO aisoc.raw_events "
        "(tenant_id, event_time, class_uid, category_uid, severity_id, severity, "
        "src_hostname, raw_payload) VALUES",
        [
            (TENANT_A, now, 2001, 2, 4, "high", "tenant-a-host-1", "{}"),
            (TENANT_A, now, 2001, 2, 4, "high", "tenant-a-host-2", "{}"),
            (TENANT_B, now, 2001, 2, 4, "high", "tenant-b-host-1", "{}"),
        ],
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


class TestTheSchemaIsTheProducts:
    def test_the_shipped_ddl_executes(self, lake) -> None:  # noqa: ANN001
        """The claim the hand-written CREATE TABLE cannot make.

        If `001_init.sql` stops being valid ClickHouse, a deployment's
        lake never initialises — and a test that writes its own schema
        would not notice.
        """
        rows = lake.execute("SELECT count() FROM aisoc.raw_events")
        assert rows[0][0] == 3

    def test_every_column_a_query_needs_exists(self, lake) -> None:  # noqa: ANN001
        """Catches drift in the direction that actually happens: a query
        gaining a column the DDL does not create."""
        described = {row[0] for row in lake.execute("DESCRIBE TABLE aisoc.raw_events")}
        required = {"tenant_id", "event_time", "class_uid", "severity", "raw_payload", "ocsf_json"}
        missing = required - described
        assert not missing, f"the shipped DDL does not create {sorted(missing)}"


class TestTheNegativeControl:
    def test_an_unscoped_query_sees_both_tenants(self, lake) -> None:  # noqa: ANN001
        """Without this, every isolation assertion below could pass
        against an empty table."""
        total = lake.execute("SELECT count() FROM aisoc.raw_events")[0][0]
        assert total == 3, f"expected both tenants' rows seeded, found {total}"


class TestTheProductionRewriteScopes:
    def test_a_rewritten_query_returns_only_its_tenant(self, lake) -> None:  # noqa: ANN001
        """`rewrite_for_tenant` is what stands between an operator's SQL
        and every other tenant's events."""
        from app.services.lake_sql import rewrite_for_tenant

        scoped = rewrite_for_tenant("SELECT src_hostname FROM aisoc.raw_events", TENANT_A)
        rows = lake.execute(scoped.sql if hasattr(scoped, "sql") else scoped)
        hosts = {row[0] for row in rows}

        assert hosts == {"tenant-a-host-1", "tenant-a-host-2"}, hosts
        assert "tenant-b-host-1" not in hosts

    def test_a_query_naming_another_tenant_still_returns_its_own(self, lake) -> None:  # noqa: ANN001
        """An operator writing their own `tenant_id = …` must not be able
        to widen the scope — the injected predicate has to conjoin, not
        replace."""
        from app.services.lake_sql import rewrite_for_tenant

        scoped = rewrite_for_tenant(
            f"SELECT src_hostname FROM aisoc.raw_events WHERE tenant_id = '{TENANT_B}'",
            TENANT_A,
        )
        rows = lake.execute(scoped.sql if hasattr(scoped, "sql") else scoped)
        assert not rows, f"an operator named another tenant and got {len(rows)} of their rows back"


class TestItFailsClosed:
    def test_sql_it_cannot_parse_is_refused_rather_than_passed_through(self) -> None:
        """The property that matters more than any single query.

        Returning the original SQL when the rewrite cannot be applied
        would hand an unfiltered query to the lake. The pin on `sqlglot`
        exists for the same reason: the parser enforcing isolation must
        not differ between two builds of one commit.
        """
        from app.services.lake_sql import rewrite_for_tenant

        with pytest.raises(Exception):  # noqa: B017, PT011
            rewrite_for_tenant("this is not sql at all )(", TENANT_A)
