"""Tenant-lake SQL rewriter (Workstream 7).

The tenant-lake API exposes ClickHouse to operators and to the agent
runtime via ``POST /api/v1/lake/sql``. The threat model assumes the
caller can craft *any* SQL string they like — including statements that
probe other tenants' data, mutate the warehouse, hit ClickHouse table
functions like ``url(...)`` to exfiltrate rows, or burn unbounded
resources.

This module is the policy layer that sits in front of ClickHouse:

    untrusted SQL  ─►  parse with sqlglot
                       └─► reject anything that isn't a single SELECT/CTE
                       └─► reject any non-allowlisted table reference
                       └─► reject ClickHouse table functions
                            (url, remote, s3, file, mysql, postgresql, …)
                       └─► inject  tenant_id = '<uuid>'  into every
                            SELECT (top-level + every subquery + every CTE)
                       └─► clamp LIMIT to the configured cap
    ──────────────►  rewritten SQL forwarded to ClickHouse

Why parser-level rewriting:

* ``tenant_id`` lives in ``WHERE`` clauses, not in the parameter
  position. ClickHouse parameter substitution (``%(name)s``) handles
  literal values but it can't add a missing predicate.
* A single regex can't cope with subqueries, CTEs, joins, aliases, or
  the fact that the lake schema has *three* tables that all carry
  ``tenant_id``. Walking the parse tree handles all of those uniformly.
* sqlglot speaks ClickHouse dialect, so parsing succeeds for
  ``DateTime64``, ``Array(String)``, ``ASOF JOIN`` and the other
  ClickHouse-isms our schema uses.

This rewriter is exercised by ``tests/test_lake_sql.py`` which is the
authoritative spec — every change in this file must keep those tests
green and ideally extend them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final

import sqlglot
from sqlglot import exp

# ----------------------------------------------------------- public surface


# Tables agents and operators may query directly. Anything else — including
# system tables, temporary tables, CSV-injected URLs, and the ``aisoc`` config
# tables that live in Postgres — is denied at parse time.
ALLOWED_TABLES: Final[frozenset[str]] = frozenset(
    {
        "aisoc.raw_events",
        "aisoc.alert_metrics",
        "aisoc.ioc_enrichments",
    }
)

# Default schema (ClickHouse database) we resolve unqualified ``FROM <name>``
# references against. Lets agents write ``FROM raw_events`` for terseness.
DEFAULT_SCHEMA: Final[str] = "aisoc"

# Default max rows the rewriter will let a query return. Keeps a pathological
# ``SELECT *`` from raw_events from blowing up the agent's context window or
# starving ClickHouse memory.
DEFAULT_ROW_CAP: Final[int] = 10_000

# Hard ceiling regardless of caller-supplied ``limit`` — prevents privileged
# callers from accidentally requesting a million rows.
MAX_ROW_CAP: Final[int] = 100_000

# DML/DDL roots that are unambiguously forbidden (vs. parser-level garbage).
# We map these to ``LakeSqlForbiddenError`` so the API can return 403 rather
# than 400 — the caller wrote real SQL, just not SQL we'll execute.
#
# Why ``exp.Kill`` is here as well as ``exp.Command``:  sqlglot parses
# ClickHouse ``KILL QUERY 'id'`` into a dedicated :class:`exp.Kill` node
# rather than the generic :class:`exp.Command` fallback.  Without listing
# it explicitly the rewriter would route it to the syntax-error branch
# (since Kill is not a Select/Union/With), which would mask a real
# privilege-escalation attempt as a "typo" in the operator UI.  See
# ``test_clickhouse_admin_commands_rejected`` in tests/test_lake_sql.py.
_FORBIDDEN_ROOTS: Final[tuple[type[exp.Expression], ...]] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.TruncateTable,
    exp.Merge,
    exp.Kill,  # KILL QUERY / KILL MUTATION
    exp.Command,  # ClickHouse SYSTEM, OPTIMIZE, and other admin verbs
)


class LakeSqlError(ValueError):
    """Raised when a query violates lake policy."""


class LakeSqlSyntaxError(LakeSqlError):
    """The supplied SQL didn't parse as ClickHouse, or parsed as garbage."""


class LakeSqlForbiddenError(LakeSqlError):
    """The SQL parsed but violated policy (non-SELECT, bad table, …)."""


@dataclass(frozen=True)
class RewriteResult:
    """Outcome of a successful rewrite.

    Attributes
    ----------
    sql:
        The rewritten ClickHouse SQL, with tenant predicates injected
        and the ``LIMIT`` clause clamped.
    row_cap:
        The effective ``LIMIT`` we ended up applying.
    referenced_tables:
        The set of allowlisted tables actually touched by the query
        (CTE aliases excluded). We surface this for audit logs.
    """

    sql: str
    row_cap: int
    referenced_tables: frozenset[str]


def rewrite_for_tenant(
    sql: str,
    tenant_id: uuid.UUID,
    *,
    row_cap: int | None = None,
) -> RewriteResult:
    """Rewrite ``sql`` so it is safe to forward to ClickHouse.

    Parameters
    ----------
    sql:
        Raw SQL submitted by the caller. Must be a single statement.
    tenant_id:
        Tenant whose data the caller is authorised to see.
    row_cap:
        Optional override for the ``LIMIT`` clamp. Capped at
        :data:`MAX_ROW_CAP`. ``None`` falls back to
        :data:`DEFAULT_ROW_CAP`.

    Raises
    ------
    LakeSqlSyntaxError
        Parsing failed or produced a non-statement (e.g. a bare
        expression).
    LakeSqlForbiddenError
        The statement is forbidden DML/DDL, references multiple
        statements, touches a non-allowlisted table, or invokes a
        ClickHouse table function.
    """
    effective_cap = _resolve_row_cap(row_cap)

    # ── Step 1: parse ──────────────────────────────────────────────────
    # We parse with the clickhouse dialect so constructs like
    # ``Array(String)`` or trailing FORMAT clauses don't trip the parser.
    # ``parse`` (not ``parse_one``) lets us catch the multi-statement
    # attack — a caller sending ``SELECT 1; DROP TABLE x;`` is rejected
    # even though the first statement on its own would have been fine.
    try:
        statements = [stmt for stmt in sqlglot.parse(sql, read="clickhouse") if stmt is not None]
    except sqlglot.errors.ParseError as exc:
        raise LakeSqlSyntaxError(f"unable to parse SQL: {exc}") from exc

    if not statements:
        raise LakeSqlSyntaxError("empty SQL statement")
    if len(statements) > 1:
        raise LakeSqlForbiddenError("only a single statement is allowed per request")

    tree = statements[0]

    # Be generous about pure parenthesised SELECTs — `(SELECT …)` is a
    # SELECT for our purposes.
    root = tree.this if isinstance(tree, exp.Subquery) else tree

    # ── Step 2: classify root ─────────────────────────────────────────
    # Forbidden DML/DDL → 403. Parser-level garbage (NOT, IS, expressions,
    # bare identifiers) → 400. Selects, Unions, and CTEs → continue.
    if isinstance(root, _FORBIDDEN_ROOTS):
        raise LakeSqlForbiddenError(f"only SELECT statements are allowed (got {type(root).__name__.upper()})")

    if not isinstance(root, exp.Select | exp.Union | exp.With):
        raise LakeSqlSyntaxError(f"expected a SELECT / WITH / UNION statement; got {type(root).__name__}")

    # ── Step 3: collect CTE aliases ──────────────────────────────────
    # CTE names are *aliases*, not real tables, so a reference like
    # ``FROM highs`` after ``WITH highs AS (…)`` should not be checked
    # against the allowlist (and gets no predicate — its data is already
    # tenant-filtered inside the CTE body).
    cte_aliases = {cte.alias_or_name for cte in tree.find_all(exp.CTE)}

    # ── Step 4: walk every Select and rewrite ────────────────────────
    referenced: set[str] = set()
    selects = list(tree.find_all(exp.Select))
    if not selects:
        raise LakeSqlSyntaxError("query has no SELECT clause")

    # sqlglot will happily parse the bare token ``SELECT`` (or ``SELECT
    # FROM …``) into a :class:`exp.Select` with no projection expressions.
    # ClickHouse would reject that at execution time, but we'd rather
    # surface it as a 400 here than ship an obviously malformed string
    # to the warehouse and pay a round-trip.  Each Select in the tree
    # (including subqueries) must project at least one column or
    # expression.
    for select in selects:
        if not select.expressions:
            raise LakeSqlSyntaxError("SELECT clause has no projection expressions")

    for select in selects:
        _validate_and_rewrite_select(select, tenant_id, cte_aliases, referenced)

    # ── Step 5: clamp the outer LIMIT ────────────────────────────────
    _clamp_outer_limit(root, effective_cap)

    rewritten = tree.sql(dialect="clickhouse")
    return RewriteResult(
        sql=rewritten,
        row_cap=effective_cap,
        referenced_tables=frozenset(referenced),
    )


# ----------------------------------------------------------- internals


def _resolve_row_cap(row_cap: int | None) -> int:
    """Clamp the row cap into ``[1, MAX_ROW_CAP]``."""
    if row_cap is None:
        return DEFAULT_ROW_CAP
    if row_cap < 1:
        return 1
    if row_cap > MAX_ROW_CAP:
        return MAX_ROW_CAP
    return row_cap


def _validate_and_rewrite_select(
    select: exp.Select,
    tenant_id: uuid.UUID,
    cte_aliases: set[str],
    referenced: set[str],
) -> None:
    """Enforce table policy and inject the tenant predicate on one Select.

    ``select`` is a single ``SELECT`` node (the FROM/JOINs of CTEs and
    nested subqueries surface as their own Select nodes that the caller
    visits separately, so we don't recurse into them here).
    """
    direct_tables = _direct_tables(select)
    if not direct_tables:
        # Selects without a FROM (constant projections like
        # ``SELECT 1 AS hello``) don't touch tenant data — skip.
        return

    # Classify each table reference: real allowlisted table (qualified or
    # unqualified), CTE alias (skip), or anything else (reject).
    real_tables: list[exp.Table] = []
    for table in direct_tables:
        # Reject ClickHouse table functions: url(), file(), remote(),
        # s3(), mysql(), postgresql(), etc. They show up either as Tables
        # whose ``name`` is empty (the function payload sits in the AST
        # subtree) or as Tables whose backing ``this`` is an Anonymous
        # function call.
        if _is_table_function(table):
            raise LakeSqlForbiddenError("ClickHouse table functions are not allowed in lake queries")

        bare_name = table.name
        if not bare_name:
            # Non-function table without a name — degenerate; reject.
            raise LakeSqlForbiddenError("unrecognised table reference in FROM/JOIN")

        # CTE references: allowed, but skipped (no allowlist check, no
        # predicate injection — the CTE body already has its own SELECT
        # and is rewritten on its own visit).
        if not table.db and bare_name in cte_aliases:
            continue

        full = _qualified_name(table)
        if full not in ALLOWED_TABLES:
            raise LakeSqlForbiddenError(f"table '{full}' is not in the lake allowlist")

        # Backfill the schema on unqualified references so the rewritten
        # SQL is unambiguous regardless of the ClickHouse session
        # database.
        if not table.db:
            table.set("db", exp.to_identifier(DEFAULT_SCHEMA))

        referenced.add(full)
        real_tables.append(table)

    if not real_tables:
        # Every direct table was a CTE alias — predicates already applied
        # inside the CTE bodies. Nothing more to do here.
        return

    # ── Inject `tenant_id = '<uuid>'` predicates ──────────────────────
    #
    # When there's a single real table the predicate is unqualified
    # (``tenant_id = '…'``). When there are joins between multiple real
    # tables we emit one predicate per aliased table, AND-combined, so
    # ClickHouse filters each side independently. Tables without aliases
    # in a multi-table join get an unqualified predicate (ClickHouse will
    # pick the unambiguous ``tenant_id`` column).
    tid_lit = f"'{tenant_id}'"
    aliased = [t for t in real_tables if t.alias]
    unaliased_count = len(real_tables) - len(aliased)

    if len(real_tables) == 1:
        # Single table — unqualified predicate is the cleanest output.
        predicate = f"tenant_id = {tid_lit}"
    elif aliased:
        clauses = [f"{t.alias_or_name}.tenant_id = {tid_lit}" for t in aliased]
        if unaliased_count > 0:
            clauses.append(f"tenant_id = {tid_lit}")
        predicate = " AND ".join(clauses)
    else:
        # Multi-table join with no aliases — rare; fall back to a single
        # unqualified predicate. ClickHouse's planner will reject the
        # ambiguity if the join shape demands disambiguation, which is
        # the right surface for the caller to fix.
        predicate = f"tenant_id = {tid_lit}"

    select.where(predicate, append=True, dialect="clickhouse", copy=False)


def _direct_tables(select: exp.Select) -> list[exp.Table]:
    """Return tables referenced by this Select's FROM and JOIN clauses.

    We deliberately skip tables that live inside nested ``Select`` nodes
    (subqueries) — those have their own enclosing Select that the caller
    visits separately, and we don't want to double-inject predicates.

    Uses an explicit tree walk that stops at ``exp.Select`` boundaries
    rather than relying on parent-chain traversal, which is more robust
    across sqlglot versions that may vary in how they set parent attributes.
    """
    out: list[exp.Table] = []

    # sqlglot stores the FROM clause under args["from"]. Using the args
    # dict key is the canonical way to access it regardless of version.
    from_expr = select.args.get("from")
    if from_expr is not None:
        _collect_direct_tables(from_expr, out)

    for join in select.args.get("joins") or []:
        _collect_direct_tables(join, out)

    return out


def _collect_direct_tables(node: exp.Expression, out: list[exp.Table]) -> None:
    """Walk ``node`` collecting Table references, stopping at nested SELECTs.

    This avoids double-visiting tables that belong to subqueries — each
    subquery's enclosing Select is visited separately by the outer loop
    in :func:`rewrite_for_tenant`.
    """
    if isinstance(node, exp.Table):
        out.append(node)
        return
    if isinstance(node, exp.Select):
        # Do not descend into nested selects (subqueries).
        return
    for child in node.args.values():
        if isinstance(child, exp.Expression):
            _collect_direct_tables(child, out)
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, exp.Expression):
                    _collect_direct_tables(item, out)


def _is_table_function(table: exp.Table) -> bool:
    """Detect ClickHouse table-valued functions in FROM/JOIN positions.

    sqlglot represents ``FROM url('https://x', JSONEachRow)`` as a
    ``Table`` node whose ``this`` is a function-call node (or whose
    rendered ``sql()`` carries a function call). We treat those as
    forbidden because they let an attacker exfiltrate data, hit
    untrusted endpoints, or read foreign databases.
    """
    inner = table.this
    if isinstance(inner, exp.Anonymous | exp.Func):
        return True
    # Some dialects parse ``url(…)`` with an empty Table.name and a
    # function-shaped child elsewhere. Catch those by scanning direct
    # children for Anonymous calls.
    for child in table.find_all(exp.Anonymous):
        # ``find_all`` includes ``table`` itself; skip if the only hit is
        # the table node masquerading as a function.
        if child is not table:
            return True
    return False


def _qualified_name(table: exp.Table) -> str:
    """Return ``db.name`` for an allowlisted Table node.

    Unqualified references default to :data:`DEFAULT_SCHEMA` so an agent
    can write ``FROM raw_events`` and still hit the allowlist. The
    returned string is always lowercase to keep allowlist comparisons
    case-insensitive.
    """
    db = (table.db or DEFAULT_SCHEMA).lower()
    name = table.name.lower()
    return f"{db}.{name}"


def _clamp_outer_limit(node: exp.Expression, cap: int) -> None:
    """Force the outer query to honour a row cap.

    For ``WITH … SELECT …`` we apply the limit to the underlying SELECT
    inside the CTE wrapper. For ``UNION`` we apply it to the union
    itself. For a bare ``SELECT`` we apply it directly.

    If the caller already specified a smaller LIMIT we keep it (no point
    in expanding their request). If their LIMIT is larger or absent we
    replace it with the cap.
    """
    target: exp.Expression = node
    if isinstance(node, exp.With) and isinstance(node.this, exp.Select | exp.Union):
        target = node.this

    if not isinstance(target, exp.Select | exp.Union):
        # Defensive: caller already validated the root, but if a future
        # expansion misses a case we'd rather leave the SQL alone than
        # corrupt it.
        return

    existing = target.args.get("limit")
    if existing is not None:
        # Try to read the current limit literal; if it's an expression
        # (rare — most ClickHouse SQL uses literal limits) we leave it
        # alone since clamping a non-literal would be unsound.
        current = existing.expression
        if isinstance(current, exp.Literal) and current.is_int:
            current_value = int(current.this)
            if current_value <= cap:
                return  # caller asked for fewer rows; keep their value

    target.set("limit", exp.Limit(expression=exp.Literal.number(cap)))
