"""Translate ``UnifiedQuery`` -> IBM QRadar AQL (Ariel Query Language).

Shape:

    SELECT * FROM <table> WHERE <filters> LAST <N> MINUTES LIMIT <limit>

String values are single-quoted with embedded quotes escaped. The time window
is expressed with AQL's ``LAST N MINUTES`` clause (QRadar's native relative
window), and free text uses AQL ``TEXT SEARCH``.
"""

from __future__ import annotations

from typing import Any

from app.federated.query import Indicator, QueryError, UnifiedQuery


def _aql_quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _indicator_to_aql(indicator: Indicator) -> str:
    field = indicator.field
    op = indicator.operator
    value = indicator.value

    if op == "eq":
        return f"{field} = {_aql_quote(value)}"
    if op == "ne":
        return f"{field} <> {_aql_quote(value)}"
    if op == "contains":
        return f"{field} ILIKE '%{value}%'"
    if op == "starts_with":
        return f"{field} ILIKE '{value}%'"
    if op == "ends_with":
        return f"{field} ILIKE '%{value}'"
    if op == "gt":
        return f"{field} > {_aql_quote(value)}"
    if op == "gte":
        return f"{field} >= {_aql_quote(value)}"
    if op == "lt":
        return f"{field} < {_aql_quote(value)}"
    if op == "lte":
        return f"{field} <= {_aql_quote(value)}"
    if op == "in":
        joined = ", ".join(_aql_quote(v) for v in value)
        return f"{field} IN ({joined})"
    raise QueryError(f"unsupported operator for AQL: {op}")


def to_aql(query: UnifiedQuery, *, table: str = "events") -> str:
    """Render a ``UnifiedQuery`` as an IBM QRadar AQL search string."""
    clauses: list[str] = []
    if query.free_text:
        clauses.append(f"TEXT SEARCH {_aql_quote(query.free_text)}")
    clauses.extend(_indicator_to_aql(indicator) for indicator in query.indicators)

    sql = f"SELECT * FROM {table}"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    minutes = max(1, query.since_seconds // 60)
    sql += f" LAST {minutes} MINUTES LIMIT {query.limit}"
    return sql
