"""Translate ``UnifiedQuery`` → Elastic ES|QL.

ES|QL is Elastic's piped query language; the shape we emit:

    FROM <index>
    | WHERE @timestamp > NOW() - <Ns>
    | WHERE <free_text predicate>
    | WHERE <indicator>
    ...
    | LIMIT <limit>

Indices are chosen by the caller from ``connector_config`` — typically
``logs-*`` for Beats-shipped data or ``security-*`` for Elastic SIEM.
"""

from __future__ import annotations

from typing import Any

from app.federated.query import Indicator, QueryError, UnifiedQuery


def _esql_quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _indicator_to_esql(indicator: Indicator) -> str:
    field_token = indicator.field
    op = indicator.operator
    value = indicator.value

    if op == "eq":
        return f"{field_token} == {_esql_quote(value)}"
    if op == "ne":
        return f"{field_token} != {_esql_quote(value)}"
    if op == "contains":
        # ES|QL has no native CONTAINS; LIKE with %...% is the canonical port.
        return f'{field_token} LIKE "%{value}%"'
    if op == "starts_with":
        return f'{field_token} LIKE "{value}%"'
    if op == "ends_with":
        return f'{field_token} LIKE "%{value}"'
    if op == "gt":
        return f"{field_token} > {_esql_quote(value)}"
    if op == "gte":
        return f"{field_token} >= {_esql_quote(value)}"
    if op == "lt":
        return f"{field_token} < {_esql_quote(value)}"
    if op == "lte":
        return f"{field_token} <= {_esql_quote(value)}"
    if op == "in":
        joined = ", ".join(_esql_quote(v) for v in value)
        return f"{field_token} IN ({joined})"
    raise QueryError(f"unsupported operator for ES|QL: {op}")


def to_esql(query: UnifiedQuery, *, index: str = "logs-*") -> str:
    """Render a ``UnifiedQuery`` as an ES|QL pipeline."""
    lines: list[str] = [
        f"FROM {index}",
        f"| WHERE @timestamp > NOW() - {query.since_seconds} seconds",
    ]
    if query.free_text:
        lines.append(f'| WHERE message LIKE "%{query.free_text}%"')
    for indicator in query.indicators:
        lines.append(f"| WHERE {_indicator_to_esql(indicator)}")
    lines.append(f"| LIMIT {query.limit}")
    return "\n".join(lines)
