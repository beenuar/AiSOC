"""Translate ``UnifiedQuery`` → Splunk SPL.

The SPL we emit is intentionally vanilla — no transforming commands,
no subsearches — so it composes well with whatever index, sourcetype,
or saved-search prefix the tenant's Splunk admin layered on top via
the connector's ``connector_config``.

Shape:

    search index=<index> earliest=-Ns latest=now <filters> | head <limit>

Field/operator semantics map onto Splunk's standard search syntax.
String values are quoted and any embedded double quotes are escaped.
"""

from __future__ import annotations

from typing import Any

from app.federated.query import Indicator, QueryError, UnifiedQuery


def _spl_quote(value: Any) -> str:
    """Quote a value for safe inclusion in an SPL filter.

    Splunk's search language treats most characters literally inside
    double quotes; escape embedded quotes and backslashes.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _indicator_to_spl(indicator: Indicator) -> str:
    field_token = indicator.field
    op = indicator.operator
    value = indicator.value

    if op == "eq":
        return f"{field_token}={_spl_quote(value)}"
    if op == "ne":
        return f"NOT {field_token}={_spl_quote(value)}"
    if op == "contains":
        return f"{field_token}=*{value}*"
    if op == "starts_with":
        return f"{field_token}={value}*"
    if op == "ends_with":
        return f"{field_token}=*{value}"
    if op == "gt":
        return f"{field_token}>{_spl_quote(value)}"
    if op == "gte":
        return f"{field_token}>={_spl_quote(value)}"
    if op == "lt":
        return f"{field_token}<{_spl_quote(value)}"
    if op == "lte":
        return f"{field_token}<={_spl_quote(value)}"
    if op == "in":
        joined = " OR ".join(f"{field_token}={_spl_quote(v)}" for v in value)
        return f"({joined})"
    raise QueryError(f"unsupported operator for SPL: {op}")


def to_spl(query: UnifiedQuery, *, index: str = "main") -> str:
    """Render a ``UnifiedQuery`` as a Splunk search string.

    ``index`` is supplied by the caller from the connector's
    ``connector_config`` (typically ``notable`` for ES customers,
    ``main`` for self-hosted indexes).
    """
    parts: list[str] = [f"search index={index} earliest=-{query.since_seconds}s latest=now"]
    if query.free_text:
        parts.append(_spl_quote(query.free_text))
    for indicator in query.indicators:
        parts.append(_indicator_to_spl(indicator))
    parts.append(f"| head {query.limit}")
    return " ".join(parts)
