"""Translate ``UnifiedQuery`` → Microsoft Sentinel / Azure Monitor KQL.

The emitted KQL targets ``CommonSecurityLog`` by default since that's
the broadest cross-source table in a typical Sentinel deployment, but
the table name is parameterized so a connector can scope to
``SecurityIncident``, ``SigninLogs``, etc.

Shape:

    <table>
    | where TimeGenerated > ago(Ns)
    | where <free_text>
    | where <indicator>
    ...
    | take <limit>
"""

from __future__ import annotations

from typing import Any, Final

from app.federated.query import Indicator, QueryError, UnifiedQuery

_SENTINEL_TABLE_FIELD_ALIASES: Final[dict[str, dict[str, str]]] = {
    "SecurityIncident": {
        "device.name": "CompromisedEntity",
        "severity": "Severity",
        "message": "AlertName",
    },
    "SigninLogs": {
        "user.name": "UserPrincipalName",
    },
}


def _kql_quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _resolve_kql_field(field: str, table: str) -> str:
    aliases = _SENTINEL_TABLE_FIELD_ALIASES.get(table)

    if aliases is None:
        return field

    return aliases.get(field, field)


def _indicator_to_kql(
    indicator: Indicator,
    *,
    table: str,
) -> str:
    """Render a single ``Indicator`` as a KQL where-clause."""

    field_token = _resolve_kql_field(
        indicator.field,
        table,
    )

    op = indicator.operator
    value = indicator.value

    if op == "eq":
        return f"{field_token} == {_kql_quote(value)}"
    if op == "ne":
        return f"{field_token} != {_kql_quote(value)}"
    if op == "contains":
        return f"{field_token} contains {_kql_quote(value)}"
    if op == "starts_with":
        return f"{field_token} startswith {_kql_quote(value)}"
    if op == "ends_with":
        return f"{field_token} endswith {_kql_quote(value)}"
    if op == "gt":
        return f"{field_token} > {_kql_quote(value)}"
    if op == "gte":
        return f"{field_token} >= {_kql_quote(value)}"
    if op == "lt":
        return f"{field_token} < {_kql_quote(value)}"
    if op == "lte":
        return f"{field_token} <= {_kql_quote(value)}"
    if op == "in":
        joined = ", ".join(_kql_quote(v) for v in value)
        return f"{field_token} in ({joined})"
    raise QueryError(f"unsupported operator for KQL: {op}")


def to_kql(query: UnifiedQuery, *, table: str = "CommonSecurityLog") -> str:
    """Render a ``UnifiedQuery`` as a KQL pipeline."""
    lines: list[str] = [
        table,
        f"| where TimeGenerated > ago({query.since_seconds}s)",
    ]
    if query.free_text:
        # KQL's "search" verb does free-text across all string columns;
        # we use it as a where-clause so the pipeline shape stays uniform.
        lines.append(f"| where * contains {_kql_quote(query.free_text)}")

    for indicator in query.indicators:
        lines.append(f"| where {_indicator_to_kql(indicator, table=table)}")
    lines.append(f"| take {query.limit}")
    return "\n".join(lines)
