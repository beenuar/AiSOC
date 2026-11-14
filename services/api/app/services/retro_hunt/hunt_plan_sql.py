"""Compile a hunting agent's plan into lake SQL. The platform's half.

Gap-closure Phase 8.3.

``services/agents/app/hunt/plan.py`` decides what a model may propose. This
decides what that becomes. The split is the boundary: a model names a field
from a closed set and an operator from a closed set, and every value it
supplies travels as a bound parameter. No text the model produced is ever
concatenated into a statement.

Kept beside ``sql.py`` rather than inside it because the two answer different
questions with the same care. That one compiles a fixed sweep for one
indicator; this one compiles a variable plan. They share the property that
matters and nothing else, so sharing code would only couple them.

Tenant scoping is structural and bound, following ``lake_hunt`` rather than
``lake_sql``: the predicate is written into the WHERE clause here and its
value is a query parameter, because ``rewrite_for_tenant`` exists to constrain
SQL an *operator* wrote and handing it platform-authored SQL is how every
fresh tenant once saw the same global figures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["CompiledPlan", "HuntPlanCompileError", "compile_plan"]

LAKE_TABLE = "aisoc.raw_events"

#: Rows a plan may return. A hunting agent reads these into a prompt, so this
#: is a token budget as well as a warehouse one.
MAX_ROWS = 200

#: Columns a finding carries. Projected rather than ``SELECT *`` for the same
#: reason the Phase 4 SIEM search projects: it bounds cost, and it bounds how
#: much attacker-influenced vendor text reaches a prompt.
_PROJECTION = (
    "event_time",
    "connector_type",
    "severity",
    "src_hostname",
    "dst_hostname",
    "user_name",
    "process_name",
    "file_path",
    "hash_sha256",
    "toString(source_ip) AS source_ip",
    "toString(dest_ip) AS dest_ip",
    "mitre_techniques",
)

#: Mirrors ``app.hunt.plan``'s vocabulary. Duplicated rather than imported
#: because the two services package their code as a top-level ``app`` and
#: cannot import each other; ``scripts/check_hunt_agent_boundary.py`` reads
#: both files and fails when they disagree, which is the same arrangement
#: ``check_agent_read_tools.py`` uses for the indicator vocabulary.
_ARRAY_FIELDS = frozenset({"mitre_techniques", "mitre_tactics", "iocs"})
_IP_FIELDS = frozenset({"source_ip", "dest_ip"})
_NUMERIC_FIELDS = frozenset({"src_port", "dst_port", "severity_id", "class_uid"})

_FIELDS = frozenset(
    {
        "user_name",
        "src_hostname",
        "dst_hostname",
        "process_name",
        "file_path",
        "hash_sha256",
        "source_ip",
        "dest_ip",
        "src_port",
        "dst_port",
        "protocol",
        "connector_type",
        "severity_id",
        "class_uid",
        "mitre_techniques",
        "mitre_tactics",
        "iocs",
    }
)

_OPERATORS = frozenset({"eq", "neq", "contains", "starts_with", "ends_with", "gte", "lte", "has"})


class HuntPlanCompileError(ValueError):
    """The plan could not be compiled into a safe statement."""


@dataclass(frozen=True)
class CompiledPlan:
    sql: str
    params: dict[str, Any]
    fields_searched: tuple[str, ...]


def _predicate(field: str, operator: str, key: str) -> str:
    """One predicate. The value is always ``%(key)s``, never interpolated."""
    placeholder = f"%({key})s"

    if field in _ARRAY_FIELDS:
        if operator != "has":
            raise HuntPlanCompileError(f"{operator!r} cannot be applied to the list field {field!r}")
        return f"has({field}, {placeholder})"

    if field in _IP_FIELDS:
        if operator not in {"eq", "neq"}:
            raise HuntPlanCompileError(f"{operator!r} cannot be applied to the address field {field!r}")
        # The writer stores an IPv4 address in its IPv4-mapped IPv6 form, so
        # the needle is normalised the same way rather than compared as text.
        return f"{field} {'=' if operator == 'eq' else '!='} toIPv6({placeholder})"

    renderers = {
        "eq": f"{field} = {placeholder}",
        "neq": f"{field} != {placeholder}",
        "gte": f"{field} >= {placeholder}",
        "lte": f"{field} <= {placeholder}",
        # `position` rather than `LIKE`, so the value stays a literal and
        # cannot carry pattern metacharacters. A model-supplied `%` in a LIKE
        # is a wildcard the analyst did not ask for and a scan the warehouse
        # did not budget for.
        "contains": f"position({field}, {placeholder}) > 0",
        "starts_with": f"startsWith({field}, {placeholder})",
        "ends_with": f"endsWith({field}, {placeholder})",
    }
    rendered = renderers.get(operator)
    if rendered is None:
        raise HuntPlanCompileError(f"{operator!r} is not an operator this compiler implements")
    return rendered


def _bind(field: str, value: str) -> Any:
    if field in _NUMERIC_FIELDS:
        try:
            return int(float(value))
        except (TypeError, ValueError) as exc:
            raise HuntPlanCompileError(f"{field!r} is numeric and {value!r} is not a number") from exc
    return str(value)


def compile_plan(
    clauses: list[dict[str, Any]],
    *,
    tenant_id: str,
    lookback_hours: int = 168,
    limit: int = MAX_ROWS,
) -> CompiledPlan:
    """Compile a validated plan into a tenant-scoped, parameterised query.

    Re-validates the field and operator rather than trusting the agents-side
    check. The two services cannot import each other, so this is the only
    place that can refuse a clause on the path that actually reaches the
    warehouse, and a boundary enforced only on the far side of a network hop
    is not a boundary.
    """
    if not clauses:
        raise HuntPlanCompileError("a plan with no clauses would match the whole window")

    params: dict[str, Any] = {"tenant_id": tenant_id, "hours": max(1, min(int(lookback_hours), 2160))}
    where = [
        "tenant_id = %(tenant_id)s",
        "event_time >= now() - INTERVAL %(hours)s HOUR",
    ]
    fields: list[str] = []

    for index, clause in enumerate(clauses):
        field = str(clause.get("field") or "")
        operator = str(clause.get("operator") or "")
        if field not in _FIELDS:
            raise HuntPlanCompileError(f"{field!r} is not a field a hunt plan may name")
        if operator not in _OPERATORS:
            raise HuntPlanCompileError(f"{operator!r} is not an operator a hunt plan may use")
        key = f"c{index}"
        where.append(_predicate(field, operator, key))
        params[key] = _bind(field, str(clause.get("value") or ""))
        fields.append(field)

    row_cap = max(1, min(int(limit), MAX_ROWS))
    sql = f"SELECT {', '.join(_PROJECTION)} FROM {LAKE_TABLE} WHERE {' AND '.join(where)} ORDER BY event_time DESC LIMIT {row_cap}"

    # Fail closed on the property everything above rests on.
    if "tenant_id = %(tenant_id)s" not in sql:
        raise AssertionError("refusing to return a hunt plan query with no tenant predicate")

    return CompiledPlan(sql=sql, params=params, fields_searched=tuple(fields))
