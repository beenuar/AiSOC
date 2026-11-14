"""Compile a translated hunt into SQL against AiSOC's own event lake.

Every connector's events are archived to ClickHouse `aisoc.raw_events`, and
until now nothing could hunt them. `/nl-query/execute` only ever executed
against Elasticsearch, so a tenant whose data lives in the platform's own lake
got "ES_URL or ES_API_KEY not configured" and had no way to query anything they
had ingested. `POST /saved-hunts/{id}/run` was worse: it re-translated the
question, stamped `last_run_at`, and returned — so the UI displayed "last run
just now" having queried nothing at all.

This module closes that by compiling the translator's structured IR
(`QueryIntents`) into ClickHouse SQL. Deterministic, no LLM: the IR already
carries typed filters with a closed operator set, group-bys, aggregations, a
sort and a limit.

Two properties this must not get wrong:

**No user text ever reaches the SQL string.** Field names resolve through a
fixed alias map to real column names, operators come from a closed set, and
every value is bound as a query parameter. A question is untrusted input, and
the lake holds every tenant's events.

**Tenant scoping is structural, not rewritten in afterwards.** The tenant
predicate is part of the generated WHERE clause and its parameter is bound by
this module, rather than relying on `rewrite_for_tenant` — which exists to
constrain untrusted *operator* SQL, and which cannot help if a caller forgets
to use it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

LAKE_TABLE = "aisoc.raw_events"

#: ECS-ish field names the translator emits, mapped to lake columns.
#:
#: The translator speaks ECS because it also targets Elasticsearch. Anything
#: absent from this map is a field the lake genuinely does not store, and is
#: reported to the caller rather than silently dropped — a hunt that quietly
#: ignores half its filters returns more rows than the analyst asked for, which
#: reads as "no results were filtered out" when the truth is "your filter was
#: discarded".
_FIELD_TO_COLUMN: dict[str, str] = {
    "@timestamp": "event_time",
    "event.created": "event_time",
    "user.name": "user_name",
    "source.ip": "source_ip",
    "destination.ip": "dest_ip",
    "source.port": "src_port",
    "destination.port": "dst_port",
    "host.name": "src_hostname",
    "destination.domain": "dst_hostname",
    "process.name": "process_name",
    "file.path": "file_path",
    "file.hash.sha256": "hash_sha256",
    "event.severity": "severity_id",
    # Every one of the 68 shipped hunts filters on a bare `source`, and the
    # lake stores it as `connector_type`. Without this line the corpus had
    # zero resolvable fields against the lake.
    "source": "connector_type",
    "event.category": "connector_type",
    "event.provider": "connector_type",
    "network.protocol": "protocol",
    "rule.name": "connector_type",
    "threat.technique.id": "mitre_techniques",
    "process.command_line": "raw_payload",
    "url.full": "raw_payload",
    "user_agent.original": "raw_payload",
}

#: Columns holding an Array(String); membership tests differ from scalars.
_ARRAY_COLUMNS = frozenset({"mitre_techniques", "mitre_tactics", "iocs"})

#: Operators the IR can emit, mapped to ClickHouse syntax. A closed set: an
#: operator outside it is rejected rather than passed through.
_SCALAR_OPS = {
    "==": "=",
    "!=": "!=",
    ">": ">",
    "<": "<",
    ">=": ">=",
    "<=": "<=",
}

MAX_LIMIT = 1000


@dataclass(frozen=True)
class CompiledHunt:
    """A parameterised lake query plus an honest account of what was dropped."""

    sql: str
    params: dict[str, Any]
    #: Translator fields with no lake column. Surfaced to the caller so a
    #: partial hunt is never presented as a complete one.
    unsupported_fields: list[str]

    @property
    def is_partial(self) -> bool:
        return bool(self.unsupported_fields)


class HuntCompileError(ValueError):
    """The IR could not be compiled into a safe lake query."""


#: A vendor field name the lake has no column for, but which the stored
#: payload may carry. Deliberately narrow: an identifier, nothing else.
#:
#: The name is bound as a query parameter, never interpolated, so a hunt
#: cannot inject SQL through a field name -- but it is *also* validated here,
#: because "the value is escaped" is not a reason to accept a field name that
#: cannot be a field name, and refusing is cheaper than reasoning about every
#: downstream use.
_PAYLOAD_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _column_for(field: str) -> str | None:
    if field in _FIELD_TO_COLUMN:
        return _FIELD_TO_COLUMN[field]
    # A bare column name is accepted only if it really is a lake column.
    if field in set(_FIELD_TO_COLUMN.values()) | _ARRAY_COLUMNS:
        return field
    return None


def _payload_expression(field: str, key: str) -> str | None:
    """Reach a vendor field inside the stored payload, or give up honestly.

    The lake keeps the whole original event in `raw_payload`, so a field with
    no dedicated column is not necessarily out of reach: of the 114 distinct
    fields the shipped hunt corpus filters on, exactly **zero** resolved to a
    lake column, and most of the remainder are vendor names like `EventID`,
    `CommandLine` or `eventName` that the payload does carry.

    Three paths are tried because Windows nests its payload one level below
    anything flat: `EventData` and `System`. That nesting is the same thing
    that once made 2,173 Sigma rules unable to fire, and it is worth reaching
    for rather than declaring the field unsupported.

    Returns `None` for anything that is not a plain identifier, so the caller
    reports it as unsupported rather than guessing.
    """
    if not _PAYLOAD_FIELD.match(field):
        return None
    name = f"%({key}_field)s"
    return (
        "coalesce("
        f"nullIf(JSONExtractString(raw_payload, {name}), ''), "
        f"nullIf(JSONExtractString(raw_payload, 'EventData', {name}), ''), "
        f"nullIf(JSONExtractString(raw_payload, 'System', {name}), '')"
        ")"
    )


def _predicate(column: str, op: str, value: str, key: str) -> tuple[str, Any]:
    """Build one parameterised predicate. Never interpolates the value."""
    placeholder = f"%({key})s"

    if column in _ARRAY_COLUMNS:
        if op in {"==", "IN"}:
            values = _as_list(value)
            return f"hasAny({column}, %({key})s)", values
        raise HuntCompileError(f"operator {op!r} is not supported on array column {column!r}")

    if op == "IN":
        return f"{column} IN %({key})s", _as_list(value)
    if op == "LIKE":
        # The translator emits LIKE for "contains" phrasing. Bind the whole
        # pattern, wildcards included, so the value stays data.
        pattern = value if "%" in value else f"%{value}%"
        return f"{column} ILIKE %({key})s", pattern
    if op in _SCALAR_OPS:
        # A payload expression always yields a string, so the numeric coercion
        # that `_coerce` applies by column name must not fire on it -- a bound
        # integer against `JSONExtractString` matches nothing and would read as
        # "no results" rather than as a type mismatch.
        bound = value if column.startswith("coalesce(") else _coerce(column, value)
        return f"{column} {_SCALAR_OPS[op]} {placeholder}", bound

    raise HuntCompileError(f"unsupported operator {op!r}")


def _as_list(value: str) -> list[str]:
    """The IR JSON-encodes IN lists so its dedup set stays hashable."""
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return [value]
    return [str(v) for v in parsed] if isinstance(parsed, list) else [str(parsed)]


def _coerce(column: str, value: str) -> Any:
    """Numeric columns need numbers, not strings, or ClickHouse rejects them."""
    if column in {"severity_id", "src_port", "dst_port"}:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise HuntCompileError(f"{column} needs a number, got {value!r}") from exc
    return value


def compile_hunt(
    intents: Any,
    *,
    tenant_id: str,
    hours: int = 24,
    limit: int | None = None,
) -> CompiledHunt:
    """Compile translator intents into a tenant-scoped lake query.

    `intents` is a `QueryIntents` (or anything with the same attributes), so
    this works against both the API's vendored translator and the agents' copy
    without importing either.
    """
    params: dict[str, Any] = {"tenant_id": tenant_id, "hours": max(1, int(hours))}
    where = [
        # Structural, not rewritten in afterwards.
        "tenant_id = %(tenant_id)s",
        "event_time >= now() - INTERVAL %(hours)s HOUR",
    ]
    unsupported: list[str] = []

    for index, (field, op, value) in enumerate(getattr(intents, "filters", []) or []):
        key = f"f{index}"
        column = _column_for(str(field))
        if column is None:
            # No dedicated column, but the lake keeps the whole original event
            # in `raw_payload`, so a vendor field name is often still reachable.
            expression = _payload_expression(str(field), key)
            if expression is None:
                unsupported.append(str(field))
                continue
            column = expression
            params[f"{key}_field"] = str(field)
        clause, bound = _predicate(column, str(op), str(value), key)
        where.append(clause)
        params[key] = bound

    group_by: list[str] = []
    for field in getattr(intents, "group_by", []) or []:
        column = _column_for(str(field))
        if column is None:
            unsupported.append(str(field))
            continue
        group_by.append(column)

    select = _select_clause(intents, group_by, unsupported)
    sql = f"SELECT {', '.join(select)} FROM {LAKE_TABLE} WHERE {' AND '.join(where)}"

    if group_by:
        sql += f" GROUP BY {', '.join(group_by)}"

    sql += f" ORDER BY {_order_clause(intents, group_by)}"

    effective_limit = min(int(limit or getattr(intents, "limit", 500) or 500), MAX_LIMIT)
    sql += f" LIMIT {max(1, effective_limit)}"

    return CompiledHunt(sql=sql, params=params, unsupported_fields=sorted(set(unsupported)))


def _select_clause(intents: Any, group_by: list[str], unsupported: list[str]) -> list[str]:
    """Projection: aggregations when asked for, otherwise the event columns."""
    aggregations = getattr(intents, "aggregations", []) or []
    distinct = getattr(intents, "distinct", None)

    if distinct:
        column = _column_for(str(distinct))
        if column is not None:
            return [f"DISTINCT {column}"]
        unsupported.append(str(distinct))

    if aggregations:
        select = list(group_by)
        for function, arg, alias in aggregations:
            select.append(_aggregation(str(function), arg, str(alias), unsupported))
        return select

    if group_by:
        return [*group_by, "count() AS event_count"]

    return [
        "event_time",
        "severity",
        "connector_type",
        "src_hostname",
        "user_name",
        "process_name",
        "toString(source_ip) AS source_ip",
        "toString(dest_ip) AS dest_ip",
        "mitre_techniques",
    ]


def _aggregation(function: str, arg: Any, alias: str, unsupported: list[str]) -> str:
    """Render one aggregation from the closed set the translator can emit."""
    name = function.lower()
    safe_alias = "".join(c for c in alias if c.isalnum() or c == "_") or "value"

    if name in {"count", "count_distinct"} and not arg:
        return f"count() AS {safe_alias}"

    column = _column_for(str(arg)) if arg else None
    if column is None:
        if arg:
            unsupported.append(str(arg))
        return f"count() AS {safe_alias}"

    renderers = {
        "count": f"count({column})",
        "count_distinct": f"uniqExact({column})",
        "sum": f"sum({column})",
        "avg": f"avg({column})",
        "min": f"min({column})",
        "max": f"max({column})",
    }
    return f"{renderers.get(name, f'count({column})')} AS {safe_alias}"


def _order_clause(intents: Any, group_by: list[str]) -> str:
    """Always returns a clause that is valid for the query being built.

    The default must respect `group_by`: ordering an aggregate query by
    `event_time` is a ClickHouse error, because the column is not in the
    grouping set. Same for a sort field that does not map to a lake column —
    falling back to a non-grouped column there would turn an unmappable sort
    into a failed query rather than a sensible default.
    """
    default = "count() DESC" if group_by else "event_time DESC"
    sort_by = getattr(intents, "sort_by", None)
    if not sort_by:
        return default

    field, direction = sort_by
    column = _column_for(str(field))
    if column is None or (group_by and column not in group_by):
        return default
    return f"{column} {'DESC' if str(direction).lower().startswith('desc') else 'ASC'}"
