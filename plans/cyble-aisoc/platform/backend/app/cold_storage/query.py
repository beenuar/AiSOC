"""Query-on-cold engine + agent-facing tool (t6-cold-storage).

A small, deliberate SQL-ish surface so the rest of the platform
can ask cold-tier questions without re-hydrating into the
operational store. Production deployments swap the local query
engine for an Athena/Presto adapter; the agent-facing tool
contract stays identical.

Supported syntax (parsed by :func:`parse_query`)::

    SELECT * FROM tenant.<tenant_id>
    [WHERE field = value [AND field = value ...]]
    [LIMIT n]

Where ``tenant.<tenant_id>`` is a stand-in for the cold archive's
per-tenant logical view. Comparison operators are limited to ``=``
deliberately — the agent surface doesn't need full predicate push-
down; if the operator does, they are presumably running a real
Presto cluster.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol

from app.cold_storage.archive import StorageTier, TieredArchive, cold_archive


# ---------------------------------------------------------------------------
# Query AST + parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Predicate:
    field: str
    value: Any


@dataclass(frozen=True)
class ColdQuery:
    tenant_id: str
    predicates: tuple[Predicate, ...] = ()
    limit: int = 100
    tier: str = StorageTier.COLD


_SELECT_RE = re.compile(
    r"""
    ^\s*SELECT\s+\*\s+FROM\s+tenant\.(?P<tenant>[A-Za-z0-9_\-]+)
    (?:\s+WHERE\s+(?P<where>.+?))?
    (?:\s+LIMIT\s+(?P<limit>\d+))?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)


def parse_query(query: str, *, default_tier: str = StorageTier.COLD) -> ColdQuery:
    """Parse the query string into a :class:`ColdQuery`.

    Tier selection lives in a small extension to the grammar:
    ``WHERE __tier = 'warm'`` resolves the tier without exposing a
    separate clause. The syntax stays close to ANSI SQL, which is
    also what the Athena/Presto adapter parses in production.
    """

    if not query or not query.strip():
        raise ValueError("query is empty")

    match = _SELECT_RE.match(query)
    if match is None:
        raise ValueError(
            "query must look like 'SELECT * FROM tenant.<id> [WHERE ...] [LIMIT n]'"
        )

    tenant = match.group("tenant")
    where = match.group("where")
    limit_str = match.group("limit")

    predicates: list[Predicate] = []
    tier = default_tier
    if where:
        for clause in [c.strip() for c in re.split(r"(?i)\sAND\s", where) if c.strip()]:
            m = re.match(
                r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", clause
            )
            if not m:
                raise ValueError(
                    f"unsupported WHERE clause: '{clause}'. "
                    f"Only equality on a single field is supported."
                )
            field_name = m.group(1)
            value_raw = m.group(2).strip()
            value = _parse_literal(value_raw)
            if field_name == "__tier":
                if not isinstance(value, str) or value not in (
                    StorageTier.HOT,
                    StorageTier.WARM,
                    StorageTier.COLD,
                ):
                    raise ValueError(
                        f"__tier must be one of hot/warm/cold, got {value!r}"
                    )
                tier = value
                continue
            predicates.append(Predicate(field=field_name, value=value))

    limit = int(limit_str) if limit_str else 100
    if limit < 1 or limit > 10_000:
        raise ValueError("LIMIT must be between 1 and 10000")
    return ColdQuery(
        tenant_id=tenant,
        predicates=tuple(predicates),
        limit=limit,
        tier=tier,
    )


def _parse_literal(raw: str) -> Any:
    raw = raw.strip()
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    if raw.lower() == "null":
        return None
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return raw


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


@dataclass
class QueryResult:
    rows: list[dict[str, Any]]
    scanned: int = 0
    tier: str = StorageTier.COLD
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_count": len(self.rows),
            "scanned": self.scanned,
            "tier": self.tier,
            "truncated": self.truncated,
            "rows": list(self.rows),
        }


class QueryEngine(Protocol):
    def execute(self, query: ColdQuery) -> QueryResult: ...


@dataclass
class LocalQueryEngine:
    """Default engine — scans on-disk JSONL batches."""

    archive: TieredArchive = field(default_factory=lambda: cold_archive)

    def execute(self, query: ColdQuery) -> QueryResult:
        scanned = 0
        rows: list[dict[str, Any]] = []
        for row in self.archive.iter_rows(tenant_id=query.tenant_id, tier=query.tier):
            scanned += 1
            if not _matches(row, query.predicates):
                continue
            rows.append(row)
            if len(rows) >= query.limit:
                # Drain the rest of the iterator's count for stats
                # without reading them — the archive's iter_rows is
                # already streaming, so we just stop here.
                break
        truncated = len(rows) == query.limit
        return QueryResult(
            rows=rows,
            scanned=scanned,
            tier=query.tier,
            truncated=truncated,
        )


def _matches(row: dict[str, Any], predicates: Iterable[Predicate]) -> bool:
    for p in predicates:
        if row.get(p.field) != p.value:
            return False
    return True


_engine: Optional[QueryEngine] = None


def _engine_instance() -> QueryEngine:
    global _engine
    if _engine is None:
        _engine = LocalQueryEngine()
    return _engine


def set_query_engine(engine: QueryEngine) -> None:
    """Register a non-default :class:`QueryEngine` (e.g. Athena/Presto)."""

    global _engine
    _engine = engine


# ---------------------------------------------------------------------------
# Agent-facing tool
# ---------------------------------------------------------------------------


def query_cold_archive(
    *,
    query: str,
    tenant_id: Optional[str] = None,
) -> dict[str, Any]:
    """Run a cold-archive query and return a JSON-serialisable result.

    This is the function the tool registry binds to
    ``cold_archive.query``. Tenant scoping is enforced both by the
    query string (``FROM tenant.<id>``) and by an optional
    ``tenant_id`` override the tool registry can pass through —
    if the override is set, the parsed query MUST agree with it.
    """

    parsed = parse_query(query)
    if tenant_id is not None and parsed.tenant_id != tenant_id:
        raise ValueError(
            f"query targets tenant '{parsed.tenant_id}' but tool was invoked "
            f"for tenant '{tenant_id}'"
        )
    engine = _engine_instance()
    result = engine.execute(parsed)
    return result.to_dict()
