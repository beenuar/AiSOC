#!/usr/bin/env python3
"""The investigation ledger's replay contract, held in both directions.

Why this exists
---------------

"Investigation Ledger stores every step" is a front-page claim, and the gate
the claim matrix named for it — ``api tests (audit_hash, audit immutability)``
— tests a **different table**. ``services/api/tests/test_audit_hash.py``
covers ``app.services.audit_hash`` over ``audit_log``, which the API's audit
middleware writes. The ledger is ``investigation_runs`` /
``investigation_events`` / ``investigation_artifacts``, created by
``services/api/migrations/008_investigation_ledger.sql`` and written by
``services/agents/app/investigator/ledger.py`` over raw asyncpg. Two tables
with two writers, and only one of them was ever gated; the hash chain could
have been perfect while every replay surface was broken.

What was actually ungated: the ledger's only test covered tenant resolution
against a stub connection, no test anywhere touched ``/replay``, ``/events``
or ``/explain``, and the "hermetic e2e" the row cited is one Playwright spec
in the ``screenshots`` project, which runs from a monthly cron whose job is
to capture PNGs rather than from any pull request.

Three trees have to agree for a step to survive from the agent that took it
to the analyst reading it back, and none of them can import the others: the
writer packages as top-level ``app`` in ``services/agents``, the reader
packages as top-level ``app`` in ``services/api``, and the console is
TypeScript. The contract between them is a handful of declarations agreeing
by convention, and this tree has already shipped both halves of that failing:
six Investigation Rail entity pivots emitted ``/attack-graph?entity=...``
against a route that never existed, and ``EntityBaseline.peer_group_id`` was
declared by a model no migration created, so the first query raised.

Nothing is imported. The gate runs on a bare interpreter, and importing the
API service to read a list of field names would drag in SQLAlchemy, FastAPI
and the whole model graph.

What it checks, in both directions
----------------------------------

The dominant failure shape in this repository is the one-directional gate: it
compares A against B, never B against A, and prints OK while drift
accumulates in the direction things actually change. The graph-schema drift
check declared "OK" over a YAML file with 17 labels against Go with 28. So
each of the three properties below is asserted both ways.

``FIELD-*``
    Every field of the ``EventOut`` response model is a field of the
    ``LedgerEvent`` TypeScript interface, and the reverse. The direction that
    drifts is a field added to the Python model that the TypeScript type never
    hears about: it is serialised, delivered, and dropped at the boundary with
    nothing failing. The reverse direction is a console rendering a key no
    response carries, which reads as an empty cell rather than as a bug.

``ROUTE-*``
    Every path the ``ledgerApi`` client requests is a path the FastAPI router
    declares, and every ledger route the router declares is either consumed
    somewhere under ``apps/web/src`` or recorded in ``SERVER_ONLY_ROUTES``
    with a reason. Read from the ``@router.get`` / ``@router.post`` decorators
    and from the client's own literals, so a route renamed on one side alone
    is a finding rather than a 404 an operator discovers.

``COLUMN-*`` / ``SEQ-*``
    Every column the three ledger tables carry is either written by the
    ledger writer or recorded as unwritten with a reason.

    Only that direction. The other one — a column the writer writes that no
    migration creates — is held by ``scripts/check_raw_sql_columns.py``,
    which landed while this was being written and makes the comparison
    generically for every raw statement under ``services/*/app``, including
    this writer's. Two gates reporting the same finding is not redundancy, it
    is two places to keep in step, so this one delegates and says so. The
    delegation is checked rather than asserted: if that gate stops existing
    or stops reading the writer's tree, ``COLUMN-DELEGATION-MISSING`` fires
    here, because a direction nobody covers must not go quiet.

    What no generic column gate can say is what "stores every step" actually
    means, so this does: the writer must stamp ``seq`` on every event it
    appends, the schema must keep ``UNIQUE (run_id, seq)`` so a replayed
    write conflicts instead of appending a second copy of a step, and every
    read handler that materialises a collection of events must ``ORDER BY
    seq`` — and not by ``ts``, which ties at the resolution the agent writes
    it and moves backwards under a clock correction. A replay that returns
    steps in whatever order the planner chose is not a replay, and Postgres
    promises no order without an ``ORDER BY``.

Non-vacuity
-----------

Found nothing and scanned nothing print the same word. A verdict is refused
outright on zero parsed fields, zero parsed routes, zero parsed client paths,
zero parsed columns, or zero event-list handlers, and the counts are printed
on every run so a parser that quietly stopped matching is visible by reading
rather than by trusting the exit code.

What it reads
-------------

* ``services/api/app/api/v1/endpoints/investigations.py`` — Python ``ast``
  for the ``EventOut`` model, the router decorators, and each handler's query
  shape.
* ``apps/web/src/lib/api.ts`` — the ``LedgerEvent`` interface and the
  ``ledgerApi`` object, comments stripped first so a documented-but-absent
  field cannot satisfy a requirement.
* ``apps/web/src/**/*.ts(x)`` — which ledger routes anything actually calls.
* ``services/agents/app/investigator/ledger.py`` — the SQL passed to
  ``conn.execute``, by ``ast``, so a table name in a docstring is not a write.
* ``services/api/migrations/*.sql`` — ``CREATE TABLE`` in 008 plus every
  later ``ADD COLUMN`` against those three tables, because four of the
  columns the writer writes arrived in migration 063.

Usage
-----

::

    python3 scripts/check_ledger_replay_contract.py             # gate
    python3 scripts/check_ledger_replay_contract.py --json
    python3 scripts/check_ledger_replay_contract.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

# ---------------------------------------------------------------------------
# What the contract is written across
# ---------------------------------------------------------------------------

ENDPOINTS_REL = "services/api/app/api/v1/endpoints/investigations.py"
API_TS_REL = "apps/web/src/lib/api.ts"
WRITER_REL = "services/agents/app/investigator/ledger.py"
CREATING_MIGRATION_REL = "services/api/migrations/008_investigation_ledger.sql"
MIGRATIONS_DIR_REL = "services/api/migrations"
WEB_SRC_REL = "apps/web/src"

#: The response model and the TypeScript type that must carry the same fields.
RESPONSE_MODEL = "EventOut"
TS_INTERFACE = "LedgerEvent"

#: The client object whose every request must land on a declared route.
CLIENT_OBJECT = "ledgerApi"

#: ``APIRouter(prefix=...)`` in the endpoints module. Read rather than assumed,
#: with this as the fallback only if the constructor stops naming one.
ROUTER_PREFIX_DEFAULT = "/investigations"

#: The three tables migration 008 creates. Deliberately not "every table the
#: writer touches": it also writes ``alerts``, ``agent_approvals`` and
#: ``aisoc_outcome_suppressions``, which belong to other migrations and other
#: gates.
LEDGER_TABLES = ("investigation_runs", "investigation_events", "investigation_artifacts")

#: The append-only table, the column that orders it, and the run it belongs to.
#: ``UNIQUE (run_id, seq)`` is what makes a replayed write conflict instead of
#: appending a second copy of a step.
EVENTS_TABLE = "investigation_events"
SEQUENCE_COLUMN = "seq"
RUN_COLUMN = "run_id"

#: The ORM class the API reads events through, named in the read handlers.
EVENT_ORM = "InvestigationEvent"

#: The gate that owns the other half of the column comparison — a column the
#: writer writes that no migration creates — and the glob whose presence in
#: its source means it still reaches this writer. Checked rather than
#: assumed: delegating to a gate that has stopped looking is how a direction
#: goes quiet while two files each believe the other has it.
DELEGATE_REL = "scripts/check_raw_sql_columns.py"
DELEGATE_SCOPE_MARKER = "services/*/app"


# ---------------------------------------------------------------------------
# Recorded exceptions
# ---------------------------------------------------------------------------
#
# Shrink-only, and verified in both directions: an entry that stops being
# needed fails the build rather than sitting here looking like coverage. Each
# says why, because a bare list of names is a second place for drift to hide.

#: Routes the router declares that no browser client calls, and why that is a
#: decision rather than an oversight. Checked both ways — an entry naming a
#: route that no longer exists, or one the console has since started calling,
#: is a finding.
SERVER_ONLY_ROUTES: dict[str, str] = {
    "POST /investigations/{}/close": (
        "closing a run is driven from the case workspace through /cases, which owns the case lifecycle; "
        "the console never posts here directly"
    ),
    "GET /investigations/{}/summary.pdf": (
        "a browser follows this as a download link rather than fetching it through the typed client, "
        "so there is no request literal to match"
    ),
}

#: ``(table, column)`` the schema carries and the ledger writer never writes,
#: with the reason it is not a write. Read-only or database-populated columns
#: are the expected shape here.
UNWRITTEN_COLUMNS: dict[tuple[str, str], str] = {
    ("investigation_artifacts", "blob_ref"): "reserved for object-store offload; artifacts are stored inline in content for now",
}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class GateError(RuntimeError):
    """The scan itself could not run — a missing file, an unparseable source."""


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.detail}"


@dataclass
class RouteDecl:
    """One ``@router.<method>(path)`` declaration, normalised."""

    method: str
    path: str
    handler: str

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class EventQuery:
    """What one router handler does with ``InvestigationEvent`` rows."""

    handler: str
    orders_by_sequence: bool
    #: Event columns the handler orders by that are *not* ``seq``. Ordering a
    #: replay by ``ts`` is the plausible drift and a silently wrong one:
    #: timestamps tie at the resolution the agent writes them, and a clock
    #: correction can move one backwards, while ``seq`` cannot.
    other_order_columns: tuple[str, ...] = ()


@dataclass
class Corpus:
    """Everything the verdict is computed from, so it can be probed directly."""

    model_fields: set[str] = field(default_factory=set)
    ts_fields: set[str] = field(default_factory=set)
    routes: dict[str, RouteDecl] = field(default_factory=dict)
    client_paths: set[str] = field(default_factory=set)
    consumer_paths: set[str] = field(default_factory=set)
    written_columns: dict[str, set[str]] = field(default_factory=dict)
    schema_columns: dict[str, set[str]] = field(default_factory=dict)
    created_in_migration: dict[str, str] = field(default_factory=dict)
    unique_constraints: dict[str, set[tuple[str, ...]]] = field(default_factory=dict)
    event_queries: list[EventQuery] = field(default_factory=list)
    #: Whether ``DELEGATE_REL`` still covers the direction this gate hands it.
    delegate_reads_writer: bool = False

    def counts(self) -> dict[str, int]:
        return {
            "model_fields": len(self.model_fields),
            "typescript_fields": len(self.ts_fields),
            "routes": len(self.routes),
            "client_paths": len(self.client_paths),
            "consumer_paths": len(self.consumer_paths),
            "written_columns": sum(len(v) for v in self.written_columns.values()),
            "schema_columns": sum(len(v) for v in self.schema_columns.values()),
            "event_list_handlers": len(self.event_queries),
        }


# ---------------------------------------------------------------------------
# Python: the response model, the router, the read handlers
# ---------------------------------------------------------------------------


def _parse_python(text: str, rel: str) -> ast.Module:
    try:
        return ast.parse(text)
    except SyntaxError as exc:
        raise GateError(f"{rel}: could not parse: {exc}") from exc


def parse_model_fields(text: str, rel: str, class_name: str) -> set[str]:
    """Annotated field names of one Pydantic model, by ``ast``.

    A field named only in a docstring or a comment is not a field, which is
    the whole reason this reads the tree rather than grepping it.
    """
    tree = _parse_python(text, rel)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {stmt.target.id for stmt in node.body if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)}
    raise GateError(f"{rel}: no class named {class_name}")


def _router_prefix(tree: ast.Module) -> str:
    """The prefix the module's ``APIRouter`` was constructed with."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "APIRouter"):
            continue
        for kw in node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return ROUTER_PREFIX_DEFAULT


def _normalise_path(path: str) -> str:
    """Collapse every path parameter to ``{}``.

    ``/{run_id}/events`` and ``/${runId}/events`` describe the same route and
    have to compare equal, or the gate would only ever be able to check the
    literal spelling each side happens to use.
    """
    collapsed = re.sub(r"\$?\{[^}]*\}", "{}", path)
    return collapsed.rstrip("/") or "/"


def parse_routes(text: str, rel: str) -> dict[str, RouteDecl]:
    """Every route the module's router declares, keyed ``METHOD /path``.

    Read from the decorators rather than from the module docstring's endpoint
    list, which is prose and was already one route out of date.
    """
    tree = _parse_python(text, rel)
    prefix = _router_prefix(tree)
    out: dict[str, RouteDecl] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            target = decorator.func.value
            if not (isinstance(target, ast.Name) and target.id == "router"):
                continue
            method = decorator.func.attr.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            if not (decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)):
                continue
            decl = RouteDecl(method=method, path=_normalise_path(prefix + decorator.args[0].value), handler=node.name)
            out[decl.key] = decl
    return out


def _mentions_event_orm(node: ast.AST) -> bool:
    """Whether a subtree names the event ORM class at all."""
    return any(isinstance(inner, ast.Name) and inner.id == EVENT_ORM for inner in ast.walk(node))


def _event_order_columns(node: ast.AST) -> set[str]:
    """Event columns a subtree's ``order_by(...)`` calls name.

    Picks up ``InvestigationEvent.seq`` directly and ``InvestigationEvent.seq
    .asc()``, where the interesting attribute is one level in.
    """
    columns: set[str] = set()
    for inner in ast.walk(node):
        if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) and inner.func.attr == "order_by"):
            continue
        for argument in inner.args:
            for attribute in ast.walk(argument):
                if not isinstance(attribute, ast.Attribute):
                    continue
                owner = attribute.value
                if isinstance(owner, ast.Name) and owner.id == EVENT_ORM:
                    columns.add(attribute.attr)
    return columns


def parse_event_queries(text: str, rel: str) -> list[EventQuery]:
    """Per handler: does it read a collection of events, and how does it order them?

    The unit is the handler rather than the individual query, deliberately.
    These are chained builders — ``list_events`` assigns ``select(...)`` in one
    statement, narrows it in a second, and appends ``order_by`` in a third —
    so pairing an ``order_by`` with the ``select`` it belongs to would need
    dataflow, and a gate that guesses at that is worse than one that is coarse
    and says so. The cost of the coarseness is stated: a handler that orders
    one event query correctly and leaves a second unordered passes here.

    A handler qualifies when it both builds a ``select(InvestigationEvent)``
    and materialises a list with ``.all()``. ``explain_step`` qualifies — its
    ``.all()`` is over artifacts, but it does order its neighbour lookups by
    ``seq``, which is the same property. A handler that only ever reads one
    event by exact ``seq`` makes no ordering claim and is not asked for one.
    """
    tree = _parse_python(text, rel)
    out: list[EventQuery] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        selects_events = any(
            isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "select" and _mentions_event_orm(call)
            for call in ast.walk(node)
        )
        reads_a_collection = any(
            isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "all" for call in ast.walk(node)
        )
        if not (selects_events and reads_a_collection):
            continue
        ordered_by = _event_order_columns(node)
        out.append(
            EventQuery(
                handler=node.name,
                orders_by_sequence=SEQUENCE_COLUMN in ordered_by,
                other_order_columns=tuple(sorted(ordered_by - {SEQUENCE_COLUMN})),
            )
        )
    return out


# ---------------------------------------------------------------------------
# TypeScript: the interface and the client
# ---------------------------------------------------------------------------


def _strip_ts_comments(text: str) -> str:
    """Block and line comments, so documentation cannot satisfy a requirement.

    A commented-out field is not a field either, which is the other half of
    why this runs first.
    """
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"^\s*//.*$", "", without_blocks, flags=re.MULTILINE)


def _balanced_body(text: str, open_at: int) -> str:
    """The text between ``text[open_at]`` and its matching close brace."""
    depth, i = 1, open_at + 1
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[open_at + 1 : i - 1]


def parse_ts_interface_fields(text: str, name: str) -> set[str]:
    """Field names of one exported TypeScript interface."""
    stripped = _strip_ts_comments(text)
    match = re.search(rf"export\s+interface\s+{re.escape(name)}\s*(?:extends\s+[\w<>,\s]+?)?\{{", stripped)
    if match is None:
        raise GateError(f"{API_TS_REL}: no exported interface named {name}")
    body = _balanced_body(stripped, match.end() - 1)
    # Only top-level members: a nested inline object type would otherwise
    # contribute its own keys as if they were fields of the interface.
    fields: set[str] = set()
    depth = 0
    for line in body.splitlines():
        if depth == 0:
            member = re.match(r"\s*(\w+)\??\s*:", line)
            if member:
                fields.add(member.group(1))
        depth += line.count("{") - line.count("}")
    return fields


def ledger_path_from_literal(literal: str) -> str | None:
    """The ledger route a request literal addresses, or ``None``.

    The discriminator is what precedes ``/investigations``: an optional base
    URL placeholder and an optional API version prefix, and nothing else.
    ``/api/v1/cases/${caseId}/investigations/${runId}/report.md`` is a *cases*
    route that happens to contain the word, and crediting it here would both
    invent a client path the router does not declare and falsely mark a
    genuinely unconsumed route as consumed.
    """
    collapsed = re.sub(r"\$\{[^}]*\}", "{}", literal)
    index = collapsed.find(ROUTER_PREFIX_DEFAULT)
    if index < 0:
        return None
    if not re.fullmatch(r"(\{\})?(/api/v\d+)?", collapsed[:index]):
        return None
    return _normalise_path(collapsed[index:].split("?")[0].strip())


def parse_client_paths(text: str, object_name: str) -> set[str]:
    """Ledger paths the named client object requests.

    Scoped to that object rather than to the file: ``api.ts`` is five thousand
    lines and holds every client in the console, and a path another client
    happens to build is not this contract's business.
    """
    stripped = _strip_ts_comments(text)
    match = re.search(rf"export\s+const\s+{re.escape(object_name)}\s*=\s*\{{", stripped)
    if match is None:
        raise GateError(f"{API_TS_REL}: no exported const named {object_name}")
    body = _balanced_body(stripped, match.end() - 1)
    paths = {ledger_path_from_literal(literal) for literal in re.findall(r"[`'\"]([^`'\"]*)[`'\"]", body)}
    return {p for p in paths if p}


def parse_consumer_paths(sources: dict[str, str]) -> set[str]:
    """Ledger paths anything under the web source requests.

    Wider than ``ledgerApi`` on purpose. ``/timeline`` is called by
    ``InvestigationTimeline.tsx`` through a bare ``fetch``, so a
    consumed-or-recorded check that only read the typed client would demand a
    reason for a route that has a caller.
    """
    found: set[str] = set()
    for text in sources.values():
        stripped = _strip_ts_comments(text)
        for literal in re.findall(r"[`'\"]([^`'\"\n]*)[`'\"]", stripped):
            path = ledger_path_from_literal(literal)
            if path:
                found.add(path)
    return found


# ---------------------------------------------------------------------------
# SQL: what the writer writes, what the schema creates
# ---------------------------------------------------------------------------


def _strip_sql_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


def _split_top_level(text: str) -> list[str]:
    """Split on commas at paren depth zero."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _balanced_parens(text: str, open_at: int) -> tuple[str, int]:
    """The text inside ``text[open_at]``'s parens, and the index after them."""
    depth, i = 1, open_at + 1
    while i < len(text) and depth:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    return text[open_at + 1 : i - 1], i


_TERMINATORS = ("WHERE", "RETURNING", "FROM")


def _set_clause(sql: str, start: int) -> str:
    """An ``UPDATE ... SET`` assignment list, up to the first clause that ends it."""
    depth = 0
    i = start
    while i < len(sql):
        char = sql[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0:
            upper = sql[i:].upper()
            for keyword in _TERMINATORS:
                if upper.startswith(keyword) and (i == 0 or not sql[i - 1].isalnum()):
                    tail = sql[i + len(keyword) : i + len(keyword) + 1]
                    if not tail.isalnum() and tail != "_":
                        return sql[start:i]
        i += 1
    return sql[start:]


def _executed_sql(text: str, rel: str) -> list[str]:
    """Every SQL literal the module hands to a database call.

    By ``ast``, and only the first string argument of an ``execute`` /
    ``fetch`` / ``fetchrow`` / ``fetchval`` call, so the module docstring's
    description of the tables is not mistaken for a write to them.
    """
    tree = _parse_python(text, rel)
    statements: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in {"execute", "executemany", "fetch", "fetchrow", "fetchval"}:
            continue
        for argument in node.args[:1]:
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                statements.append(argument.value)
    return statements


def parse_written_columns(text: str, rel: str, tables: tuple[str, ...]) -> dict[str, set[str]]:
    """Columns the module's INSERT and UPDATE statements write, per table."""
    out: dict[str, set[str]] = {table: set() for table in tables}
    for raw in _executed_sql(text, rel):
        sql = _strip_sql_comments(raw)
        for match in re.finditer(r"INSERT\s+INTO\s+(\w+)\s*\(", sql, re.IGNORECASE):
            table = match.group(1)
            if table not in out:
                continue
            columns, _ = _balanced_parens(sql, match.end() - 1)
            out[table].update(part.split()[0] for part in _split_top_level(columns))
        for match in re.finditer(r"UPDATE\s+(\w+)\s+SET\s+", sql, re.IGNORECASE):
            table = match.group(1)
            if table not in out:
                continue
            for assignment in _split_top_level(_set_clause(sql, match.end())):
                # The target is everything before the first `=`. Reading only
                # that keeps `total_cost_usd = COALESCE($6, total_cost_usd)`
                # from crediting whatever names appear inside the expression.
                name = assignment.split("=", 1)[0].strip()
                if re.fullmatch(r"\w+", name):
                    out[table].add(name)
    return out


_TABLE_CONSTRAINT_KEYWORDS = ("primary", "unique", "foreign", "check", "constraint", "exclude", "like")


SchemaFacts = tuple[dict[str, set[str]], dict[str, str], dict[str, set[tuple[str, ...]]]]


def parse_schema(sql_by_file: dict[str, str], tables: tuple[str, ...]) -> SchemaFacts:
    """Columns, creating file, and unique constraints for each named table.

    Reads ``CREATE TABLE`` *and* every later ``ADD COLUMN``, because half the
    column additions in this repository are ``ALTER TABLE ... ADD COLUMN IF
    NOT EXISTS`` in a later migration — four of the columns the ledger writer
    writes to ``investigation_runs`` arrived in 063, so a gate reading only
    the creating migration would report four findings against a working tree.
    """
    columns: dict[str, set[str]] = {table: set() for table in tables}
    created_in: dict[str, str] = {}
    uniques: dict[str, set[tuple[str, ...]]] = {table: set() for table in tables}

    for rel, raw in sorted(sql_by_file.items()):
        sql = _strip_sql_comments(raw)
        for match in re.finditer(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", sql, re.IGNORECASE):
            table = match.group(1)
            if table not in columns:
                continue
            created_in.setdefault(table, rel)
            body, _ = _balanced_parens(sql, match.end() - 1)
            for fragment in _split_top_level(body):
                head = fragment.split()[0]
                if head.lower() in _TABLE_CONSTRAINT_KEYWORDS:
                    if head.lower() == "unique":
                        inner, _ = _balanced_parens(fragment, fragment.index("("))
                        uniques[table].add(tuple(part.split()[0] for part in _split_top_level(inner)))
                    continue
                columns[table].add(head)
        for match in re.finditer(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)\b", sql, re.IGNORECASE):
            table = match.group(1)
            if table not in columns:
                continue
            statement = sql[match.end() :].split(";", 1)[0]
            columns[table].update(
                m.group(1) for m in re.finditer(r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", statement, re.IGNORECASE)
            )
            for m in re.finditer(r"ADD\s+(?:CONSTRAINT\s+\w+\s+)?UNIQUE\s*\(", statement, re.IGNORECASE):
                inner, _ = _balanced_parens(statement, m.end() - 1)
                uniques[table].add(tuple(part.split()[0] for part in _split_top_level(inner)))
    return columns, created_in, uniques


# ---------------------------------------------------------------------------
# Reading the tree
# ---------------------------------------------------------------------------


def _read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        raise GateError(f"{rel} is missing; the ledger replay contract cannot be checked")
    return path.read_text(encoding="utf-8", errors="replace")


def collect(root: Path) -> Corpus:
    endpoints = _read(root, ENDPOINTS_REL)
    api_ts = _read(root, API_TS_REL)
    writer = _read(root, WRITER_REL)

    migrations_dir = root / MIGRATIONS_DIR_REL
    if not migrations_dir.is_dir():
        raise GateError(f"{MIGRATIONS_DIR_REL} is missing; the ledger schema cannot be read")
    sql_by_file = {
        str(path.relative_to(root)): path.read_text(encoding="utf-8", errors="replace") for path in sorted(migrations_dir.glob("*.sql"))
    }
    if not sql_by_file:
        raise GateError(f"{MIGRATIONS_DIR_REL} holds no .sql files; the ledger schema cannot be read")

    web_src = root / WEB_SRC_REL
    if not web_src.is_dir():
        raise GateError(f"{WEB_SRC_REL} is missing; ledger route consumers cannot be read")
    web_sources = {
        str(path.relative_to(root)): path.read_text(encoding="utf-8", errors="replace")
        for pattern in ("**/*.ts", "**/*.tsx")
        for path in sorted(web_src.glob(pattern))
    }
    if not web_sources:
        raise GateError(f"{WEB_SRC_REL} holds no TypeScript; ledger route consumers cannot be read")

    delegate = root / DELEGATE_REL
    delegate_reads_writer = delegate.is_file() and DELEGATE_SCOPE_MARKER in delegate.read_text(encoding="utf-8", errors="replace")

    schema_columns, created_in, uniques = parse_schema(sql_by_file, LEDGER_TABLES)
    return Corpus(
        model_fields=parse_model_fields(endpoints, ENDPOINTS_REL, RESPONSE_MODEL),
        ts_fields=parse_ts_interface_fields(api_ts, TS_INTERFACE),
        routes=parse_routes(endpoints, ENDPOINTS_REL),
        client_paths=parse_client_paths(api_ts, CLIENT_OBJECT),
        consumer_paths=parse_consumer_paths(web_sources),
        written_columns=parse_written_columns(writer, WRITER_REL, LEDGER_TABLES),
        schema_columns=schema_columns,
        created_in_migration=created_in,
        unique_constraints=uniques,
        event_queries=parse_event_queries(endpoints, ENDPOINTS_REL),
        delegate_reads_writer=delegate_reads_writer,
    )


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------


def _vacuity(corpus: Corpus) -> list[Finding]:
    """Refusals for a corpus that credits nothing.

    Each of these is a state in which every comparison below would pass over
    an empty set, which is the failure this repository has shipped most often.
    """
    out: list[Finding] = []
    if not corpus.model_fields:
        out.append(Finding("EMPTY-MODEL", f"{ENDPOINTS_REL}: {RESPONSE_MODEL} parsed with no fields"))
    if not corpus.ts_fields:
        out.append(Finding("EMPTY-TS", f"{API_TS_REL}: {TS_INTERFACE} parsed with no fields"))
    if not corpus.routes:
        out.append(Finding("EMPTY-ROUTES", f"{ENDPOINTS_REL}: no router decorators parsed"))
    if not corpus.client_paths:
        out.append(Finding("EMPTY-CLIENT", f"{API_TS_REL}: {CLIENT_OBJECT} parsed with no request paths"))
    for table in LEDGER_TABLES:
        if not corpus.schema_columns.get(table):
            out.append(Finding("EMPTY-SCHEMA", f"{table}: no columns parsed from {MIGRATIONS_DIR_REL}"))
        if not corpus.written_columns.get(table):
            out.append(Finding("EMPTY-WRITER", f"{table}: no columns parsed from {WRITER_REL}"))
    if not corpus.event_queries:
        out.append(Finding("EMPTY-HANDLERS", f"{ENDPOINTS_REL}: no handler parsed as reading more than one {EVENT_ORM}"))
    return out


def _field_findings(corpus: Corpus) -> list[Finding]:
    out: list[Finding] = []
    for name in sorted(corpus.model_fields - corpus.ts_fields):
        out.append(
            Finding(
                "FIELD-PY-NOT-IN-TS",
                f"{RESPONSE_MODEL}.{name} is serialised to the console and {TS_INTERFACE} does not declare it, "
                f"so every replay drops it silently at the boundary",
            )
        )
    for name in sorted(corpus.ts_fields - corpus.model_fields):
        out.append(
            Finding(
                "FIELD-TS-NOT-IN-PY",
                f"{TS_INTERFACE}.{name} is read by the console and {RESPONSE_MODEL} never sends it, "
                f"so the replay view renders it as permanently absent",
            )
        )
    return out


def _route_findings(corpus: Corpus) -> list[Finding]:
    out: list[Finding] = []
    declared = {decl.path for decl in corpus.routes.values()}

    for path in sorted(corpus.client_paths - declared):
        out.append(
            Finding(
                "ROUTE-CLIENT-ORPHAN",
                f"{CLIENT_OBJECT} requests {path} and the router declares no such route — the console would 404 here",
            )
        )

    for key, decl in sorted(corpus.routes.items()):
        consumed = decl.path in corpus.client_paths or any(path == decl.path for path in corpus.consumer_paths)
        if consumed or key in SERVER_ONLY_ROUTES:
            continue
        out.append(
            Finding(
                "ROUTE-UNCONSUMED",
                f"{key} (handler {decl.handler}) is declared and nothing under {WEB_SRC_REL} calls it; "
                f"wire it or record it in SERVER_ONLY_ROUTES with a reason",
            )
        )

    # Both directions on the recorded list, so an entry cannot outlive its need.
    for key in sorted(SERVER_ONLY_ROUTES):
        if key not in corpus.routes:
            out.append(Finding("ROUTE-STALE-EXEMPTION", f"SERVER_ONLY_ROUTES names {key} and the router no longer declares it"))
            continue
        path = corpus.routes[key].path
        if path in corpus.client_paths or path in corpus.consumer_paths:
            out.append(
                Finding(
                    "ROUTE-STALE-EXEMPTION",
                    f"SERVER_ONLY_ROUTES excuses {key} as server-only and the console now calls it; drop the entry",
                )
            )
    return out


def _column_findings(corpus: Corpus) -> list[Finding]:
    out: list[Finding] = []

    # The delegated direction has to be covered by somebody. If the gate that
    # owns it is gone or has narrowed away from this writer, that is a gap in
    # this contract even though the check lives elsewhere.
    if not corpus.delegate_reads_writer:
        out.append(
            Finding(
                "COLUMN-DELEGATION-MISSING",
                f"{DELEGATE_REL} no longer reads {DELEGATE_SCOPE_MARKER}, so nothing checks that a column "
                f"{WRITER_REL} writes is a column some migration creates; bring that direction back here",
            )
        )

    for table in LEDGER_TABLES:
        written = corpus.written_columns.get(table, set())
        schema = corpus.schema_columns.get(table, set())
        for column in sorted(schema - written):
            if (table, column) in UNWRITTEN_COLUMNS:
                continue
            out.append(
                Finding(
                    "COLUMN-UNWRITTEN",
                    f"{table}.{column} exists in the schema and {WRITER_REL} never writes it; "
                    f"write it or record it in UNWRITTEN_COLUMNS with a reason",
                )
            )
    for (table, column), reason in sorted(UNWRITTEN_COLUMNS.items()):
        if column not in corpus.schema_columns.get(table, set()):
            out.append(
                Finding(
                    "COLUMN-STALE-EXEMPTION",
                    f"UNWRITTEN_COLUMNS names {table}.{column} ({reason}) and the schema has no such column",
                )
            )
        elif column in corpus.written_columns.get(table, set()):
            out.append(
                Finding(
                    "COLUMN-STALE-EXEMPTION",
                    f"UNWRITTEN_COLUMNS excuses {table}.{column} as unwritten and the writer now writes it",
                )
            )
    return out


def _sequence_findings(corpus: Corpus) -> list[Finding]:
    """The assertions that make "every step" mean an ordered, unduplicated one."""
    out: list[Finding] = []

    if SEQUENCE_COLUMN not in corpus.written_columns.get(EVENTS_TABLE, set()):
        out.append(
            Finding(
                "SEQ-UNSTAMPED",
                f"{WRITER_REL} appends to {EVENTS_TABLE} without writing {SEQUENCE_COLUMN}, so the steps carry no order to replay",
            )
        )

    creating = corpus.created_in_migration.get(EVENTS_TABLE)
    if creating != CREATING_MIGRATION_REL:
        out.append(
            Finding(
                "SEQ-SCHEMA-MOVED",
                f"{EVENTS_TABLE} is created in {creating or 'no migration this gate read'} and this gate was written against "
                f"{CREATING_MIGRATION_REL}; point it at the new creating migration deliberately",
            )
        )

    expected = (RUN_COLUMN, SEQUENCE_COLUMN)
    if expected not in corpus.unique_constraints.get(EVENTS_TABLE, set()):
        out.append(
            Finding(
                "SEQ-NOT-UNIQUE",
                f"{EVENTS_TABLE} has no UNIQUE {expected} constraint, so a replayed write appends a second copy of a step "
                f"instead of conflicting, and the ledger reports a run that never happened that way",
            )
        )

    for query in corpus.event_queries:
        if not query.orders_by_sequence:
            out.append(
                Finding(
                    "SEQ-UNORDERED-READ",
                    f"{ENDPOINTS_REL}: {query.handler} reads a collection of {EVENT_ORM} rows with no ORDER BY {SEQUENCE_COLUMN} — "
                    f"Postgres promises no order without one, so the replay is a set of steps rather than a sequence",
                )
            )
        if query.other_order_columns:
            out.append(
                Finding(
                    "SEQ-ORDERED-BY-CLOCK",
                    f"{ENDPOINTS_REL}: {query.handler} orders {EVENT_ORM} rows by {list(query.other_order_columns)} — "
                    f"only {SEQUENCE_COLUMN} is monotonic within a run; timestamps tie at the resolution the agent writes "
                    f"them and a clock correction can move one backwards",
                )
            )
    return out


def evaluate(corpus: Corpus) -> list[Finding]:
    vacuous = _vacuity(corpus)
    if vacuous:
        # A corpus that credits nothing cannot also render a drift verdict:
        # every comparison below would pass over an empty set and the two
        # kinds of failure would be indistinguishable in the output.
        return vacuous
    return _field_findings(corpus) + _route_findings(corpus) + _column_findings(corpus) + _sequence_findings(corpus)


def exit_status(findings: list[Finding]) -> int:
    """0 clean, 1 drift, 2 the scan itself could not run.

    A corpus that parsed nothing is the third case, not the second: there is
    no drift to report because nothing was compared, and rounding it to 1
    would have the gate claim it found a disagreement it never looked for.
    """
    if not findings:
        return 0
    return 2 if any(finding.code.startswith("EMPTY-") for finding in findings) else 1


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _probe_corpus() -> Corpus:
    """A minimal corpus that passes, so each injection below changes one thing.

    Built *from* the recorded exception lists rather than beside them: a probe
    that hard-coded its own route set would start reporting stale exemptions
    the moment somebody added a legitimate one, and the temptation would then
    be to weaken the check rather than the probe.
    """
    routes = {"GET /investigations/{}/replay": RouteDecl("GET", "/investigations/{}/replay", "replay_run")}
    for key in SERVER_ONLY_ROUTES:
        method, path = key.split(" ", 1)
        routes[key] = RouteDecl(method, path, f"{path.strip('/').replace('/', '_')}_handler")

    columns = {table: {"id", RUN_COLUMN, SEQUENCE_COLUMN} for table in LEDGER_TABLES}
    schema = {table: set(cols) for table, cols in columns.items()}
    for table, column in UNWRITTEN_COLUMNS:
        schema[table].add(column)

    return Corpus(
        model_fields={"id", "seq", "input_hash"},
        ts_fields={"id", "seq", "input_hash"},
        routes=routes,
        client_paths={"/investigations/{}/replay"},
        consumer_paths={"/investigations/{}/replay"},
        written_columns=columns,
        schema_columns=schema,
        created_in_migration=dict.fromkeys(LEDGER_TABLES, CREATING_MIGRATION_REL),
        unique_constraints={table: {(RUN_COLUMN, SEQUENCE_COLUMN)} for table in LEDGER_TABLES},
        event_queries=[EventQuery("replay_run", orders_by_sequence=True)],
        delegate_reads_writer=True,
    )


def _self_test_cases() -> list[tuple[str, bool]]:
    """Injected drift for each property, in both directions.

    A gate that has never failed is not known to work, and the shapes it must
    catch are cheap to construct — so they are constructed here rather than
    left to whoever next changes the tree.
    """
    cases: list[tuple[str, bool]] = []

    def codes(mutate) -> set[str]:
        corpus = _probe_corpus()
        mutate(corpus)
        return {finding.code for finding in evaluate(corpus)}

    cases.append(("a clean corpus is clean", evaluate(_probe_corpus()) == []))

    # 1. Field parity, both ways.
    cases.append(
        (
            "a field added to the response model and not to TypeScript is caught",
            "FIELD-PY-NOT-IN-TS" in codes(lambda c: c.model_fields.add("output_hash")),
        )
    )
    cases.append(
        (
            "a field renamed on the Python side alone is caught in both directions",
            codes(lambda c: (c.model_fields.discard("input_hash"), c.model_fields.add("inputHash")))
            >= {"FIELD-PY-NOT-IN-TS", "FIELD-TS-NOT-IN-PY"},
        )
    )
    cases.append(
        (
            "a field TypeScript reads and no response sends is caught",
            "FIELD-TS-NOT-IN-PY" in codes(lambda c: c.ts_fields.add("pivot_path")),
        )
    )

    # 2. Route parity, both ways.
    cases.append(
        (
            "a client request against a route the router never declares is caught",
            "ROUTE-CLIENT-ORPHAN" in codes(lambda c: c.client_paths.add("/investigations/{}/attack-graph")),
        )
    )
    cases.append(
        (
            "deleting one route decorator while the client still calls it is caught",
            "ROUTE-CLIENT-ORPHAN" in codes(lambda c: c.routes.pop("GET /investigations/{}/replay")),
        )
    )
    cases.append(
        (
            "a declared route nothing calls and nothing records is caught",
            "ROUTE-UNCONSUMED"
            in codes(
                lambda c: c.routes.__setitem__(
                    "GET /investigations/{}/orphan", RouteDecl("GET", "/investigations/{}/orphan", "orphan_handler")
                )
            ),
        )
    )
    cases.append(
        (
            "a recorded server-only route the console has started calling is caught",
            "ROUTE-STALE-EXEMPTION"
            in codes(lambda c: c.consumer_paths.update(corpus_routes.path for corpus_routes in _probe_corpus().routes.values())),
        )
    )

    # 3. Writer/schema parity and the sequencing assertions.
    cases.append(
        (
            "a schema column the writer never writes is caught",
            "COLUMN-UNWRITTEN" in codes(lambda c: c.schema_columns[EVENTS_TABLE].add("signed_by")),
        )
    )
    cases.append(
        (
            "losing the gate this one delegates the other column direction to is caught",
            "COLUMN-DELEGATION-MISSING" in codes(lambda c: setattr(c, "delegate_reads_writer", False)),
        )
    )
    cases.append(
        (
            f"{DELEGATE_REL} is present and still reads {DELEGATE_SCOPE_MARKER}",
            (repo_root() / DELEGATE_REL).is_file()
            and DELEGATE_SCOPE_MARKER in (repo_root() / DELEGATE_REL).read_text(encoding="utf-8", errors="replace"),
        )
    )
    cases.append(
        (
            "a recorded unwritten column the writer has started writing is caught",
            "COLUMN-STALE-EXEMPTION" in codes(lambda c: [c.written_columns[table].add(column) for table, column in UNWRITTEN_COLUMNS]),
        )
    )
    cases.append(
        (
            "an event append with no sequence number is caught",
            "SEQ-UNSTAMPED" in codes(lambda c: c.written_columns[EVENTS_TABLE].discard("seq")),
        )
    )
    cases.append(
        (
            "dropping UNIQUE (run_id, seq) is caught",
            "SEQ-NOT-UNIQUE" in codes(lambda c: c.unique_constraints[EVENTS_TABLE].clear()),
        )
    )
    cases.append(
        (
            "a replay handler that reads a collection of steps with no ORDER BY seq is caught",
            "SEQ-UNORDERED-READ" in codes(lambda c: c.event_queries.__setitem__(0, EventQuery("replay_run", orders_by_sequence=False))),
        )
    )
    by_clock = EventQuery("replay_run", orders_by_sequence=True, other_order_columns=("ts",))
    cases.append(
        (
            "a replay handler that orders steps by the clock instead of the sequence is caught",
            "SEQ-ORDERED-BY-CLOCK" in codes(lambda c: c.event_queries.__setitem__(0, by_clock)),
        )
    )
    cases.append(
        (
            "ordering by the clock is read off the source, not assumed",
            parse_event_queries(
                "async def replay(db):\n"
                "    q = select(InvestigationEvent).order_by(InvestigationEvent.ts.asc())\n"
                "    return (await db.execute(q)).scalars().all()\n",
                "probe.py",
            )
            == [EventQuery("replay", orders_by_sequence=False, other_order_columns=("ts",))],
        )
    )

    # 4. Non-vacuity: every corpus that credits nothing is refused.
    for label, mutate, code in (
        ("no model fields", lambda c: c.model_fields.clear(), "EMPTY-MODEL"),
        ("no TypeScript fields", lambda c: c.ts_fields.clear(), "EMPTY-TS"),
        ("no routes and no client paths", lambda c: (c.routes.clear(), c.client_paths.clear()), "EMPTY-ROUTES"),
        ("no parsed schema columns", lambda c: c.schema_columns[EVENTS_TABLE].clear(), "EMPTY-SCHEMA"),
        ("no parsed writer columns", lambda c: c.written_columns[EVENTS_TABLE].clear(), "EMPTY-WRITER"),
        ("no event-list handlers", lambda c: c.event_queries.clear(), "EMPTY-HANDLERS"),
    ):
        cases.append((f"a corpus with {label} is refused rather than called clean", code in codes(mutate)))

    # 5. The parsers themselves, on the shapes that would make them lie.
    cases.append(
        (
            "a table named only in a docstring is not parsed as a write",
            parse_written_columns('"""Writes investigation_events (id, seq)."""\n', "probe.py", LEDGER_TABLES)[EVENTS_TABLE] == set(),
        )
    )
    cases.append(
        (
            "a COALESCE self-reference credits the target column and nothing inside the expression",
            parse_written_columns(
                'conn.execute("UPDATE investigation_runs SET total_cost_usd = COALESCE($1, total_cost_usd) WHERE id = $2")\n',
                "probe.py",
                LEDGER_TABLES,
            )["investigation_runs"]
            == {"total_cost_usd"},
        )
    )
    cases.append(
        (
            "a cases route containing the word investigations is not a ledger path",
            ledger_path_from_literal("/api/v1/cases/${caseId}/investigations/${runId}/report.md") is None,
        )
    )
    cases.append(
        (
            "a bare fetch against a base-URL variable is a ledger path",
            ledger_path_from_literal("${apiBase}/investigations/${runId}/timeline") == "/investigations/{}/timeline",
        )
    )
    cases.append(
        (
            "a documented-but-absent TypeScript field is not a field",
            parse_ts_interface_fields("export interface Probe {\n  // ghost: string;\n  real: number;\n}\n", "Probe") == {"real"},
        )
    )
    cases.append(
        (
            "a single-event read with no ORDER BY is not demanded to have one",
            parse_event_queries(
                "async def focus(db):\n"
                "    q = select(InvestigationEvent).where(InvestigationEvent.seq == step)\n"
                "    return (await db.execute(q)).scalar_one_or_none()\n",
                "probe.py",
            )
            == [],
        )
    )

    return cases


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="tree to render a verdict about (defaults to git)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable findings + counts")
    parser.add_argument("--self-test", action="store_true", help="prove the gate still detects what it claims")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    root = args.repo_root or repo_root()
    try:
        corpus = collect(root)
    except GateError as exc:
        print(f"UNABLE: {exc}")
        return 2

    findings = evaluate(corpus)
    counts = corpus.counts()
    status = exit_status(findings)

    if args.as_json:
        print(json.dumps({"counts": counts, "findings": [{"code": f.code, "detail": f.detail} for f in findings]}, indent=2))
        return status

    scanned = ", ".join(f"{value} {name.replace('_', ' ')}" for name, value in counts.items())
    if findings:
        print(f"FAIL: the investigation ledger's replay contract disagrees across trees ({len(findings)} finding(s))")
        for finding in findings:
            print(f"  - {finding}")
        print(f"\nscanned: {scanned}")
        return status

    print("OK: the investigation ledger's replay contract agrees across its three trees")
    print(f"     {scanned}")
    print(
        f"     {len(SERVER_ONLY_ROUTES)} route(s) recorded server-only, "
        f"{len(UNWRITTEN_COLUMNS)} column(s) recorded unwritten, each with a reason"
    )
    print(f"     a column written but never created is {DELEGATE_REL}'s direction, and that gate still reads {DELEGATE_SCOPE_MARKER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
