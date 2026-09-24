#!/usr/bin/env python3
"""Every column a model declares must be a column some migration creates.

Why this exists
---------------

``services/ueba/app/models/ueba.py`` declared ``EntityBaseline.peer_group_id``
and migration ``0001`` never created it. SQLAlchemy names every mapped column
in its ``SELECT``, so the *first* database call UEBA's scoring path makes
raised ``UndefinedColumnError``. UEBA could therefore never write a baseline
or an anomaly, on any deployment, from the day the column was added — and
because the consumer had no ``except``, the container stayed ``running`` with
``/health`` answering 200 the whole time.

Two more of the same kind were in the same three tables:
``ueba_peer_groups.id`` was created ``UUID`` and declared ``String(64)`` while
the code wrote ``dept:engineering`` into it, and ``ueba_anomalies.event_type``
was created 64 characters wide and declared 128.

None of this needed a database to find. The model and the migration are both
in the tree, and the disagreement is structural. That is what this reads.

What it checks, in both directions
----------------------------------

``missing-in-migration``
    A model declares a column no migration creates. This is the direction
    that breaks at runtime, and it breaks on the first query rather than on
    some rare path, because the column list is in the ``SELECT``.

``missing-in-model``
    A migration creates a column no model declares. Not a crash, so it is
    reported separately and carries a recorded reason — but it is checked,
    because a gate that only looks one way passes while drift accumulates in
    the other. Three of the four cases here turned out to be
    ``server_default`` columns nothing maps, and one was a table whose model
    had been renamed.

``type-narrower-in-migration``
    Both sides have the column and the database's is too small to hold what
    the model will send. ``String(64)`` in a table against ``String(128)`` in
    the model passes every test that inserts a short value.

``no-migration-source``
    A model declares a table **no migration anywhere mentions**. This is the
    finding that exists because of how this gate could have been useless: a
    table the parser fails to pair contributes zero column comparisons, and
    zero findings over zero comparisons prints the same word as a clean
    result. ``--credits`` exists for the same reason — it enumerates what
    each verdict was *based on*, so a parser that silently credits nothing
    can be caught by reading rather than by trusting the exit code.

What it reads
-------------

Structurally, both sides. Models: Python ``ast`` over
``services/*/app/**`` for classes carrying ``__tablename__``, collecting
``mapped_column`` / ``Column`` assignments. Migrations: Python ``ast`` over
each alembic chain for ``op.create_table`` / ``op.add_column`` /
``op.drop_column``, plus the raw-SQL statements those revisions and
``services/api/migrations/*.sql`` execute, because half the column additions
in this repository are ``ALTER TABLE … ADD COLUMN IF NOT EXISTS`` inside a
string.

Usage
-----

::

    python3 scripts/check_orm_migration_parity.py           # table + verdict
    python3 scripts/check_orm_migration_parity.py --check    # gate
    python3 scripts/check_orm_migration_parity.py --credits  # what it credited
    python3 scripts/check_orm_migration_parity.py --json
    python3 scripts/check_orm_migration_parity.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

REPO_ROOT = repo_root()
SERVICES_DIR = REPO_ROOT / "services"

#: Where a service's raw-SQL chain lives, if it has one. Alembic chains are
#: discovered from ``alembic.ini`` instead, since two of the four do not put
#: them under a directory named ``alembic``.
SQL_MIGRATION_DIRS = ("migrations",)

#: Directories under ``services/<svc>/`` that never hold models worth pairing.
_SKIP_PARTS = frozenset({"tests", "test", "_vendor", "node_modules", "__pycache__", "alembic", "versions"})


# ---------------------------------------------------------------------------
# Recorded exceptions
# ---------------------------------------------------------------------------
#
# Shrink-only, and verified in both directions: an entry that stops being
# needed fails the build rather than sitting here. Each one says why, because
# a bare list of table names is a second place for drift to hide.

#: ``(table, column)`` a migration creates and no model maps. Harmless by
#: construction — every one carries a ``server_default``, so an insert that
#: does not name it still succeeds — but recorded rather than ignored.
UNMAPPED_COLUMNS: dict[tuple[str, str], str] = {
    ("ueba_entity_baselines", "observation_count"): "server_default '0'; the rolling count lives in feature_stats instead",
    ("ueba_entity_baselines", "created_at"): "server_default now(); the model exposes window_start/updated_at",
    ("ueba_anomalies", "z_scores"): "server_default '{}'; superseded by the per-feature z_score inside features",
    ("ueba_peer_groups", "created_at"): "server_default now(); the model exposes updated_at",
}

#: Tables whose model is mapped but whose creation this gate cannot see, with
#: the reason. Empty on purpose: it exists so that adding one is a deliberate,
#: reviewed act rather than the default outcome of a parser that missed
#: something.
UNSOURCED_TABLES: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Model side
# ---------------------------------------------------------------------------


def _string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


#: SQL type name → family. Two spellings of the same family are not drift
#: (``Text`` against ``String``, ``BigInteger`` against ``Integer``); two
#: families are, and one such mismatch is why this mapping exists.
#:
#: ``ueba_peer_groups.id`` was created ``UUID DEFAULT gen_random_uuid()`` and
#: declared ``String(64)``, and the code wrote ``dept:engineering`` into it —
#: an ``InvalidTextRepresentation`` on the first insert. A length comparison
#: could not see it: neither side declares a length that the other contradicts,
#: so the column read as agreed. Found by re-running this gate against the
#: tree as it was and noticing that it reported two of the three known
#: defects, which is the question `--credits` is for: what does it credit as
#: clean, not what does it flag.
_TYPE_FAMILIES: dict[str, str] = {
    # SQLAlchemy constructors and SQL type names share this table on purpose:
    # the two sides have to be classified identically or the comparison is
    # between two different vocabularies.
    "string": "string",
    "str": "string",
    "text": "string",
    "unicode": "string",
    "unicodetext": "string",
    "varchar": "string",
    "char": "string",
    "citext": "string",
    "uuid": "uuid",
    "guid": "uuid",
    "integer": "integer",
    "int": "integer",
    "int4": "integer",
    "int8": "integer",
    "smallint": "integer",
    "bigint": "integer",
    "smallinteger": "integer",
    "biginteger": "integer",
    "serial": "integer",
    "bigserial": "integer",
    "float": "numeric",
    "numeric": "numeric",
    "decimal": "numeric",
    "real": "numeric",
    "double": "numeric",
    "boolean": "boolean",
    "bool": "boolean",
    "json": "json",
    "jsonb": "json",
    "datetime": "datetime",
    "timestamp": "datetime",
    "timestamptz": "datetime",
    "date": "datetime",
    "time": "datetime",
    "interval": "interval",
    "largebinary": "binary",
    "bytea": "binary",
    "inet": "inet",
    "array": "array",
    "enum": "enum",
}


def _family(name: str | None) -> str | None:
    """The family of a type name, or None when it is one this gate cannot rank.

    Unknown is not a mismatch. A vendor type or a custom ``TypeDecorator``
    must not be reported as drift just because this table has not heard of
    it — a gate that invents findings gets turned off, and then it is not
    checking the ones it was right about either.
    """
    return _TYPE_FAMILIES.get(name.strip().lower()) if name else None


def _declared_type(call: ast.Call) -> tuple[str | None, int | None]:
    """``(family, string_length)`` of the type in a column definition.

    The length is only read for ``String``: the other families either carry
    no length or carry one whose mismatch is not silently lossy the way a
    truncating varchar is.
    """
    for node in ast.walk(call):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        family = _family(name)
        if family is None:
            continue
        if family != "string":
            return family, None
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                return family, arg.value
        for kw in node.keywords:
            if kw.arg == "length" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return family, kw.value.value
        # ``String`` with no length is unbounded text — never too narrow.
        return family, None
    return None, None


def _column_from_assignment(node: ast.AST) -> tuple[str, tuple[str | None, int | None]] | None:
    """``(column_name, string_length)`` for one class-body assignment.

    Handles the two spellings in this tree: SQLAlchemy 2.0
    ``name: Mapped[T] = mapped_column(...)`` and the older
    ``name = Column(...)``. The column's name is the attribute name unless
    the call passes an explicit string first — ``mapped_column("other", ...)``
    — which is the case a regex over attribute names would get wrong.
    """
    if isinstance(node, ast.AnnAssign):
        target, value = node.target, node.value
    elif isinstance(node, ast.Assign) and len(node.targets) == 1:
        target, value = node.targets[0], node.value
    else:
        return None
    if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
        return None

    func = value.func
    callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    if callee not in {"mapped_column", "Column"}:
        return None

    name = target.id
    if value.args and (explicit := _string(value.args[0])):
        name = explicit
    return name, _declared_type(value)


def model_tables(paths: list[pathlib.Path]) -> dict[str, dict]:
    """Mapped tables, by table name, from the model modules given."""
    tables: dict[str, dict] = {}
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            tablename: str | None = None
            columns: dict[str, tuple[str | None, int | None]] = {}
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    only = stmt.targets[0]
                    if isinstance(only, ast.Name) and only.id == "__tablename__":
                        tablename = _string(stmt.value)
                found = _column_from_assignment(stmt)
                if found is not None:
                    columns[found[0]] = found[1]
            if tablename and columns:
                tables[tablename] = {
                    "columns": columns,
                    "source": str(path.relative_to(REPO_ROOT)),
                    "model": node.name,
                }
    return tables


# ---------------------------------------------------------------------------
# Migration side
# ---------------------------------------------------------------------------

#: ``CREATE TABLE [IF NOT EXISTS] name ( ... )`` — the body is scanned for
#: leading identifiers, one per column definition.
_CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?(\w+)[\"']?\s*\((.*?)\);", re.I | re.S)
_ADD_COLUMN = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?[\"']?(\w+)[\"']?\s+ADD\s+COLUMN\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?[\"']?(\w+)[\"']?\s*([A-Za-z]*)\s*(?:\((\d+)\))?",
    re.I,
)
_DROP_COLUMN = re.compile(r"ALTER\s+TABLE\s+(?:ONLY\s+)?[\"']?(\w+)[\"']?\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?[\"']?(\w+)[\"']?", re.I)
_ALTER_TYPE = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?[\"']?(\w+)[\"']?\s+ALTER\s+COLUMN\s+[\"']?(\w+)[\"']?\s+"
    r"(?:SET\s+DATA\s+)?TYPE\s+([A-Za-z]+)\s*(?:\((\d+)\))?",
    re.I,
)

#: Words that begin a table-level constraint rather than a column.
_CONSTRAINT_WORDS = frozenset({"primary", "unique", "foreign", "constraint", "check", "exclude", "like"})


def _split_columns(body: str) -> list[tuple[str, str | None, int | None]]:
    """Column ``(name, length)`` pairs from a ``CREATE TABLE`` body."""
    depth = 0
    current: list[str] = []
    parts: list[str] = []
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))

    out: list[tuple[str, str | None, int | None]] = []
    for part in parts:
        tokens = part.strip().strip('"').split()
        if not tokens:
            continue
        name = tokens[0].strip('"').strip(",")
        if not name or not name.replace("_", "").isalnum() or name.lower() in _CONSTRAINT_WORDS:
            continue
        family: str | None = None
        length: int | None = None
        if len(tokens) > 1:
            # ``VARCHAR(64)`` arrives as one token; the family is the part
            # before the parenthesis.
            declared = tokens[1].split("(")[0]
            family = _family(declared)
            if match := re.search(r"\((\d+)\)", tokens[1]):
                length = int(match.group(1))
        out.append((name, family, length))
    return out


def _record(
    store: dict[str, dict[str, tuple[str | None, int | None]]],
    table: str,
    column: str,
    family: str | None,
    length: int | None,
) -> None:
    store.setdefault(table, {})[column] = (family, length)


def _scan_sql(text: str, store: dict[str, dict[str, tuple[str | None, int | None]]], dropped: set[tuple[str, str]]) -> None:
    for table, body in _CREATE_TABLE.findall(text):
        for column, family, length in _split_columns(body):
            _record(store, table, column, family, length)
    for table, column, type_name, length in _ADD_COLUMN.findall(text):
        _record(store, table, column, _family(type_name), int(length) if length else None)
    for table, column, type_name, length in _ALTER_TYPE.findall(text):
        # Only widens what is already known; an ALTER TYPE on a column this
        # scan never saw created is still a column it never saw created.
        if column in store.get(table, {}):
            _record(store, table, column, _family(type_name), int(length) if length else None)
    for table, column in _DROP_COLUMN.findall(text):
        dropped.add((table, column))


def _scan_alembic_module(tree: ast.AST, store: dict[str, dict[str, tuple[str | None, int | None]]], dropped: set[tuple[str, str]]) -> None:
    """``op.*`` table and column operations, plus the SQL they execute."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        op_name = node.func.attr

        if op_name == "execute":
            for arg in node.args:
                for literal in ast.walk(arg):
                    if (sql := _string(literal)) and "TABLE" in sql.upper():
                        _scan_sql(sql, store, dropped)
            continue

        if op_name == "create_table" and node.args:
            table = _string(node.args[0])
            if not table:
                continue
            for arg in node.args[1:]:
                if isinstance(arg, ast.Call) and (column := _string(arg.args[0]) if arg.args else None):
                    _record(store, table, column, *_declared_type(arg))
            continue

        if op_name == "add_column" and len(node.args) >= 2:
            table = _string(node.args[0])
            spec = node.args[1]
            if table and isinstance(spec, ast.Call) and spec.args and (column := _string(spec.args[0])):
                _record(store, table, column, *_declared_type(spec))
            continue

        if op_name == "alter_column" and len(node.args) >= 2:
            table, column = _string(node.args[0]), _string(node.args[1])
            if not table or not column or column not in store.get(table, {}):
                continue
            for kw in node.keywords:
                if kw.arg == "type_" and isinstance(kw.value, ast.Call):
                    _record(store, table, column, *_declared_type(kw.value))
            continue

        if op_name == "drop_column" and len(node.args) >= 2:
            table, column = _string(node.args[0]), _string(node.args[1])
            if table and column:
                dropped.add((table, column))


def _upgrade_only(path: pathlib.Path) -> ast.Module | None:
    """The revision's ``upgrade()`` body, with ``downgrade()`` removed.

    ``downgrade`` drops what ``upgrade`` creates. Scanning the whole module
    made every revision cancel itself out — the parser credited a column and
    then recorded it as dropped, so a correct chain reported every column
    missing. Caught by reading ``--credits``, not by the exit code.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, OSError):
        return None
    tree.body = [node for node in tree.body if not (isinstance(node, ast.FunctionDef) and node.name.startswith("downgrade"))]
    return tree


def migration_columns(service: pathlib.Path) -> tuple[dict[str, dict[str, tuple[str | None, int | None]]], set[tuple[str, str]], list[str]]:
    """Columns this service's migrations create, columns they drop, files read."""
    store: dict[str, dict[str, tuple[str | None, int | None]]] = {}
    dropped: set[tuple[str, str]] = set()
    read: list[str] = []

    # Alembic chain, located from alembic.ini rather than assumed: osquery-tls
    # keeps its chain under app/db, and a gate that globbed for a directory
    # named `alembic` would have reported that service as having no migrations
    # at all — which is a clean result, wrongly.
    ini = service / "alembic.ini"
    if ini.is_file():
        match = re.search(r"^\s*script_location\s*=\s*(.+?)\s*$", ini.read_text(encoding="utf-8"), re.M)
        if match:
            versions = service / match.group(1).strip() / "versions"
            for path in sorted(versions.glob("*.py")):
                tree = _upgrade_only(path)
                if tree is not None:
                    _scan_alembic_module(tree, store, dropped)
                    read.append(str(path.relative_to(REPO_ROOT)))

    for name in SQL_MIGRATION_DIRS:
        for path in sorted((service / name).glob("*.sql")):
            _scan_sql(path.read_text(encoding="utf-8", errors="replace"), store, dropped)
            read.append(str(path.relative_to(REPO_ROOT)))

    return store, dropped, read


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def model_paths(service: pathlib.Path) -> list[pathlib.Path]:
    return [path for path in sorted((service / "app").rglob("*.py")) if not _SKIP_PARTS & set(path.relative_to(service).parts)]


def creates_tables_from_metadata(paths: list[pathlib.Path]) -> str | None:
    """The file where this service calls ``metadata.create_all``, if it does.

    This is the line that decides whether the check applies, and why it is
    read structurally rather than assumed per service.

    A service that calls ``create_all`` on the way up builds its tables from
    the models, so a column the models declare and no migration creates is
    *created anyway* — the migrations are supplemental there, adding columns
    to tables the ORM already owns. ``services/api`` is the one such service
    in this tree, and it accounts for 173 of the 173 disagreements found
    before this distinction existed. Holding it to the same rule would have
    meant either 173 allowlist entries or a gate nobody could turn on.

    A migration-managed service has no such fallback, which is exactly why
    UEBA's missing column was fatal rather than cosmetic.

    Those services are still scanned, counted, and printed — ``--all`` shows
    their findings — because "excluded" has to be visible. An exclusion that
    prints nothing is the same defect one level up.
    """
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "create_all":
                return str(path.relative_to(REPO_ROOT))
    return None


def scan() -> dict:
    if not SERVICES_DIR.is_dir():
        return {"error": f"no services directory at {SERVICES_DIR}"}

    services: list[dict] = []
    for service in sorted(p for p in SERVICES_DIR.iterdir() if p.is_dir()):
        if not (service / "app").is_dir():
            continue
        paths = model_paths(service)
        models = model_tables(paths)
        if not models:
            continue
        create_all = creates_tables_from_metadata(paths)
        created, dropped, files = migration_columns(service)
        if not files:
            # A service with models and no migration chain manages its schema
            # elsewhere (create_all, or another service's chain). Not a
            # finding, but counted, so `--credits` shows it was considered.
            services.append(
                {
                    "service": service.name,
                    "schema_source": "orm" if create_all else "none",
                    "tables": len(models),
                    "columns": sum(len(t["columns"]) for t in models.values()),
                    "migration_files": 0,
                    "findings": [],
                    "credits": {},
                }
            )
            continue

        findings: list[dict] = []
        credits: dict[str, dict] = {}
        for table, spec in sorted(models.items()):
            table_columns = {c: spec_t for c, spec_t in created.get(table, {}).items() if (table, c) not in dropped}
            credits[table] = {
                "model": spec["model"],
                "model_source": spec["source"],
                "migration_columns": sorted(table_columns),
            }
            if not table_columns:
                if table in UNSOURCED_TABLES:
                    credits[table]["recorded"] = UNSOURCED_TABLES[table]
                    continue
                findings.append(
                    {
                        "kind": "no-migration-source",
                        "table": table,
                        "column": "*",
                        "detail": f"{spec['source']} maps {spec['model']} to {table}; no migration in this service creates it",
                    }
                )
                continue

            for column, (model_family, model_length) in sorted(spec["columns"].items()):
                if column not in table_columns:
                    findings.append(
                        {
                            "kind": "missing-in-migration",
                            "table": table,
                            "column": column,
                            "detail": f"{spec['model']} declares it; no migration creates it. Every query naming this table will fail.",
                        }
                    )
                    continue
                table_family, table_length = table_columns[column]

                if model_family and table_family and model_family != table_family:
                    findings.append(
                        {
                            "kind": "type-family-mismatch",
                            "table": table,
                            "column": column,
                            "detail": f"{spec['model']} declares {model_family}; the table is {table_family}",
                        }
                    )
                    # The width question is meaningless across families.
                    continue

                if model_length is not None and table_length is not None and table_length < model_length:
                    findings.append(
                        {
                            "kind": "type-narrower-in-migration",
                            "table": table,
                            "column": column,
                            "detail": f"{spec['model']} declares String({model_length}); the table is {table_length} wide",
                        }
                    )

            for column in sorted(table_columns):
                if column in spec["columns"] or (table, column) in UNMAPPED_COLUMNS:
                    continue
                findings.append(
                    {
                        "kind": "missing-in-model",
                        "table": table,
                        "column": column,
                        "detail": f"a migration creates it; {spec['model']} does not map it",
                    }
                )

        services.append(
            {
                "service": service.name,
                "schema_source": "orm" if create_all else "migrations",
                "create_all_at": create_all,
                "tables": len(models),
                "columns": sum(len(t["columns"]) for t in models.values()),
                "migration_files": len(files),
                "findings": findings,
                "credits": credits,
            }
        )

    gated = [s for s in services if s["schema_source"] == "migrations"]
    return {
        "root": str(REPO_ROOT),
        "services": services,
        "gated_services": [s["service"] for s in gated],
        "advisory_services": [s["service"] for s in services if s["schema_source"] != "migrations"],
        "tables": sum(s["tables"] for s in services),
        "columns": sum(s["columns"] for s in services),
        # Only the gated services: quoting the total next to the verdict would
        # credit this check with 832 columns in `api` that it deliberately
        # does not gate.
        "gated_columns": sum(s["columns"] for s in gated),
        "compared": sum(len(s["credits"]) for s in gated),
        "findings": [dict(f, service=s["service"]) for s in gated for f in s["findings"]],
        "advisory_findings": [dict(f, service=s["service"]) for s in services if s["schema_source"] != "migrations" for f in s["findings"]],
    }


def unused_exceptions(result: dict) -> list[str]:
    """Recorded exceptions nothing needs any more.

    The other direction of the same check: an allowlist verified only when it
    forgives something keeps growing, and every stale entry is a column the
    gate has stopped looking at for a reason that no longer exists.
    """
    seen_columns: set[tuple[str, str]] = set()
    seen_tables: set[str] = set()
    for service in result["services"]:
        if service["schema_source"] != "migrations":
            continue
        for table, credit in service["credits"].items():
            seen_tables.add(table)
            for column in credit["migration_columns"]:
                seen_columns.add((table, column))

    stale = [
        f"UNMAPPED_COLUMNS[{key!r}] — {key[1]} is no longer created by any migration" for key in UNMAPPED_COLUMNS if key not in seen_columns
    ]
    stale += [f"UNSOURCED_TABLES[{name!r}] — {name} is no longer a mapped table" for name in UNSOURCED_TABLES if name not in seen_tables]
    return stale


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_INJECTED_MODEL = """
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String

class Widget:
    __tablename__ = "widgets"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    ghost: Mapped[str] = mapped_column(String(32))
    squeezed: Mapped[str] = mapped_column(String(128))
    mistyped: Mapped[str] = mapped_column(String(64))
"""

_INJECTED_MIGRATION = """
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = "0001"
down_revision = None

def upgrade() -> None:
    op.create_table(
        "widgets",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("squeezed", sa.String(64)),
        sa.Column("mistyped", postgresql.UUID(as_uuid=True)),
        sa.Column("orphan", sa.String(8), server_default=""),
    )

def downgrade() -> None:
    op.drop_table("widgets")
"""


def _detects_injected_drift() -> list[tuple[str, bool]]:
    """Prove the gate still catches each kind, on a tree built for the purpose.

    Three synthetic disagreements in one service, one per kind. Run before the
    gate renders any verdict about the real tree, which is the point of a
    self-test: a gate whose parser has quietly stopped matching anything
    reports a clean repository in exactly the same words as a clean one.
    """
    import tempfile

    global REPO_ROOT, SERVICES_DIR  # noqa: PLW0603 — restored below
    saved_root, saved_services = REPO_ROOT, SERVICES_DIR
    try:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            service = root / "services" / "widgetry"
            (service / "app" / "models").mkdir(parents=True)
            (service / "app" / "models" / "widget.py").write_text(_INJECTED_MODEL)
            (service / "alembic" / "versions").mkdir(parents=True)
            (service / "alembic.ini").write_text("[alembic]\nscript_location = alembic\n")
            (service / "alembic" / "versions" / "0001_init.py").write_text(_INJECTED_MIGRATION)

            REPO_ROOT, SERVICES_DIR = root, root / "services"
            kinds = {f["kind"] for f in scan()["findings"]}
    finally:
        REPO_ROOT, SERVICES_DIR = saved_root, saved_services

    return [
        ("detects a model column no migration creates", "missing-in-migration" in kinds),
        ("detects a migration column no model maps", "missing-in-model" in kinds),
        ("detects a column the table is too narrow for", "type-narrower-in-migration" in kinds),
        ("detects a column whose type family disagrees", "type-family-mismatch" in kinds),
    ]


def _detects_unsourced_table() -> list[tuple[str, bool]]:
    """And a mapped table whose creation the parser cannot find at all.

    Separate from the three above because it is the failure mode of this gate
    rather than of the tree: pairing nothing has to be a finding, or a parser
    that matches no migration statement at all reports every service clean.
    """
    import tempfile

    global REPO_ROOT, SERVICES_DIR  # noqa: PLW0603 — restored below
    saved_root, saved_services = REPO_ROOT, SERVICES_DIR
    try:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            service = root / "services" / "widgetry"
            (service / "app" / "models").mkdir(parents=True)
            (service / "app" / "models" / "widget.py").write_text(_INJECTED_MODEL)
            (service / "alembic" / "versions").mkdir(parents=True)
            (service / "alembic.ini").write_text("[alembic]\nscript_location = alembic\n")
            # A revision that creates a different table, so the chain is real
            # and the mapped table is still unaccounted for.
            (service / "alembic" / "versions" / "0001_init.py").write_text(_INJECTED_MIGRATION.replace('"widgets"', '"sprockets"'))
            REPO_ROOT, SERVICES_DIR = root, root / "services"
            kinds = {f["kind"] for f in scan()["findings"]}
    finally:
        REPO_ROOT, SERVICES_DIR = saved_root, saved_services

    return [("detects a mapped table no migration mentions", "no-migration-source" in kinds)]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="ORM/migration column parity")
    parser.add_argument("--check", action="store_true", help="exit non-zero on findings")
    parser.add_argument("--all", action="store_true", help="also list findings for services that build tables from the models")
    parser.add_argument("--credits", action="store_true", help="print what each verdict was based on")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="prove this gate still detects drift")
    args = parser.parse_args()

    if args.self_test:
        return self_test_main(
            pathlib.Path(__file__).name,
            ["--check"],
            extra=[*_detects_injected_drift(), *_detects_unsourced_table()],
        )

    result = scan()
    if "error" in result:
        print(f"orm-parity: {result['error']}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))

    # Naming the root and the corpus size is not decoration. A gate that
    # printed "OK" without them could be reporting on a different checkout,
    # or on none: `found nothing` and `scanned nothing` print the same word.
    if not args.json:
        print(f"orm-parity: root {result['root']}")
        print(f"{'service':<14} {'schema from':<11} {'tables':>6} {'columns':>8} {'migrations':>11} {'findings':>9}")
        print(f"{'-' * 14} {'-' * 11} {'-' * 6} {'-' * 8} {'-' * 11} {'-' * 9}")
        for service in result["services"]:
            print(
                f"{service['service']:<14} {service['schema_source']:<11} {service['tables']:>6} "
                f"{service['columns']:>8} {service['migration_files']:>11} {len(service['findings']):>9}"
            )
        for service in result["services"]:
            if service["schema_source"] == "orm":
                print(
                    f"\n{service['service']}: advisory only — builds its tables from the models at "
                    f"{service['create_all_at']}, so a column no migration creates is created anyway. "
                    f"{len(service['findings'])} disagreement(s); see --all."
                )

    if args.all and result["advisory_findings"]:
        print(f"\nAdvisory ({len(result['advisory_findings'])}), in services whose tables come from the models:")
        for finding in result["advisory_findings"]:
            print(f"  [{finding['kind']}] {finding['service']}: {finding['table']}.{finding['column']}")

    if args.credits:
        print("\nWhat each table's verdict was based on:")
        for service in result["services"]:
            for table, credit in sorted(service["credits"].items()):
                columns = ", ".join(credit["migration_columns"]) or "(nothing — this is a finding)"
                print(f"  {service['service']}/{table} ← {credit['model_source']}::{credit['model']}")
                print(f"      migrations credit: {columns}")

    if not result["gated_services"] or not result["compared"]:
        # The corpus refusal. A tree with no migration-managed table produces
        # no findings, and that is not a clean repository — it is a scan that
        # read nothing, which this must never report as a pass. It also
        # catches the scoping above going wrong: if every service were
        # classified as building its tables from the models, this gate would
        # have nothing left to judge and has to say so rather than pass.
        print(
            f"\norm-parity: paired 0 migration-managed tables under {SERVICES_DIR}. Zero tables "
            f"compared is not zero drift; check the root above is the tree you meant.",
            file=sys.stderr,
        )
        return 1

    stale = unused_exceptions(result)
    findings = result["findings"]

    if not args.json:
        print(
            f"\ngated: {result['compared']} migration-managed table(s), "
            f"{result['gated_columns']} declared column(s) across {len(result['gated_services'])} service(s)"
        )

    if findings:
        print(f"\nFAIL: {len(findings)} ORM/migration disagreement(s):", file=sys.stderr)
        for finding in findings:
            print(
                f"  [{finding['kind']}] {finding['service']}: {finding['table']}.{finding['column']}\n" f"      {finding['detail']}",
                file=sys.stderr,
            )
        print(
            "\nFix: add the column in a new migration (the direction that breaks at runtime), "
            "or record it in UNMAPPED_COLUMNS in this file with the reason it is harmless.",
            file=sys.stderr,
        )
    if stale:
        print("\nFAIL: recorded exceptions that nothing needs any more:", file=sys.stderr)
        for entry in stale:
            print(f"  {entry}", file=sys.stderr)
        print("\nFix: delete them. This list only shrinks.", file=sys.stderr)

    if args.check:
        return 1 if (findings or stale) else 0
    if findings or stale:
        print("\n(advisory run — use --check to make this a gate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
