#!/usr/bin/env python3
"""Every table and column a raw SQL statement names must be one a migration creates.

Why this exists
---------------

``services/api/app/api/v1/endpoints/rule_tuning.py`` inserts an auto-tuner
proposal with a raw ``sqlalchemy.text()`` statement naming fourteen columns of
``detection_rule_proposals``. One of them, ``source``, is created by no
migration in this repository — not in ``010_detection_as_code.sql`` where the
table is defined, not in ``039_detection_proposal_github_pr.sql`` where it is
altered, not anywhere. The statement raises ``UndefinedColumnError`` on the
first row it tries to write, so the human-approval-gated tuning loop cannot
produce a single proposal on any deployment. This gate found it.

Nothing about that needed a database. The statement and the migrations are
both in the tree and the disagreement is structural, which is the same
observation ``check_orm_migration_parity.py`` was written on: UEBA declared
``EntityBaseline.peer_group_id``, migration ``0001`` never created it, and
UEBA could not write a baseline or an anomaly from the day the column was
added. That gate reads ORM-declared models. A raw ``text()`` string is
invisible to it, so the identical failure class had no gate at all over 107
raw statements naming 44 tables — and 35 of those 44 have no ORM model in the
tree at all, so raw SQL is the only thing that writes them and nothing was
checking it.

Two things hid it for as long as they did.

*The claim that a real database already exercised it.* The claim-to-gate
matrix recorded the analyst-disposition tuning loop as ``PARTIAL`` with the
gap "end-to-end proposal insert exercised in api integration, not a unit DB",
which reads as thin coverage of something that does run. No job runs
``services/api/tests/`` against a real database. ``Python — Tests`` in
``ci.yml`` declares no ``postgres`` service and sets
``DATABASE_URL=postgresql+asyncpg://x:x@localhost/x``, a deliberate
non-database. ``integration.yml`` and ``upgrade-test.yml`` are the only
workflows with a live Postgres, and the single API test either of them runs is
``tests/test_mssp_portfolio_isolation.py``. The insert had never touched a
database anywhere.

*A test that greps for the table name.* ``test_wave1_loop_edges.py`` asserted
``"detection_rule_proposals" in str(db.execute.await_args.args[0])``. Being a
substring test it also passes on ``aisoc_detection_rule_proposals``, which
contains the right name inside the wrong one — and that exact confusion is
recorded history here: three insert sites and two tests had codified the
``aisoc_``-prefixed spelling of this very table. A mocked session cannot fail
on a column, so the assertion had nothing else to check.

What it checks, in both directions
----------------------------------

``unknown-table``
    ``INSERT INTO t`` or ``UPDATE t SET`` naming a table no migration creates.
    This is the ``aisoc_detection_rule_proposals`` class exactly, and unlike
    the substring assertion it cannot be satisfied by a name that merely
    contains the right one.

``unknown-column``
    A column in an ``INSERT`` column list, or on the left of a ``SET`` in an
    ``UPDATE`` or an ``ON CONFLICT … DO UPDATE``, that no migration creates on
    that table. ``detection_rule_proposals.source`` is this.

``unparsed-statement``
    The other direction, and the one that decides whether this gate is worth
    anything: a statement whose table or column list is assembled at runtime
    contributes zero comparisons, and zero findings over zero comparisons
    prints the same word as a clean result. Rather than skipping those
    quietly, each is a finding until it is recorded in ``DYNAMIC_SQL`` below
    with a reason. The list is checked in both directions, so an entry nothing
    needs any more fails the build instead of sitting there looking like
    coverage.

``--credits`` exists for the same reason: it enumerates what each verdict was
based on, so a parser that has silently stopped matching can be caught by
reading rather than by trusting the exit code.

What it reads
-------------

Statements: Python ``ast`` over ``services/*/app/**/*.py``, every string
constant and f-string in the module rather than only the arguments of
``text()`` — the SQL in ``services/fusion/app/services/alert_sink.py`` and
``services/agents/app/hunt/store.py`` is a module-level constant that
something else wraps later, and a gate keyed on the call site would not see
either. An f-string renders with ``{}`` where its interpolations were, which
is how a runtime-assembled table or column list becomes visible as one.

Schema: the migration parsers in ``check_orm_migration_parity.py``, imported
rather than reimplemented. Two parsers of the same DDL drift the first time
either learns something the other has not, and this repository has the scars:
its graph-schema check declared OK while one side had 17 labels and the other
28. Reusing them also fixed two gaps that only a column-level reader would
notice — a ``--`` comment line swallowed the column definition after it, and
``ALTER TABLE … RENAME COLUMN`` was never applied, so four ``connectors``
columns were known to the parser under names nothing in the tree uses.

Scope: every service with an ``app/`` directory, which on today's tree is 893
modules yielding 107 statements — ``api`` 75, ``agents`` 20, ``fusion`` 5,
``actions`` 3, ``slack-bot`` 2, ``osquery-tls`` 1, ``ueba`` 1. Small enough to
triage one by one, so nothing is narrowed to keep the number down.

The schema is the union of every migration source in the repository — 85 SQL
files under ``services/api/migrations`` plus the four alembic chains, 131
tables and 1,582 columns — because it is one Postgres. ``services/agents`` and
``services/fusion`` own no migrations and write to tables ``services/api``
creates, so a per-service comparison would have reported every one of their
25 statements as unsourced.

Usage
-----

::

    python3 scripts/check_raw_sql_columns.py            # gate
    python3 scripts/check_raw_sql_columns.py --list      # every statement read
    python3 scripts/check_raw_sql_columns.py --credits   # what it credited
    python3 scripts/check_raw_sql_columns.py --json
    python3 scripts/check_raw_sql_columns.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import pathlib
import re
import sys
import tempfile

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. Both siblings sit beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

# `--self-test` is answered in `main()` rather than through
# `self_test_if_requested`, because that shortcut is for gates with nothing
# bespoke to add and this one has five injected-drift cases to run alongside
# the shared empty-tree refusal. Installing it here would exit before any of
# them, leaving a self-test that proves only half of what it prints.
from check_orm_migration_parity import migration_columns, strip_sql_comments
from gate_toolkit import repo_root, self_test_main

REPO_ROOT = repo_root()
SERVICES_DIR = REPO_ROOT / "services"

#: Directories under ``services/<svc>/app/`` that hold no production SQL.
#: Tests are excluded because a fixture may name a table on purpose to assert
#: what happens when it is wrong.
_SKIP_PARTS = frozenset({"tests", "test", "_vendor", "node_modules", "__pycache__"})

#: What an f-string interpolation renders as. Anything carrying this was
#: assembled at runtime and cannot be compared against a migration.
DYNAMIC = "{}"


# ---------------------------------------------------------------------------
# Recorded exceptions
# ---------------------------------------------------------------------------
#
# Shrink-only, and verified in both directions: an entry that stops being
# needed fails the build rather than sitting here.
#
# Two lists rather than one, because they excuse genuinely different things
# and collapsing them would let either reason cover the other. A table no
# migration owns is a fact about the table, so it is keyed on the table and
# forgives the column check with it. A statement assembled at runtime is a
# fact about that one statement, so it is keyed on (file, table as written) —
# and it only ever excuses a statement this parser could not read, so an
# ordinary INSERT in an allow-listed file is still held to the contract.

#: Tables that exist but whose creation no migration under ``services/`` owns.
UNMIGRATED_TABLES: dict[str, str] = {
    "aisoc.raw_events": (
        "ClickHouse, not Postgres. The event lake's table is created by "
        "services/fusion/app/services/lake_writer.py with CREATE DATABASE / CREATE TABLE IF NOT EXISTS on "
        "startup — the ECS ClickHouse task does not run docker-entrypoint-initdb.d — so no migration "
        "declares it and no migration should."
    ),
    "aisoc_schema_migrations": (
        "The Postgres migration runner's own ledger, created by CREATE_MIGRATIONS_TABLE in "
        "services/api/app/scripts/run_migrations.py before any migration executes. A migration chain "
        "cannot be asked to declare the table that records which migrations ran — the same reason "
        "alembic's version table is in no revision."
    ),
}

#: Statements whose table or column list is assembled at runtime, and so
#: cannot be compared against anything, with the reason.
DYNAMIC_SQL: dict[tuple[str, str], str] = {
    (
        "services/api/app/db/lake_migrations.py",
        DYNAMIC,
    ): (
        "The ClickHouse lake's own migration ledger: the table is `MIGRATION_TABLE` "
        "('aisoc._migrations'), interpolated, and this module creates it. Same reason as "
        "`aisoc_schema_migrations` above, one store over."
    ),
    (
        "services/api/app/api/v1/endpoints/cases.py",
        "aisoc_cases",
    ): (
        "A PATCH handler: the SET clause is `', '.join(sets)` over whichever fields the request body "
        "supplied, so there is no column list in the source to compare. The columns it can append are "
        "literals in this function, which is the read a human has to do."
    ),
    (
        "services/api/app/api/v1/endpoints/cases.py",
        "aisoc_case_tasks",
    ): "A PATCH handler on case tasks, same shape as the one above.",
    (
        "services/api/app/api/v1/endpoints/hunts.py",
        "aisoc_hunts",
    ): "A PATCH handler on saved hunts, same shape as the two above.",
    (
        "services/api/app/scripts/seed_demo.py",
        DYNAMIC,
    ): (
        "The demo re-anchor sweep walks `_REANCHOR_TABLES` and shifts every timestamp column it names, so "
        "both the table and the assignment list are interpolated per iteration. Demo-mode seeding, not a "
        "production write path."
    ),
    (
        "services/osquery-tls/app/db/env.py",
        DYNAMIC,
    ): ("Alembic's own bookkeeping: the table is `VERSION_TABLE`, interpolated, and alembic creates it rather than a revision."),
}


# ---------------------------------------------------------------------------
# Schema side
# ---------------------------------------------------------------------------


def migration_schema(services_dir: pathlib.Path) -> tuple[dict[str, set[str]], dict[str, str], int]:
    """``({table: columns}, {table: owning service}, migration files read)``.

    The union across every service that ships migrations, because the services
    share one Postgres: ``services/agents`` writes ``investigation_runs`` and
    ``services/fusion`` writes ``alerts``, both created under
    ``services/api/migrations``.
    """
    schema: dict[str, set[str]] = {}
    owner: dict[str, str] = {}
    files = 0
    for service in sorted(p for p in services_dir.iterdir() if p.is_dir()):
        created, dropped, read = migration_columns(service)
        if not read:
            continue
        files += len(read)
        for table, columns in created.items():
            live = {c for c in columns if (table, c) not in dropped}
            if not live:
                continue
            schema.setdefault(table, set()).update(live)
            owner.setdefault(table, service.name)
    return schema, owner, files


# ---------------------------------------------------------------------------
# Statement side
# ---------------------------------------------------------------------------

_INSERT = re.compile(r"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+([^\s(;]+)", re.I)
_UPDATE = re.compile(r"\bUPDATE\s+(?:ONLY\s+)?([^\s(;]+)\s+SET\b", re.I)
_DO_UPDATE = re.compile(r"\bDO\s+UPDATE\s+SET\b", re.I)

#: Where a ``SET`` clause ends. ``FROM`` is included because Postgres allows
#: ``UPDATE t SET … FROM other``, and reading past it would collect the joined
#: table's columns as if they were assignments.
_SET_END = re.compile(r"\b(WHERE|RETURNING|FROM)\b", re.I)

_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


def _render(node: ast.AST) -> str | None:
    """A string literal's text, with ``{}`` where an f-string interpolated.

    Rendering rather than skipping is what makes a runtime-assembled table
    name or column list *visible*. ``f"INSERT INTO {VERSION_TABLE} …"`` comes
    back as ``INSERT INTO {} …``, which this gate reports as unparsed instead
    of failing to notice.
    """
    if isinstance(node, ast.Constant):
        text = node.value if isinstance(node.value, str) else None
    elif isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append(DYNAMIC)
        text = "".join(parts)
    else:
        return None
    # Comments are stripped through the same helper the migration side uses.
    # Three ordinary upserts here read as assembled at runtime purely because
    # a `--` note sat inside their SET clause and the comma-split collected it
    # as if it were an assignment.
    return strip_sql_comments(text) if text else text


def _balanced(text: str, start: int) -> tuple[str, int] | None:
    """The contents of the parenthesised group beginning at or after ``start``.

    Returns ``None`` when the next non-space character is not ``(``, which is
    how ``INSERT INTO t VALUES (…)`` — no column list — is told apart from
    ``INSERT INTO t (a, b) VALUES (…)``.
    """
    index = start
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "(":
        return None
    depth = 0
    for position in range(index, len(text)):
        if text[position] == "(":
            depth += 1
        elif text[position] == ")":
            depth -= 1
            if depth == 0:
                return text[index + 1 : position], position + 1
    return None


def _split_top_level(body: str) -> list[str]:
    """``body`` split on commas outside any parentheses."""
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
    return parts


def _column_names(parts: list[str]) -> tuple[list[str], bool]:
    """``(identifiers, every part was a plain identifier)``.

    The flag is the honest half. A part this cannot read — an expression, a
    cast, an interpolation — means the list is not fully accounted for, and
    comparing the identifiers it *did* read while staying silent about the
    rest would credit the statement with more scrutiny than it received.
    """
    names: list[str] = []
    complete = True
    for part in parts:
        token = part.strip().strip('"').strip()
        if _IDENTIFIER.match(token):
            names.append(token)
        elif token:
            complete = False
    return names, complete


def _set_columns(text: str, start: int) -> tuple[list[str], bool]:
    """Assigned column names in the ``SET`` clause beginning at ``start``."""
    clause = text[start:]
    if end := _SET_END.search(clause):
        clause = clause[: end.start()]
    names: list[str] = []
    complete = True
    for part in _split_top_level(clause):
        left = part.split("=", 1)[0].strip().strip('"').strip()
        if not left:
            continue
        # `t.col = …` is still an assignment to `col`.
        if "." in left:
            left = left.rsplit(".", 1)[-1].strip('"')
        if _IDENTIFIER.match(left):
            names.append(left)
        else:
            complete = False
    return names, complete


def statements_in(source: str, relpath: str) -> list[dict]:
    """Every raw ``INSERT`` / ``UPDATE`` in one module's string literals."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    found: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant | ast.JoinedStr):
            continue
        text = _render(node)
        if not text or not ("INSERT" in text.upper() or "UPDATE" in text.upper()):
            continue
        line = getattr(node, "lineno", 0)

        inserts: list[tuple[int, dict]] = []
        for match in _INSERT.finditer(text):
            group = _balanced(text, match.end())
            columns, complete = _column_names(_split_top_level(group[0])) if group else ([], True)
            statement = {
                "kind": "INSERT",
                "file": relpath,
                "line": line,
                "table": match.group(1).strip('"'),
                "columns": columns,
                # A statement with no column list names no column to check,
                # which is not the same as one whose list could not be read.
                "columns_declared": group is not None,
                "columns_complete": complete,
            }
            inserts.append((match.start(), statement))
            found.append(statement)

        for match in _UPDATE.finditer(text):
            columns, complete = _set_columns(text, match.end())
            found.append(
                {
                    "kind": "UPDATE",
                    "file": relpath,
                    "line": line,
                    "table": match.group(1).strip('"'),
                    "columns": columns,
                    "columns_declared": True,
                    "columns_complete": complete,
                }
            )

        # `ON CONFLICT … DO UPDATE SET` assigns to the table of the INSERT it
        # belongs to, so it is the same column contract under another spelling
        # — and upserts are how most of this repository writes.
        for match in _DO_UPDATE.finditer(text):
            preceding = [statement for position, statement in inserts if position < match.start()]
            if not preceding:
                continue
            columns, complete = _set_columns(text, match.end())
            found.append(
                {
                    "kind": "UPSERT",
                    "file": relpath,
                    "line": line,
                    "table": preceding[-1]["table"],
                    "columns": columns,
                    "columns_declared": True,
                    "columns_complete": complete,
                }
            )

    return found


def service_statements(services_dir: pathlib.Path, root: pathlib.Path) -> tuple[list[dict], int]:
    """Statements across ``services/*/app/**/*.py``, and the file count read."""
    found: list[dict] = []
    read = 0
    for service in sorted(p for p in services_dir.iterdir() if p.is_dir()):
        app = service / "app"
        if not app.is_dir():
            continue
        for path in sorted(app.rglob("*.py")):
            if _SKIP_PARTS & set(path.relative_to(service).parts):
                continue
            read += 1
            try:
                relpath = str(path.relative_to(root))
            except ValueError:
                relpath = str(path)
            found.extend(statements_in(path.read_text(encoding="utf-8", errors="replace"), relpath))
    return found, read


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def scan(root: pathlib.Path | None = None) -> dict:
    root = root or REPO_ROOT
    services_dir = root / "services"
    if not services_dir.is_dir():
        return {"error": f"no services directory at {services_dir}"}

    schema, owner, migration_files = migration_schema(services_dir)
    statements, files_read = service_statements(services_dir, root)

    findings: list[dict] = []
    credits: list[dict] = []
    foreign_used: set[str] = set()
    dynamic_used: set[tuple[str, str]] = set()

    for statement in statements:
        table = statement["table"]
        key = (statement["file"], table)

        if table in UNMIGRATED_TABLES:
            foreign_used.add(table)
            credits.append({**statement, "verdict": "unmigrated-table", "detail": UNMIGRATED_TABLES[table]})
            continue

        # Only a statement this parser could not read may be excused as
        # dynamic. A file holding one assembled statement does not get its
        # ordinary ones forgiven along with it.
        if DYNAMIC in table or not statement["columns_complete"]:
            if key in DYNAMIC_SQL:
                dynamic_used.add(key)
                credits.append({**statement, "verdict": "runtime-assembled", "detail": DYNAMIC_SQL[key]})
                continue
            findings.append(
                {
                    **statement,
                    "kind_of_finding": "unparsed-statement",
                    "column": "*",
                    "detail": (
                        f"{statement['kind']} into {table!r} is assembled at runtime, so no table or column "
                        "here was compared against a migration. Record it in DYNAMIC_SQL with the reason."
                    ),
                }
            )
            continue

        if table not in schema:
            findings.append(
                {
                    **statement,
                    "kind_of_finding": "unknown-table",
                    "column": "*",
                    "detail": f"no migration creates a table named {table!r}. Every execution of this statement fails.",
                }
            )
            continue

        unknown = [column for column in statement["columns"] if column not in schema[table]]
        for column in unknown:
            findings.append(
                {
                    **statement,
                    "kind_of_finding": "unknown-column",
                    "column": column,
                    "detail": (
                        f"{statement['kind']} names {table}.{column}; no migration creates it on that table "
                        f"(migrations for {table} come from services/{owner[table]})."
                    ),
                }
            )
        credits.append(
            {
                **statement,
                "verdict": "compared",
                "detail": f"{len(statement['columns'])} column(s) against services/{owner[table]} migrations",
            }
        )

    stale = [
        f"UNMIGRATED_TABLES[{name!r}] — no raw statement names that table any more"
        for name in UNMIGRATED_TABLES
        if name not in foreign_used
    ]
    stale += [
        f"DYNAMIC_SQL[{key!r}] — no statement there is assembled at runtime any more, so it is checkable"
        for key in DYNAMIC_SQL
        if key not in dynamic_used
    ]

    return {
        "root": str(root),
        "files_read": files_read,
        "migration_files": migration_files,
        "schema_tables": len(schema),
        "schema_columns": sum(len(c) for c in schema.values()),
        "statements": statements,
        "credits": credits,
        "compared": sum(1 for c in credits if c["verdict"] == "compared"),
        "recorded": sum(1 for c in credits if c["verdict"] != "compared"),
        "tables_touched": sorted({s["table"] for s in statements if DYNAMIC not in s["table"]}),
        "findings": findings,
        "stale": stale,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_GOOD_MIGRATION = """
CREATE TABLE IF NOT EXISTS widgets (
    id          UUID PRIMARY KEY,
    -- a comment line, which used to swallow the column behind it
    tenant_id   UUID NOT NULL,
    name        VARCHAR(200) NOT NULL
);
"""

_GOOD_STATEMENT = """
from sqlalchemy import text

SQL = text("INSERT INTO widgets (id, tenant_id, name) VALUES (:id, :tid, :name)")
"""


def _scratch(root: pathlib.Path, statement: str, migration: str = _GOOD_MIGRATION) -> dict:
    service = root / "services" / "widgetry"
    (service / "app" / "api").mkdir(parents=True)
    (service / "app" / "api" / "widgets.py").write_text(statement)
    (service / "migrations").mkdir(parents=True)
    (service / "migrations" / "001_init.sql").write_text(migration)
    return scan(root)


def _detects_injected_drift() -> list[tuple[str, bool]]:
    """Prove the gate still catches each kind, on a tree built for the purpose.

    Run before the gate renders any verdict about the real tree, which is the
    point of a self-test: a gate whose parser has quietly stopped matching
    anything reports a clean repository in exactly the same words as a clean
    one.
    """

    def kinds(statement: str) -> set[str]:
        with tempfile.TemporaryDirectory() as raw:
            return {f["kind_of_finding"] for f in _scratch(pathlib.Path(raw), statement)["findings"]}

    def counted(statement: str) -> int:
        with tempfile.TemporaryDirectory() as raw:
            return _scratch(pathlib.Path(raw), statement)["compared"]

    # The defect this gate exists for, in the spelling it actually had: the
    # wrong name contains the right one, so the substring assertion in
    # `test_wave1_loop_edges.py` passed on it.
    wrong_table = _GOOD_STATEMENT.replace("INSERT INTO widgets", "INSERT INTO aisoc_widgets")
    wrong_column = _GOOD_STATEMENT.replace("id, tenant_id, name", "id, tenant_id, source")
    dynamic = 'SQL = f"INSERT INTO {TABLE} (id) VALUES (:id)"\n'

    return [
        ("detects a table no migration creates, on a name containing a real one", kinds(wrong_table) == {"unknown-table"}),
        ("detects a column no migration creates on that table", kinds(wrong_column) == {"unknown-column"}),
        ("passes a statement whose table and every column exist", kinds(_GOOD_STATEMENT) == set()),
        ("credits the passing statement rather than skipping it", counted(_GOOD_STATEMENT) == 1),
        ("refuses a statement assembled at runtime rather than skipping it", kinds(dynamic) == {"unparsed-statement"}),
    ]


def _refuses_a_tree_with_no_statements() -> list[tuple[str, bool]]:
    """And a services tree that parses to no SQL at all.

    Separate from the above because it is the failure mode of this gate rather
    than of the tree: reading no statement has to be a refusal, or a parser
    that matches nothing reports every service clean. The scratch tree
    ``gate_toolkit`` builds has no ``services/`` directory at all; this is the
    other shape, where the directory is there and the corpus is gone.
    """
    with tempfile.TemporaryDirectory() as raw:
        root = pathlib.Path(raw)
        service = root / "services" / "widgetry"
        (service / "app").mkdir(parents=True)
        (service / "app" / "nothing.py").write_text("VALUE = 1\n")
        (service / "migrations").mkdir(parents=True)
        (service / "migrations" / "001_init.sql").write_text(_GOOD_MIGRATION)
        # The probe runs the real `main`, so its refusal is the real refusal
        # rather than a re-implementation of one — captured only so the
        # self-test's own output stays readable.
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            refused = main(["--repo-root", str(root)]) != 0

    return [("refuses a services tree it parsed no SQL out of", refused)]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Raw SQL / migration table and column parity")
    parser.add_argument("--list", action="store_true", help="print every statement read")
    parser.add_argument("--credits", action="store_true", help="print what each verdict was based on")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--repo-root", help="the tree to inspect, instead of this checkout")
    parser.add_argument("--self-test", action="store_true", help="prove this gate still detects drift")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test_main(
            pathlib.Path(__file__).name,
            [],
            extra=[*_detects_injected_drift(), *_refuses_a_tree_with_no_statements()],
        )

    result = scan(pathlib.Path(args.repo_root).resolve() if args.repo_root else None)
    if "error" in result:
        print(f"raw-sql-columns: {result['error']}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))

    # Naming the root and the corpus size is not decoration. A gate that
    # printed "OK" without them could be reporting on a different checkout,
    # or on none: `found nothing` and `scanned nothing` print the same word.
    if not args.json:
        print(f"raw-sql-columns: root {result['root']}")
        print(
            f"read {result['files_read']} module(s) under services/*/app, "
            f"{result['migration_files']} migration file(s) declaring "
            f"{result['schema_tables']} table(s) / {result['schema_columns']} column(s)"
        )
        print(
            f"parsed {len(result['statements'])} raw statement(s) against "
            f"{len(result['tables_touched'])} table(s); {result['compared']} compared, "
            f"{result['recorded']} recorded as unmigrated or runtime-assembled"
        )

    if args.list:
        print("\nEvery statement read:")
        for statement in result["statements"]:
            columns = ", ".join(statement["columns"]) or "(no column list)"
            print(f"  {statement['file']}:{statement['line']} {statement['kind']} {statement['table']}")
            print(f"      {columns}")

    if args.credits:
        print("\nWhat each verdict was based on:")
        for credit in result["credits"]:
            print(f"  [{credit['verdict']}] {credit['file']}:{credit['line']} {credit['kind']} {credit['table']}")
            print(f"      {credit['detail']}")

    if not result["statements"] or not result["compared"]:
        # The corpus refusal. A tree this parses no SQL out of produces no
        # findings, and that is not a clean repository — it is a scan that
        # read nothing, which must never print as a pass. It also catches the
        # extraction above going wrong: a renamed helper, a changed string
        # shape, a glob that stopped matching. None of them removes
        # `services/`.
        print(
            f"\nraw-sql-columns: compared 0 raw statements under {result['root']}/services. Zero statements "
            f"compared is not zero drift; check the root above is the tree you meant.",
            file=sys.stderr,
        )
        return 1

    if result["findings"]:
        print(f"\nFAIL: {len(result['findings'])} raw SQL statement(s) naming something no migration creates:", file=sys.stderr)
        for finding in result["findings"]:
            print(
                f"  [{finding['kind_of_finding']}] {finding['file']}:{finding['line']} "
                f"{finding['table']}.{finding['column']}\n      {finding['detail']}",
                file=sys.stderr,
            )
        print(
            "\nFix: add the table or column in a new migration (the direction that breaks at runtime), "
            "correct the statement, or — only for SQL genuinely assembled at runtime — record it in "
            "DYNAMIC_SQL in this file with the reason.",
            file=sys.stderr,
        )

    if result["stale"]:
        print("\nFAIL: recorded exceptions that nothing needs any more:", file=sys.stderr)
        for entry in result["stale"]:
            print(f"  {entry}", file=sys.stderr)
        print("\nFix: delete them. This list only shrinks.", file=sys.stderr)

    return 1 if (result["findings"] or result["stale"]) else 0


if __name__ == "__main__":
    sys.exit(main())
