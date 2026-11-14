#!/usr/bin/env python3
"""Refuse a `:name::type` cast inside a SQLAlchemy ``text()`` statement.

SQLAlchemy finds bind parameters in a ``text()`` string with
``(?<![:\\w\\x5c]):(\\w+)(?!:)``. The trailing ``(?!:)`` is there so the
Postgres ``::`` cast operator is not mistaken for a parameter — but it does
not skip the construct, it *backtracks one character* and declares a
different, shorter name. So ``:payload::jsonb`` declares ``payloa``,
``:urls::text[]`` declares ``url``, and the ``.bindparams(payload=...)`` that
follows raises ``ArgumentError``.

Three properties make this worth a gate rather than a code review note:

* It raises on the ``.bindparams()`` call, which in every instance found sat
  *outside* the handler's ``try``. So the route did not degrade to its 503
  path — it 500'd, and the statement never reached a connection.
* It is invisible to a reading eye. ``:payload::jsonb`` is what the Postgres
  documentation shows, and the truncated name never appears in the source.
* It survived because the tests covering those routes read the handler's
  source text instead of calling it. A substring assertion cannot fail on
  this, because the substring is present and correct.

Four route handlers were dead this way: ``compliance.collect_evidence``,
``phishing.submit``, ``phishing.retriage`` and ``knowledge_base.ingest``.
``knowledge_base.query_kb`` carried the same spelling, was found, and was
fixed to ``CAST(:kinds AS text[])`` — while the sibling INSERT twenty lines
above it kept the broken form. A gate is what closes that gap.

The fix is always ``CAST(:name AS type)``, which is standard SQL, means the
same thing to Postgres, and leaves the parameter name intact.

Usage:
    python3 scripts/check_text_bind_casts.py
    python3 scripts/check_text_bind_casts.py --self-test
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main

# Verbatim from `sqlalchemy.sql.elements.TextClause._bind_params_regex`. If a
# future SQLAlchemy changes it, this gate reports names that release does not,
# which is the safe direction: it can complain about a statement that works,
# never stay quiet about one that raises.
SQLA_BIND_RE = re.compile(r"(?<![:\w\x5c]):(\w+)(?!:)")

# A `:name` whose next two characters are `::`. The lookbehind mirrors
# SQLAlchemy's so a `::` that is not preceded by a parameter (an `a::b` cast of
# a column, say) is not reported.
CAST_ADJACENT_RE = re.compile(r"(?<![:\w\\]):(\w+)::")

# A bind parameter tested directly for NULL: `:name IS NULL`, or the negated
# form. Postgres has nothing to infer the parameter's type from, so asyncpg
# answers `could not determine data type of parameter $N` — and only when the
# value bound is actually `None`, which is why this survives every test that
# supplies a value. A `CAST(:name AS TEXT) IS NULL` is already typed and is
# not matched.
UNTYPED_NULL_TEST_RE = re.compile(r"(?<![:\w\\]):(\w+)\s+IS\s+(?:NOT\s+)?NULL", re.IGNORECASE)

# The historical prototype subtree is reference-only and is `paths-ignore`d by
# CodeQL for the same reason.
SKIP_PREFIXES = ("plans/",)


def _tracked_python_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.py"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [root / rel for rel in out.split("\0") if rel and not rel.startswith(SKIP_PREFIXES)]


#: A string that is a SQL statement rather than a sentence that happens to
#: contain a colon. Both halves are required: a DML/DDL verb at the start of
#: some line, and a clause keyword somewhere after it. Security software is
#: full of strings that look vaguely like SQL — detection rules, ARNs,
#: synthetic telemetry — and a gate that flags correct content gets switched
#: off within a week, so this is deliberately narrow.
SQL_SHAPED_RE = re.compile(
    r"^\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WITH)\b",
    re.IGNORECASE | re.MULTILINE,
)
SQL_CLAUSE_RE = re.compile(r"\b(?:FROM|WHERE|VALUES|SET|JOIN|RETURNING)\b", re.IGNORECASE)


def _looks_like_sql(text_value: str) -> bool:
    return bool(SQL_SHAPED_RE.search(text_value)) and bool(SQL_CLAUSE_RE.search(text_value))


def _static_string(node: ast.AST) -> str | None:
    """Return the statement text when it can be read without executing anything.

    Handles the three spellings that appear in this tree: a plain literal, an
    implicit or explicit concatenation of literals, and an f-string whose
    interpolations are irrelevant to where the colons fall. A `text()` built
    from a variable is resolved against the module's own constants by
    :func:`_module_constants` — see the note there for what assuming
    otherwise cost.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_string(node.left), _static_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                # An interpolated fragment. Substitute a placeholder that
                # carries no colon so it cannot invent or mask a match.
                parts.append(" ")
        return "".join(parts)
    return None


def _is_text_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "text"
    if isinstance(func, ast.Attribute):
        return func.attr == "text"
    return False


def _module_constants(tree: ast.Module) -> dict[str, tuple[str, int]]:
    """Every module-level or class-level string constant, with its line.

    This exists because the gate shipped with the opposite assumption written
    into :func:`_static_string` as a docstring — *"the statements this defect
    lives in are all inline literals"* — and that sentence was false.
    ``services/connectors/app/vuln_promotion_sql.py`` is a module of SQL
    constants with the ``text()`` wrapper fifteen hundred lines away in
    ``scheduler.py``, and its ``UPSERT_ALERT_SQL`` carried
    ``:affected_hosts::jsonb`` for the whole life of the statement. The sweep
    that statement belongs to is the only path from ``asset_vulnerabilities``
    into the alert queue and it had never created an alert on any deployment.

    A constants module is a style this repository actively encourages — the
    header of that file says the SQL is kept module-level "so tests can pin
    the statements and a reviewer can diff the policy in one place" — so the
    assumption was not merely optimistic, it was at odds with the convention.
    """
    constants: dict[str, tuple[str, int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = _static_string(node.value)
        if value is None:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = (value, node.lineno)
    return constants


def violations(source: str, rel: str) -> list[str]:
    """Report every bind parameter inside a `text()` that needs a cast.

    Two signatures, one family and one fix. `:name::type` declares a
    different, shorter parameter name and raises on `.bindparams()`;
    `:name IS NULL` declares the right name and raises on the connection,
    but only when the value bound is `None`. Both are written
    `CAST(:name AS <type>)`.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{rel}: could not parse ({exc})"]

    constants = _module_constants(tree)

    # (statement text, line to report). Three sources, in one list so a
    # statement reachable two ways is still reported once per line.
    subjects: dict[tuple[int, str], str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_text_call(node) or not node.args:
            continue
        arg = node.args[0]
        statement = _static_string(arg)
        if statement is None and isinstance(arg, ast.Name):
            # `text(SOME_CONSTANT)` — resolve it against this module. Worth
            # doing even though the constants sweep below also sees it,
            # because a statement a `text()` is handed is SQL by definition
            # and does not have to pass the shape heuristic.
            resolved = constants.get(arg.id)
            if resolved is not None:
                statement = resolved[0]
        if statement is None:
            continue
        subjects[(node.lineno, statement)] = statement

    # Module-level SQL that no `text()` in this file wraps. The wrapper can be
    # in another module entirely, so "is this string SQL" has to be decided
    # from the string.
    for name, (value, lineno) in constants.items():
        if not _looks_like_sql(value):
            continue
        subjects.setdefault((lineno, f"{name}"), value)

    found: list[str] = []
    for (lineno, _key), statement in sorted(subjects.items()):
        declared = set(SQLA_BIND_RE.findall(statement))
        found.extend(_statement_violations(statement, declared, rel, lineno))
    return found


def _statement_violations(statement: str, declared: set[str], rel: str, lineno: int) -> list[str]:
    """Both signatures, for one statement."""
    found: list[str] = []
    for match in CAST_ADJACENT_RE.finditer(statement):
        intended = match.group(1)
        if intended in declared:
            # SQLAlchemy resolved this name anyway (it also appears in the
            # statement somewhere a cast does not follow it), so the
            # bindparams call will not raise. Still worth nothing here.
            continue
        truncated = next((d for d in declared if intended.startswith(d) and d != intended), "no parameter")
        found.append(
            f"{rel}:{lineno}: `:{intended}::` declares `{truncated}`, so `.bindparams({intended}=...)` raises. "
            f"Write `CAST(:{intended} AS <type>)`."
        )
    for match in UNTYPED_NULL_TEST_RE.finditer(statement):
        name = match.group(1)
        found.append(
            f"{rel}:{lineno}: `:{name} IS NULL` gives Postgres no type to infer, so asyncpg raises "
            f"`could not determine data type` whenever `{name}` is bound to None — the branch a test that "
            f"always supplies a value never reaches. Write `CAST(:{name} AS <type>) IS NULL`."
        )
    return found


def main() -> int:
    root = repo_root()
    files = _tracked_python_files(root)
    # Every statement this gate is about lives in a service. `scripts/` alone
    # is a runnable copy of the gate over none of its subject, and reporting
    # OK there is a verdict about a tree that is not this one.
    services = [p for p in files if p.relative_to(root).parts[:1] == ("services",)]
    if not services:
        print(
            "check_text_bind_casts: no tracked Python files under services/ — refusing to report a clean tree",
            file=sys.stderr,
        )
        return 1

    problems: list[str] = []
    this_file = Path(__file__).resolve()
    for path in files:
        # This gate's own self-test fixtures are module-level SQL constants
        # carrying the defect deliberately, which the constants sweep below is
        # right to report and which must not fail the build.
        if path.resolve() == this_file:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # No `"text(" not in source: continue` here. That skip is what made
        # this gate structurally blind to the worst instance of the defect it
        # exists to catch: `vuln_promotion_sql.py` contains `text(` zero
        # times, because it is a module of SQL constants and the wrapper lives
        # in `scheduler.py`. A gate whose "unknown" bucket is a pass is
        # broken, and this one did not even have an unknown bucket — it had a
        # silent skip.
        problems.extend(violations(source, str(path.relative_to(root))))

    if problems:
        print("A bind parameter inside a text() statement needs an explicit cast:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"\n{len(problems)} statement(s) would raise rather than run.", file=sys.stderr)
        return 1

    print(
        f"OK: {len(files)} tracked Python file(s) scanned ({len(services)} under services/), "
        "no `:name::type` and no untyped `:name IS NULL` inside a text() statement"
    )
    return 0


_CLEAN = 'q = text("INSERT INTO t (a, b) VALUES (CAST(:payload AS jsonb), :other)").bindparams(payload=x, other=y)'
_BROKEN = 'q = text("INSERT INTO t (a, b) VALUES (:payload::jsonb, :other)").bindparams(payload=x, other=y)'
_NOT_SQL = 'if ":iam::" in resource_id and ":policy/" in resource_id:\n    kind = "policy"'
_CONCAT = 'q = text("SELECT * FROM t" " WHERE k = ANY(:kinds::text[])")'

# The second signature. `_NULL_BROKEN` is the exact statement depth 8.1
# found in `resolve_saml_connection`; `_NULL_CLEAN` is its fix. The
# `NOT NULL` case is here because the same inference failure applies, and
# `_NULL_COLUMN` is the shape that must keep passing — a *column* tested
# for NULL is ordinary SQL and carries no parameter at all.
_NULL_BROKEN = 'q = text("SELECT id FROM c WHERE (:i IS NULL OR issuer = :i)").bindparams(i=issuer)'
_NULL_CLEAN = 'q = text("SELECT id FROM c WHERE (CAST(:i AS TEXT) IS NULL OR issuer = CAST(:i AS TEXT))")'
_NULL_NEGATED = 'q = text("SELECT id FROM c WHERE :since IS NOT NULL")'
_NULL_COLUMN = 'q = text("SELECT id FROM c WHERE deleted_at IS NULL AND issuer = :i")'

# The third source, and the one this gate was blind to. `vuln_promotion_sql.py`
# is a module of SQL constants with no `text(` anywhere in it; the wrapper is
# in `scheduler.py`, which the gate scanned and found nothing in because the
# argument there is a Name.
_CONSTANT_BROKEN = '''
UPSERT_ALERT_SQL = """
    INSERT INTO alerts (tenant_id, affected_hosts)
    VALUES (CAST(:tenant_id AS uuid), :affected_hosts::jsonb)
"""
'''
_CONSTANT_CLEAN = '''
UPSERT_ALERT_SQL = """
    INSERT INTO alerts (tenant_id, affected_hosts)
    VALUES (CAST(:tenant_id AS uuid), CAST(:affected_hosts AS jsonb))
"""
'''
_CONSTANT_VIA_TEXT = '''
from app.sql import UPSERT_ALERT_SQL
UPSERT_ALERT_SQL = """
    INSERT INTO alerts (tenant_id, tags) VALUES (CAST(:tenant_id AS uuid), :tags::jsonb)
"""
await conn.execute(text(UPSERT_ALERT_SQL), params)
'''

# Must keep passing. Security software is full of strings that read a little
# like SQL, and a gate that flags correct content gets switched off within a
# week — so the shape test needs a DML verb at the start of a line AND a
# clause keyword, and these have one or neither.
_CONSTANT_NOT_SQL = 'ARN_PREFIX = "arn:aws:iam::123456789012:role/aisoc"'
_CONSTANT_PROSE = 'HELP = "Set the timeout with --timeout. Format is host:port::scheme, e.g. db:5432::tcp"'
_CONSTANT_SELECT_WORD = 'LABEL = "Select a connector from the list below (filter: name::contains)"'


def _rule_self_test() -> list[tuple[str, bool]]:
    return [
        ("the CAST() spelling is not reported", not violations(_CLEAN, "f.py")),
        ("an injected `:payload::jsonb` is reported", any("payloa" in v for v in violations(_BROKEN, "f.py"))),
        ("an ARN literal outside a text() call is not reported", not violations(_NOT_SQL, "f.py")),
        ("a `::` cast in a concatenated statement is reported", any(":kinds::" in v for v in violations(_CONCAT, "f.py"))),
        ("an untyped `:i IS NULL` is reported", any(":i IS NULL" in v for v in violations(_NULL_BROKEN, "f.py"))),
        ("`CAST(:i AS TEXT) IS NULL` is not reported", not violations(_NULL_CLEAN, "f.py")),
        ("an untyped `:since IS NOT NULL` is reported", any(":since IS NULL" in v for v in violations(_NULL_NEGATED, "f.py"))),
        ("a column tested for NULL is not reported", not violations(_NULL_COLUMN, "f.py")),
        # The blind spot. Each of these would have passed before: the file
        # holds no `text(` at all, and `_static_string` returned None for the
        # Name the wrapper is handed.
        (
            "a `::` cast in a module-level SQL constant with no text() in the file is reported",
            any(":affected_hosts::" in v for v in violations(_CONSTANT_BROKEN, "sql.py")),
        ),
        ("the CAST() spelling in a module constant is not reported", not violations(_CONSTANT_CLEAN, "sql.py")),
        (
            "a constant handed to text() by name is reported",
            any(":tags::" in v for v in violations(_CONSTANT_VIA_TEXT, "s.py")),
        ),
        ("an ARN in a module constant is not reported", not violations(_CONSTANT_NOT_SQL, "c.py")),
        ("help text containing `::` is not reported", not violations(_CONSTANT_PROSE, "c.py")),
        ("a label starting with the word Select is not reported", not violations(_CONSTANT_SELECT_WORD, "c.py")),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_rule_self_test()))
    sys.exit(main())
