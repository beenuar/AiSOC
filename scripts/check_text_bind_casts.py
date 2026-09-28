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


def _static_string(node: ast.AST) -> str | None:
    """Return the statement text when it can be read without executing anything.

    Handles the three spellings that appear in this tree: a plain literal, an
    implicit or explicit concatenation of literals, and an f-string whose
    interpolations are irrelevant to where the colons fall. A `text()` built
    from a variable is skipped — reporting on it would need dataflow, and the
    statements this defect lives in are all inline literals.
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


def violations(source: str, rel: str) -> list[str]:
    """Report every `:name::type` inside a `text()` statement in ``source``."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{rel}: could not parse ({exc})"]

    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_text_call(node) or not node.args:
            continue
        statement = _static_string(node.args[0])
        if statement is None:
            continue
        declared = set(SQLA_BIND_RE.findall(statement))
        for match in CAST_ADJACENT_RE.finditer(statement):
            intended = match.group(1)
            if intended in declared:
                # SQLAlchemy resolved this name anyway (it also appears in the
                # statement somewhere a cast does not follow it), so the
                # bindparams call will not raise. Still worth nothing here.
                continue
            truncated = next((d for d in declared if intended.startswith(d) and d != intended), "no parameter")
            found.append(
                f"{rel}:{node.lineno}: `:{intended}::` declares `{truncated}`, so `.bindparams({intended}=...)` raises. "
                f"Write `CAST(:{intended} AS <type>)`."
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
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "text(" not in source:
            continue
        problems.extend(violations(source, str(path.relative_to(root))))

    if problems:
        print("A bind parameter is followed by a `::` cast, so SQLAlchemy declares a different name:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"\n{len(problems)} statement(s) would raise before reaching a connection.", file=sys.stderr)
        return 1

    print(f"OK: {len(files)} tracked Python file(s) scanned ({len(services)} under services/), no `:name::type` inside a text() statement")
    return 0


_CLEAN = 'q = text("INSERT INTO t (a, b) VALUES (CAST(:payload AS jsonb), :other)").bindparams(payload=x, other=y)'
_BROKEN = 'q = text("INSERT INTO t (a, b) VALUES (:payload::jsonb, :other)").bindparams(payload=x, other=y)'
_NOT_SQL = 'if ":iam::" in resource_id and ":policy/" in resource_id:\n    kind = "policy"'
_CONCAT = 'q = text("SELECT * FROM t" " WHERE k = ANY(:kinds::text[])")'


def _rule_self_test() -> list[tuple[str, bool]]:
    return [
        ("the CAST() spelling is not reported", not violations(_CLEAN, "f.py")),
        ("an injected `:payload::jsonb` is reported", any("payloa" in v for v in violations(_BROKEN, "f.py"))),
        ("an ARN literal outside a text() call is not reported", not violations(_NOT_SQL, "f.py")),
        ("a `::` cast in a concatenated statement is reported", any(":kinds::" in v for v in violations(_CONCAT, "f.py"))),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_rule_self_test()))
    sys.exit(main())
