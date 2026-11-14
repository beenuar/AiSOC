#!/usr/bin/env python3
"""Every automatic closure of an alert passes the closure authorization chokepoint.

Phase 1 of the closure remediation. See
`docs/remediation/phase-1-closure-authorization.md`.

What this gate is for
---------------------
`alerts.status` becomes `'resolved'` in exactly one statement in
`services/agents`: the `UPDATE alerts` at the end of
`app.investigator.ledger.persist_auto_triage`. That is what makes a chokepoint
possible at all — and it is also a property that nothing was holding.

**Scope, stated because the obvious reading is wider than the truth.** This
gate walks `services/agents/app` and nothing else, so what it proves is that
*the agent* has one governed closure path. It is not a claim about the
product: `services/connectors`'s vulnerability sweep carries its own
`RESOLVE_REMEDIATED_SQL`, which closes a CVE-promotion alert of its own making
once every affected asset is patched. That is a deterministic lifecycle rule
rather than an autonomous verdict, it is tenant-scoped, and it is outside this
phase — but a verdict string here saying "the only path to 'resolved'" would
be false, so neither this gate nor its claim row says it. A second
path to that statement had already appeared once: the outcome-memory
suppression branch reached it with `auto_closed=True` having consulted no
policy, no grant and no kill switch, and the test covering closure wiring
asserted one substring against one function, so it could not see it.

So this gate asserts two things:

1. only the ledger module contains SQL that can set an alert to `'resolved'`;
2. the function containing that SQL calls `authorize_auto_closure`.

Why it reads the AST and not the text
-------------------------------------
Grepping for `'resolved'` matches prose. This module's own docstring quotes
the SQL two paragraphs above, `authorization.py` quotes it as well, and a
line-based scanner flags both — a gate that fires on documentation gets
switched off within a week. Only string constants that are *not* docstrings
are considered, which is the difference between SQL the process executes and
English a reader reads.

Run it:

    python3 scripts/check_closure_authorization.py
    python3 scripts/check_closure_authorization.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

#: The module permitted to carry closure SQL, relative to the agents app.
LEDGER = "investigator/ledger.py"

#: The function inside it that must consult the chokepoint.
GATED_FUNCTION = "persist_auto_triage"

#: The chokepoint's name, as it is called.
CHOKEPOINT = "authorize_auto_closure"

#: A SQL fragment that can move a row's status to resolved. Matches both the
#: literal assignment and the `CASE ... THEN 'resolved'` form the ledger uses.
_CLOSURE_SQL = re.compile(
    r"""(?isx)
    (
        status \s* = \s* ['"]resolved['"]      # status = 'resolved'
      | THEN \s+ ['"]resolved['"]              # CASE ... THEN 'resolved'
    )
    """
)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Identity of every string constant that is a docstring.

    A docstring is the first statement of a module, class or function and is
    a bare string expression. Everything else that is a string constant is
    data the program uses.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", None) or []
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            found.add(id(first.value))
    return found


def executable_strings(source: str) -> list[str]:
    """Every string constant in `source` that is not a docstring."""
    tree = ast.parse(source)
    docstrings = _docstring_nodes(tree)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
    ]


def modules_with_closure_sql(app_root: Path) -> set[str]:
    """Modules under `app_root` carrying SQL that can resolve an alert."""
    found: set[str] = set()
    for path in sorted(app_root.rglob("*.py")):
        try:
            strings = executable_strings(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover - a broken tree fails elsewhere
            print(f"check_closure_authorization: cannot parse {path}: {exc}", file=sys.stderr)
            return {"<unparseable>"}
        if any(_CLOSURE_SQL.search(text) for text in strings):
            found.add(path.relative_to(app_root).as_posix())
    return found


def function_calls(source: str, function: str) -> set[str]:
    """The names called inside `function`, however it is spelled."""
    tree = ast.parse(source)
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name != function:
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            target = inner.func
            if isinstance(target, ast.Name):
                calls.add(target.id)
            elif isinstance(target, ast.Attribute):
                calls.add(target.attr)
    return calls


def check(repo_root: Path) -> list[str]:
    """Returns a list of failures. Empty means the chokepoint holds."""
    app_root = repo_root / "services" / "agents" / "app"
    if not app_root.is_dir():
        return [f"no agents app at {app_root}"]

    failures: list[str] = []

    writers = modules_with_closure_sql(app_root)
    if writers != {LEDGER}:
        extra = sorted(writers - {LEDGER})
        if extra:
            failures.append(
                "SQL that can set an alert to 'resolved' appears outside the ledger, inside services/agents: "
                + ", ".join(extra)
                + f". Every automatic closure must go through {CHOKEPOINT}; "
                "a second statement is a second path nothing governs."
            )
        if LEDGER not in writers:
            failures.append(
                f"{LEDGER} no longer contains the closure SQL this gate exists to guard. "
                "If it moved, move the chokepoint with it and update this gate."
            )

    ledger_path = app_root / LEDGER
    if ledger_path.is_file():
        calls = function_calls(ledger_path.read_text(encoding="utf-8"), GATED_FUNCTION)
        if CHOKEPOINT not in calls:
            failures.append(
                f"{LEDGER}:{GATED_FUNCTION} can set an alert to 'resolved' without calling {CHOKEPOINT}. "
                "An automatic closure would bypass the tenant's policy, the earned grant and the kill switch."
            )
    else:
        failures.append(f"{LEDGER} is missing")

    return failures


_SELF_TEST_GOOD = '''
"""A module whose docstring quotes the SQL: status = 'resolved'."""
# A comment mentioning THEN 'resolved' as well.
async def unrelated(conn):
    await conn.execute("UPDATE alerts SET status = 'triaged' WHERE id = $1")
'''

_SELF_TEST_BAD = """
async def sneaky(conn):
    await conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = $1")
"""

_SELF_TEST_CASE_FORM = """
async def sneaky(conn):
    await conn.execute("UPDATE alerts SET status = CASE WHEN $1 THEN 'resolved' ELSE status END")
"""


def self_test() -> int:
    """Prove the detector fires on SQL and stays silent on prose.

    Both directions, because a gate that cannot fire and a gate that fires on
    everything fail the same way in practice: somebody stops believing it.
    """
    failures = []

    if any(_CLOSURE_SQL.search(text) for text in executable_strings(_SELF_TEST_GOOD)):
        failures.append("the detector flagged a module that only mentions the SQL in a docstring or a comment")

    if not any(_CLOSURE_SQL.search(text) for text in executable_strings(_SELF_TEST_BAD)):
        failures.append("the detector missed a literal `status = 'resolved'` UPDATE")

    if not any(_CLOSURE_SQL.search(text) for text in executable_strings(_SELF_TEST_CASE_FORM)):
        failures.append("the detector missed the `CASE ... THEN 'resolved'` form the ledger actually uses")

    ungated = """
async def persist_auto_triage(conn):
    await conn.execute("UPDATE alerts SET status = 'resolved'")
"""
    if CHOKEPOINT in function_calls(ungated, GATED_FUNCTION):
        failures.append("the call detector reported a chokepoint call in a function that makes none")

    gated = f"""
async def {GATED_FUNCTION}(conn):
    decision = await {CHOKEPOINT}(tenant_ref="t")
    await conn.execute("UPDATE alerts SET status = 'resolved'")
"""
    if CHOKEPOINT not in function_calls(gated, GATED_FUNCTION):
        failures.append("the call detector missed a direct chokepoint call")

    for failure in failures:
        print(f"check_closure_authorization: SELF-TEST FAILED — {failure}", file=sys.stderr)
    if failures:
        return 1
    print("check_closure_authorization: self-test OK (5 cases, both directions)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the detector works in both directions")
    # `repo_root()` asks git rather than counting directories above this file.
    # Two levels up is whatever happens to be there, which is the wrong answer
    # the moment the script is copied, vendored or run from a build context.
    parser.add_argument("--root", type=Path, default=None)
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    failures = check(args.root or repo_root())
    for failure in failures:
        print(f"check_closure_authorization: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"check_closure_authorization: OK — within services/agents, {LEDGER}:{GATED_FUNCTION} "
        "is the only path to 'resolved' and it is gated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
