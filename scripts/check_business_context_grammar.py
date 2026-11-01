#!/usr/bin/env python3
"""The two business-context engines must agree on the operator grammar — depth2 4.3.

Why this exists
---------------
A business-context rule is authored and validated in ``services/api``
(``app/services/business_context/models.py``) and evaluated on the triage hot
path in ``services/agents`` (``app/workers/business_context.py``). The two ship
as separate images and cannot import each other, so the grammar is declared
twice. Nothing held the declarations equal.

Drift is silent in the direction that matters. The console validates against
its set and accepts the rule; the worker evaluates against its own and, for a
comparator it does not implement, falls through to ``False``. The tenant sees
a saved rule in the list that never fires, with no diagnostic. ``neq`` is the
case that makes it concrete — the spelling in both engines is ``ne``, so it is
the most plausible typo in the grammar, and the rule it silently disables is
usually an escalation.

Three arms, because a one-directional check is how this class of gate reports
OK while the drift that matters walks past it:

1. **Declared sets are equal.** Both directions: an operator the console
   accepts and the worker cannot evaluate is a rule that never fires; an
   operator the worker evaluates and the console rejects is a rule nobody can
   author, which is dead code rather than a defect but still drift.
2. **Every declared operator is implemented**, in each engine's own
   evaluator. A name in the set with no branch behind it is the same silent
   no-op, reached from the other side.
3. **Every implemented operator is declared.** A branch with no name in the
   set is unreachable through either parser.

Arm 1 compares the two *published* constants. Arms 2 and 3 are the only place
this script reads an evaluator's source, and they read it to check the
declaration against it — never to derive the declaration from it, which is how
a drift check ends up asserting against its own copy of the answer.

The files are parsed with ``ast`` rather than imported: both services name
their top-level package ``app``, so importing one shadows the other in the
same process.

Usage
-----
    python3 scripts/check_business_context_grammar.py
    python3 scripts/check_business_context_grammar.py --check      # same, explicit
    python3 scripts/check_business_context_grammar.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: ``(label, declaration file, constant, evaluator file, evaluator functions)``.
#:
#: The console splits the two across modules — ``models.py`` is the parser and
#: owns the declaration, ``engine.py`` is the evaluator — so the declaration
#: and evaluator paths are separate fields rather than one. Both engines need
#: two function names because the unary operators (``exists`` /
#: ``not_exists``) are handled in ``evaluate_condition`` against ``cond.op``
#: rather than in the comparator against a local ``op``.
ENGINES: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    (
        "console",
        "services/api/app/services/business_context/models.py",
        "ALLOWED_OPS",
        "services/api/app/services/business_context/engine.py",
        ("_eval_op", "evaluate_condition"),
    ),
    (
        "worker",
        "services/agents/app/workers/business_context.py",
        "COMPARATOR_OPS",
        "services/agents/app/workers/business_context.py",
        ("_cmp", "evaluate_condition"),
    ),
)


@dataclass(frozen=True)
class Engine:
    label: str
    declares_in: Path
    evaluates_in: Path
    declared: frozenset[str]
    implemented: frozenset[str]


class GrammarError(RuntimeError):
    """The two engines disagree, or one contradicts itself."""


def _literal_str_set(node: ast.AST) -> frozenset[str] | None:
    """Return the set of string literals in a ``frozenset({...})`` / ``{...}``."""
    if isinstance(node, ast.Call):
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        if name not in {"frozenset", "set"} or not node.args:
            return None
        node = node.args[0]
    if isinstance(node, ast.Set):
        elts = node.elts
    elif isinstance(node, ast.List | ast.Tuple):
        elts = list(node.elts)
    else:
        return None
    out: set[str] = set()
    for elt in elts:
        if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
            return None
        out.add(elt.value)
    return frozenset(out)


def _declared_ops(tree: ast.AST, const_name: str, *, label: str, rel: str) -> frozenset[str]:
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == const_name:
                ops = _literal_str_set(value)
                if ops is None:
                    raise GrammarError(
                        f"{rel}: {const_name} is not a literal set of strings, so the "
                        f"{label} grammar cannot be compared without executing the module"
                    )
                return ops
    raise GrammarError(f"{rel}: no {const_name} declaration found for the {label} engine")


def _implemented_ops(tree: ast.AST, fn_names: tuple[str, ...], *, label: str, rel: str) -> frozenset[str]:
    """Operators the evaluator actually branches on.

    Collects the right-hand side of every ``<something>.op == "x"`` and
    ``op == "x"`` comparison inside the named functions. Deliberately narrow:
    a looser match would pick up unrelated string comparisons and turn this
    arm into noise.
    """
    found: set[str] = set()
    seen_fn: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name not in fn_names:
            continue
        seen_fn.add(node.name)
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Compare) or len(inner.ops) != 1:
                continue
            if not isinstance(inner.ops[0], ast.Eq):
                continue
            left = inner.left
            is_op_operand = (isinstance(left, ast.Name) and left.id == "op") or (isinstance(left, ast.Attribute) and left.attr == "op")
            if not is_op_operand:
                continue
            rhs = inner.comparators[0]
            if isinstance(rhs, ast.Constant) and isinstance(rhs.value, str):
                found.add(rhs.value)
    missing_fn = sorted(set(fn_names) - seen_fn)
    if missing_fn:
        raise GrammarError(
            f"{rel}: the {label} evaluator function(s) {missing_fn} were not found. "
            "A renamed evaluator would make this arm pass over an empty set."
        )
    if not found:
        raise GrammarError(
            f"{rel}: no operator comparisons found in the {label} evaluator. Refusing to report agreement derived from nothing."
        )
    return frozenset(found)


def load_engines(root: Path = REPO_ROOT) -> list[Engine]:
    engines: list[Engine] = []
    for label, decl_rel, const_name, eval_rel, fn_names in ENGINES:
        decl_path = root / decl_rel
        eval_path = root / eval_rel
        for rel, path in ((decl_rel, decl_path), (eval_rel, eval_path)):
            if not path.is_file():
                raise GrammarError(f"{rel}: missing — the {label} engine moved without updating this gate")
        decl_tree = ast.parse(decl_path.read_text(encoding="utf-8"), filename=str(decl_path))
        eval_tree = decl_tree if eval_path == decl_path else ast.parse(eval_path.read_text(encoding="utf-8"), filename=str(eval_path))
        engines.append(
            Engine(
                label=label,
                declares_in=decl_path,
                evaluates_in=eval_path,
                declared=_declared_ops(decl_tree, const_name, label=label, rel=decl_rel),
                implemented=_implemented_ops(eval_tree, fn_names, label=label, rel=eval_rel),
            )
        )
    return engines


def check(root: Path = REPO_ROOT) -> list[str]:
    """Return a list of problems; empty means the grammars agree."""
    engines = load_engines(root)
    problems: list[str] = []

    # Arm 1 — the two declarations, both directions.
    console, worker = engines[0], engines[1]
    only_console = sorted(console.declared - worker.declared)
    only_worker = sorted(worker.declared - console.declared)
    if only_console:
        problems.append(
            f"operators the console accepts and the worker cannot evaluate: {only_console} — "
            "a rule using one of these saves successfully and never fires"
        )
    if only_worker:
        problems.append(
            f"operators the worker evaluates and the console rejects: {only_worker} — unreachable through the authoring grammar"
        )

    # Arms 2 and 3 — each engine against its own evaluator.
    for engine in engines:
        rel = engine.evaluates_in.relative_to(root)
        declared_not_implemented = sorted(engine.declared - engine.implemented)
        implemented_not_declared = sorted(engine.implemented - engine.declared)
        if declared_not_implemented:
            problems.append(
                f"{rel}: {engine.label} declares {declared_not_implemented} with no branch in its "
                "evaluator — the comparison falls through and the rule silently never matches"
            )
        if implemented_not_declared:
            problems.append(
                f"{rel}: {engine.label} implements {implemented_not_declared} but does not declare "
                "it — unreachable, because the parser rejects the operator first"
            )
    return problems


# ---------------------------------------------------------------------------
# Self-test — the gate must be shown to fail, not merely to pass.
# ---------------------------------------------------------------------------

_CONSOLE_STUB = """
ALLOWED_OPS = frozenset({"eq", "ne"})

def _eval_op(op, a, b):
    if op == "eq":
        return a == b
    if op == "ne":
        return a != b
    return False

def evaluate_condition(cond, alert):
    return _eval_op(cond.op, None, None)
"""

_WORKER_STUB = """
COMPARATOR_OPS = frozenset({"eq", "ne"})

def _cmp(op, a, b):
    if op == "eq":
        return a == b
    if op == "ne":
        return a != b
    return False

def evaluate_condition(cond, alert):
    return _cmp(cond.op, None, None)
"""


def _write_pair(root: Path, console_src: str, worker_src: str) -> None:
    """Lay the stubs out at every path the gate reads.

    The console stub carries both halves, so it is written to its declaration
    path and its evaluator path; in the live tree those are two files.
    """
    targets = (
        (ENGINES[0][1], console_src),
        (ENGINES[0][3], console_src),
        (ENGINES[1][1], worker_src),
        (ENGINES[1][3], worker_src),
    )
    for rel, src in targets:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")


def _self_test() -> int:
    import tempfile  # noqa: PLC0415 — self-test only; not imported on the gate path

    failures: list[str] = []

    def case(name: str, console_src: str, worker_src: str, *, expect_problem: bool) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pair(root, console_src, worker_src)
            try:
                problems = check(root)
            except GrammarError as exc:
                problems = [str(exc)]
            if expect_problem and not problems:
                failures.append(f"{name}: expected a problem, got none")
            if not expect_problem and problems:
                failures.append(f"{name}: expected agreement, got {problems}")

    case("in agreement", _CONSOLE_STUB, _WORKER_STUB, expect_problem=False)

    # The live defect: the console gains an operator the worker cannot run.
    case(
        "console ahead of worker",
        _CONSOLE_STUB.replace('{"eq", "ne"}', '{"eq", "ne", "matches"}').replace(
            'if op == "ne":', 'if op == "matches":\n        return True\n    if op == "ne":'
        ),
        _WORKER_STUB,
        expect_problem=True,
    )
    # The mirror: the worker runs something nobody can author.
    case(
        "worker ahead of console",
        _CONSOLE_STUB,
        _WORKER_STUB.replace('{"eq", "ne"}', '{"eq", "ne", "matches"}').replace(
            'if op == "ne":', 'if op == "matches":\n        return True\n    if op == "ne":'
        ),
        expect_problem=True,
    )
    # Declared on both sides, implemented on neither: the silent no-op that
    # equality between the two declarations alone would not catch.
    case(
        "declared by both, implemented by neither",
        _CONSOLE_STUB.replace('{"eq", "ne"}', '{"eq", "ne", "neq"}'),
        _WORKER_STUB.replace('{"eq", "ne"}', '{"eq", "ne", "neq"}'),
        expect_problem=True,
    )
    # Implemented but undeclared: unreachable branch.
    case(
        "implemented but undeclared",
        _CONSOLE_STUB.replace('if op == "ne":', 'if op == "regex":\n        return True\n    if op == "ne":'),
        _WORKER_STUB,
        expect_problem=True,
    )
    # A renamed evaluator must not read as an empty, agreeing set.
    case(
        "evaluator renamed away",
        _CONSOLE_STUB.replace("def _eval_op(", "def _eval_op_values("),
        _WORKER_STUB,
        expect_problem=True,
    )
    # A computed set cannot be compared without executing the module.
    case(
        "declaration is not a literal",
        _CONSOLE_STUB.replace('frozenset({"eq", "ne"})', "frozenset(_BASE_OPS | _EXTRA)"),
        _WORKER_STUB,
        expect_problem=True,
    )

    for line in failures:
        print(f"FAIL  {line}")
    if failures:
        print(f"\n{len(failures)} self-test case(s) failed")
        return 1
    print("OK — 7 self-test cases pass (1 agreeing, 6 detected)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify the grammars agree (default)")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects drift")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    try:
        problems = check()
    except GrammarError as exc:
        print(f"FAIL  {exc}")
        return 1

    if problems:
        print("Business-context grammar drift:\n")
        for problem in problems:
            print(f"  FAIL  {problem}")
        print(
            "\nBoth engines must declare the same operators, and each must implement "
            "every operator it declares. An operator that parses but has no branch "
            "behind it makes the rule a silent no-op."
        )
        return 1

    engines = load_engines()
    ops = sorted(engines[0].declared)
    print(f"OK — console and worker agree on {len(ops)} operators, each implemented in both: {', '.join(ops)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
