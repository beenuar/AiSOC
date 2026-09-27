#!/usr/bin/env python3
"""The replay contract spans three trees that cannot import each other. Pin it.

Gap-closure Phase 1.2 and 1.3.

``services/actions`` reads a customer's closed findings and produces
``ClosedFinding``. ``services/agents`` replays them and consumes
``HistoricalFinding``. ``packages/aisoc-benchmark`` grades the result against
``GRADED_DISPOSITIONS``. All three package their code as top-level ``app`` or
as a standalone distribution, so none of them can import the others, and the
contract between them is three declarations that agree by convention.

Conventions drift. This gate reads all three with ``ast`` and compares them
**in both directions**, because the failure this tree keeps finding is a gate
that checks A against B and prints OK while B grows a field A never hears
about. A field added to the reader and not to the replay type would be dropped
silently at the boundary; a disposition added to the taxonomy and not to the
grader would be scored as an unknown verdict.

Nothing is imported. The gate runs on a bare interpreter, and importing
``services/actions`` would drag in httpx and the whole client stack to compare
a list of attribute names.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

#: (path, class name) for the two dataclasses that must carry the same fields.
_READER = ("services/actions/app/services/alert_history.py", "ClosedFinding")
_REPLAY = ("services/agents/app/replay/findings.py", "HistoricalFinding")

#: The canonical taxonomy, declared once per tree.
_TAXONOMY_SOURCE = ("services/actions/app/services/disposition_writeback.py", "CANONICAL_DISPOSITIONS")
_GRADER_SOURCE = ("packages/aisoc-benchmark/aisoc_benchmark/replay.py", "GRADED_DISPOSITIONS")

#: ``CANONICAL_DISPOSITIONS`` covers everything a verdict may be, including the
#: two that route to a human. The grader's ``GRADED_DISPOSITIONS`` is only the
#: subset an analyst can *close* a finding as, because "needs review" is not an
#: outcome anyone closed anything with. These are the members that may appear
#: in one and not the other, and they are listed rather than inferred so adding
#: a third does not silently widen the exemption.
_NOT_A_CLOSING_LABEL = frozenset({"needs_review", "escalate"})

#: The spelling of "the analyst declined to classify", which both trees hold
#: as a module constant and neither may rename alone.
_UNLABELED = ("unlabeled", [_READER[0], _REPLAY[0]])


def _module(root: Path, relative: str) -> ast.Module:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"FAIL: {relative} is missing; the replay contract cannot be checked")
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dataclass_fields(tree: ast.Module, class_name: str, relative: str) -> set[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            fields = {item.target.id for item in node.body if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)}
            if not fields:
                raise SystemExit(f"FAIL: {class_name} in {relative} declares no annotated fields")
            return fields
    raise SystemExit(f"FAIL: {class_name} was not found in {relative}")


def _string_members(tree: ast.Module, name: str, relative: str) -> set[str]:
    """Read a module-level frozenset/tuple/set of string literals."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        value: ast.expr | None = node.value
        if isinstance(value, ast.Call) and value.args:
            value = value.args[0]
        if isinstance(value, ast.Tuple | ast.List | ast.Set):
            members = {e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            names = {e.id for e in value.elts if isinstance(e, ast.Name)}
            if members or names:
                return members | {_resolve_name(tree, n) for n in names}
    raise SystemExit(f"FAIL: {name} was not found as a literal collection in {relative}")


def _resolve_name(tree: ast.Module, name: str) -> str:
    """Resolve a module-level ``NAME = "literal"`` binding."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return str(node.value.value)
    raise SystemExit(f"FAIL: {name} is referenced in a taxonomy collection but is not a module-level string")


def _constant(tree: ast.Module, name: str, relative: str) -> str:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return str(node.value.value)
    raise SystemExit(f"FAIL: {name} was not found as a string constant in {relative}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate refuses an empty tree")
    parser.parse_args(argv)

    root = repo_root()
    failures: list[str] = []
    checked = 0

    reader_fields = _dataclass_fields(_module(root, _READER[0]), _READER[1], _READER[0])
    replay_fields = _dataclass_fields(_module(root, _REPLAY[0]), _REPLAY[1], _REPLAY[0])
    checked += len(reader_fields) + len(replay_fields)

    missing_here = sorted(reader_fields - replay_fields)
    missing_there = sorted(replay_fields - reader_fields)
    if missing_here:
        failures.append(
            f"{_READER[1]} carries {missing_here} and {_REPLAY[1]} does not: the reader sends fields replay would drop at the boundary"
        )
    if missing_there:
        failures.append(f"{_REPLAY[1]} carries {missing_there} and {_READER[1]} does not: replay expects fields no reader produces")

    canonical = _string_members(_module(root, _TAXONOMY_SOURCE[0]), _TAXONOMY_SOURCE[1], _TAXONOMY_SOURCE[0])
    graded = _string_members(_module(root, _GRADER_SOURCE[0]), _GRADER_SOURCE[1], _GRADER_SOURCE[0])
    checked += len(canonical) + len(graded)

    ungraded = sorted((canonical - graded) - _NOT_A_CLOSING_LABEL)
    invented = sorted(graded - canonical)
    if ungraded:
        failures.append(f"{_TAXONOMY_SOURCE[1]} holds {ungraded}, which an analyst can close a finding as and the grader does not score")
    if invented:
        failures.append(f"{_GRADER_SOURCE[1]} holds {invented}, which the canonical taxonomy does not define")

    name, files = _UNLABELED
    spellings = {relative: _constant(_module(root, relative), "UNLABELED", relative) for relative in files}
    checked += len(spellings)
    if len(set(spellings.values())) != 1 or next(iter(spellings.values())) != name:
        failures.append(f"UNLABELED is spelled inconsistently across the replay contract: {spellings}")

    if not checked:
        print("FAIL: the gate compared nothing, which is indistinguishable from a clean result")
        return 1

    if failures:
        print(f"FAIL: the replay contract disagrees across trees ({len(failures)} finding(s))")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"OK: replay contract agrees across three trees "
        f"({len(reader_fields)} finding fields, {len(graded)} graded dispositions, {len(spellings)} UNLABELED spellings)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
