#!/usr/bin/env python3
"""Every test file in a tree must be reached by that tree's own CI invocation.

Why this exists
---------------
``services/agents`` ships 82 test files. Until this gate landed, the workflow
step that runs them named 26 of those files one per line, and the other 56
were executed by nothing at all. Not skipped, not quarantined, not xfailed —
uncollected, which prints nothing and looks exactly like a suite that passed.

``test_playbook_engine_correctness.py`` was one of the 56. It carried a test
that spent fourteen seconds doing the precise thing its own name said must not
happen, and it did so for as long as it existed, because nothing ever ran it
to notice.

A hand-maintained list of files is the same mechanism as the hand-written
``ConnectorType`` union whose ten members named nothing the platform ingests,
and the hand-kept alias vocabulary that let an authenticated route read as
wide open. In each case the list was correct when written and the tree moved.
The fix is the same in all three: stop maintaining the list, derive it.

The question this asks
----------------------
Not "do the tests pass" — that is the suite's job. This asks **which test
files the tree's own invocation can even reach**, and it asks it in both
directions:

``unreached``
    A test file exists in a tree and no invocation for that tree collects it.
    Adding a file to a directory CI already runs is free; adding one beside a
    hand-maintained list is silently free of signal.

``names-nothing``
    An invocation names a path that is not there. A step that lists a deleted
    file either fails loudly on every run or, more often, the list was updated
    and the file was not — either way the step no longer does what it reads
    as doing.

What counts as reached
----------------------
pytest's own collection rules, applied to the arguments CI actually passes:
a directory argument reaches every ``test_*.py`` / ``*_test.py`` beneath it
(minus ``--ignore``), a file argument reaches that file, and
``--ignore``/``--deselect`` subtract. Anything a ``conftest.py`` adds to
``collect_ignore`` is subtracted too, because a file pytest is told to skip
collecting is not reached however it is named.

Quarantine is the one honest way to not run a file, and it has to be visible:
a file listed in ``QUARANTINE`` below is excused from ``unreached`` and must
carry a stated reason. The list is checked in both directions, so an entry
naming a file that no longer exists — or one that has since become reachable
— fails the build rather than sitting there looking like coverage.

Usage
-----
    python3 scripts/check_test_discovery.py              # gate
    python3 scripts/check_test_discovery.py --list       # per-tree detail
    python3 scripts/check_test_discovery.py --json
    python3 scripts/check_test_discovery.py --self-test  # prove it detects drift

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. Its siblings sit beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_gate_coverage as coverage  # noqa: E402
from gate_toolkit import repo_root, self_test_main  # noqa: E402

# --------------------------------------------------------------------------
# Recorded quarantine. Shrink-only, checked in both directions.
# --------------------------------------------------------------------------
#: Test files deliberately not run by any workflow, each with the reason. A
#: quarantined file is still *collected* by nothing, which is the state this
#: gate exists to remove — so the entry is what makes it visible rather than
#: silent. An entry naming a file that is not there, or one that has since
#: become reachable, is a finding.
#:
#: Keys are repository-relative POSIX paths.
QUARANTINE: dict[str, str] = {}

#: The corpus is ``git ls-files``, so there is no exclusion list here and
#: nothing to keep in sync. ``node_modules``, ``.venv`` and ``site-packages``
#: are not tracked, so they are out by construction rather than by a name
#: somebody remembered to write down — and a list of ephemeral directory names
#: cannot be checked in both directions anyway, because on a clean checkout
#: none of them exist. The first version of this gate carried that list and
#: failed on its own repository for exactly that reason.


class DiscoveryError(RuntimeError):
    """The scan could not be set up. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# What pytest would collect
# --------------------------------------------------------------------------
#: pytest's default ``python_files``. Read from each tree's own config when it
#: declares one, because a tree that renames the pattern renames what "a test
#: file" means for that tree and a gate using the default would scan for files
#: that cannot exist.
DEFAULT_PYTHON_FILES = ("test_*.py", "*_test.py")

#: `pytest` in command position. Matching the bare word pulls in every
#: `pip install ... pytest` line, and an install line has no path argument, so
#: it reads as a bare collection of the entire tree — an over-broad resolver
#: manufactures the coverage this gate exists to disprove.
_PYTEST_COMMAND = re.compile(
    r"(?:^|[\n;&|]|\bpython3?(?:\.\d+)?\s+-m\s+|\buv\s+run\s+|\bpoetry\s+run\s+)\s*pytest\b",
    re.MULTILINE,
)
_PIP_INSTALL = re.compile(r"\b(?:pip3?|python3?(?:\.\d+)?\s+-m\s+pip)\s+install\b")

#: Options that consume the following token, so a resolver does not mistake
#: that token for a test path. ``-k`` selects within what was collected by
#: test *name*, which this gate does not model — it is a filter a developer
#: types, not a standing property of a workflow, and no workflow here uses it.
#: ``-m`` is different and is captured below.
_OPTS_WITH_VALUE = frozenset({"-k", "-p", "-n", "--rootdir", "--cov", "--cov-config", "--cov-report", "--junitxml", "--tb", "-W"})


def _segments(text: str) -> list[str]:
    """Individual commands inside a workflow `run:` block."""
    joined = text.replace("\\\n", " ")
    out: list[str] = []
    for line in joined.splitlines():
        for piece in re.split(r"&&|\|\||[;|]", line):
            stripped = piece.strip()
            if stripped:
                out.append(stripped)
    return out


@dataclass
class Invocation:
    """One pytest command a workflow runs, with its arguments resolved."""

    workflow: str
    working_dir: str
    command: str
    paths: list[str] = field(default_factory=list)
    ignores: list[str] = field(default_factory=list)
    markers: str = ""
    bare: bool = False


def parse_invocations(surface: coverage.Surface) -> list[Invocation]:
    """Every pytest invocation the workflow surface runs, with its paths.

    Working directories and matrix expansion come from ``Surface`` rather than
    from a second parser here: two readers of the same workflows drift the
    first time either one learns something the other has not.

    A step's ``working-directory`` is only half the answer. The largest
    invocation in this repository — the agents one — is a multi-line ``run:``
    block that ``cd``s into the service and then runs pytest with
    ``tests/``-relative paths, and the first version of this parser resolved
    those against the repository root instead. It therefore reported the whole
    agents suite unreached *and* credited the root ``tests/`` tree with an
    invocation belonging to a package, which is the same defect in both
    directions at once. So ``cd`` is followed, in order, within each block.
    """
    found: list[Invocation] = []
    for workflow, working_dir, text in surface.texts():
        cwd = working_dir
        for segment in _segments(text):
            moved = _cd_target(segment, cwd)
            if moved is not None:
                cwd = moved
                continue
            if _PIP_INSTALL.search(segment):
                continue
            if not _PYTEST_COMMAND.search(segment):
                continue
            try:
                tokens = shlex.split(segment, comments=True)
            except ValueError:
                continue
            args = _args_after_pytest(tokens)
            if args is None:
                continue
            paths, ignores, markers = _split_args(args)
            found.append(
                Invocation(
                    workflow=workflow,
                    working_dir=cwd,
                    command=segment.strip(),
                    paths=paths,
                    ignores=ignores,
                    markers=markers,
                    bare=not paths,
                )
            )
    return found


def _cd_target(segment: str, cwd: str) -> str | None:
    """The directory this segment changes to, or None if it is not a ``cd``.

    Relative to the block's current directory, so ``cd services/agents``
    followed by ``cd ..`` lands back where it started. A ``cd`` whose argument
    is an unexpanded variable returns the current directory unchanged rather
    than a path that cannot exist — guessing would move the resolver
    somewhere arbitrary and every path after it would read as missing.
    """
    try:
        tokens = shlex.split(segment, comments=True)
    except ValueError:
        return None
    if len(tokens) != 2 or tokens[0] != "cd":
        return None
    target = tokens[1]
    if target.startswith("$") or target.startswith("/"):
        return cwd
    joined = Path(cwd or ".") / target
    normalised = Path(*[])
    parts: list[str] = []
    for part in joined.parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part not in {".", ""}:
            parts.append(part)
    normalised = Path(*parts) if parts else Path()
    return normalised.as_posix().strip("./") if parts else ""


def _args_after_pytest(tokens: list[str]) -> list[str] | None:
    """The arguments handed to pytest, or None if this is not a pytest run."""
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index < len(tokens) and tokens[index] == "env":
        index += 1
        while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
            index += 1
    if index < len(tokens) and tokens[index] in {"uv", "poetry"}:
        if index + 1 >= len(tokens) or tokens[index + 1] != "run":
            return None
        index += 2
    if index < len(tokens) and re.fullmatch(r"python3?(?:\.\d+)?", tokens[index]):
        index += 1
        if index < len(tokens) and tokens[index] == "-m":
            index += 1
    if index >= len(tokens) or tokens[index] != "pytest":
        return None
    return tokens[index + 1 :]


def _split_args(args: list[str]) -> tuple[list[str], list[str], str]:
    """(positional test paths, --ignore paths, the -m marker expression)."""
    paths: list[str] = []
    ignores: list[str] = []
    markers = ""
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("--ignore=") or token.startswith("--ignore-glob="):
            ignores.append(token.split("=", 1)[1])
        elif token in {"--ignore", "--ignore-glob"} and index + 1 < len(args):
            ignores.append(args[index + 1])
            index += 1
        elif token == "-m" and index + 1 < len(args):
            markers = args[index + 1]
            index += 1
        elif token.startswith("-m") and len(token) > 2 and not token.startswith("--"):
            markers = token[2:]
        elif token in _OPTS_WITH_VALUE and index + 1 < len(args):
            index += 1
        elif token.startswith("-"):
            pass
        else:
            paths.append(token)
        index += 1
    return paths, ignores, markers


# --------------------------------------------------------------------------
# Marker deselection
# --------------------------------------------------------------------------
# A file every one of whose tests is deselected by `-m` runs nothing, however
# plainly the invocation names it. The first version of this gate skipped `-m`
# as "a filter, not a collection rule" and would therefore have credited
# `test_graph_freshness.py` in full under `-m "not integration"` — a gate
# crediting a file nothing runs, which is the defect it exists to remove, one
# level up. No workflow here passes `-m` today; the point is that adding one
# cannot quietly empty a tree.


def module_markers(path: Path) -> frozenset[str]:
    """Markers a module applies to every test in it, via ``pytestmark``.

    Module level only. A marker on a single test deselects that test and not
    the file, and this gate is about files.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return frozenset()
    found: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
            continue
        for element in ast.walk(node.value):
            if isinstance(element, ast.Attribute) and isinstance(element.value, ast.Attribute) and element.value.attr == "mark":
                found.add(element.attr)
    return frozenset(found)


def deselects_module(expression: str, markers: frozenset[str]) -> bool:
    """Whether ``-m expression`` deselects every test in a module carrying ``markers``.

    Evaluated from the expression's syntax tree, not by matching text: `not
    integration` and `integration` differ by three characters and invert the
    answer. An expression shaped in a way this cannot evaluate returns False —
    the gate then reports the file as reached, which is the reading that can
    only ever produce a *missed* finding rather than a false one, and the
    unparsed expression is surfaced so it does not stay unnoticed.
    """
    if not expression.strip():
        return False
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError:
        return False

    def value(sub: ast.AST) -> bool | None:
        if isinstance(sub, ast.Name):
            return sub.id in markers
        if isinstance(sub, ast.UnaryOp) and isinstance(sub.op, ast.Not):
            inner = value(sub.operand)
            return None if inner is None else not inner
        if isinstance(sub, ast.BoolOp):
            parts = [value(v) for v in sub.values]
            if any(p is None for p in parts):
                return None
            return all(parts) if isinstance(sub.op, ast.And) else any(parts)
        return None

    selected = value(node)
    return selected is False


def _resolve(token: str, base: Path, root: Path) -> Path | None:
    """A path argument resolved against the step's working directory."""
    token = token.split("::")[0].strip("'\"")
    if not token or token.startswith("$"):
        return None
    target = (base / token).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


# --------------------------------------------------------------------------
# Test trees
# --------------------------------------------------------------------------
@dataclass
class Tree:
    """A directory of test files owned by one part of the repository."""

    name: str
    tests_dir: str
    files: list[str] = field(default_factory=list)
    reached: set[str] = field(default_factory=set)
    invocations: list[str] = field(default_factory=list)

    @property
    def unreached(self) -> list[str]:
        return sorted(set(self.files) - self.reached)


def python_files_patterns(tree_root: Path) -> tuple[str, ...]:
    """``python_files`` for this tree, from its own config if it sets one."""
    for name, key in (("pyproject.toml", "[tool.pytest.ini_options]"), ("pytest.ini", "[pytest]"), ("setup.cfg", "[tool:pytest]")):
        config = tree_root / name
        if not config.is_file():
            continue
        text = config.read_text(encoding="utf-8", errors="replace")
        if key not in text:
            continue
        section = text.split(key, 1)[1]
        match = re.search(r"^\s*python_files\s*=\s*(.+)$", section, re.MULTILINE)
        if match:
            raw = match.group(1).strip()
            patterns = tuple(p.strip().strip("\"'") for p in re.split(r"[,\s]+", raw.strip("[]")) if p.strip().strip("\"'"))
            if patterns:
                return patterns
    return DEFAULT_PYTHON_FILES


#: The pseudo-tree for a test-shaped file that sits in no ``tests/`` directory.
#: Such a file is owned by nothing, so scoping the scan to ``tests/`` alone
#: would make it invisible — the precise shape this gate exists to remove, one
#: level up. It is reached when a workflow executes it directly, which is how
#: ``scripts/integration/spine_test.py`` is run.
LOOSE = "(no tests/ directory)"

_TEST_DIR_NAMES = frozenset({"tests", "test"})


def tracked_files(root: Path) -> list[str]:
    """Every file git tracks, repository-relative.

    ``git ls-files`` rather than a filesystem walk. Three of the four
    directories a walk has to be told to skip — ``node_modules``, ``.venv``,
    ``site-packages`` — are untracked, so asking git removes the list instead
    of maintaining it, and the answer no longer depends on whether anyone has
    run an install in this checkout.
    """
    import subprocess  # noqa: PLC0415 - one call, kept next to its only use

    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise DiscoveryError(f"cannot list tracked files under {root}: {out.stderr.strip()}")
    files = [name for name in out.stdout.split("\0") if name]
    if not files:
        raise DiscoveryError(f"git ls-files returned nothing under {root} — there is no tree here to scan")
    return files


def _owning_tests_dir(rel: str) -> str | None:
    """The outermost ``tests/`` directory this path sits inside, if any."""
    parts = Path(rel).parts
    for index, part in enumerate(parts[:-1]):
        if part in _TEST_DIR_NAMES:
            return Path(*parts[: index + 1]).as_posix()
    return None


def discover_trees(root: Path) -> list[Tree]:
    """Every test file git tracks, grouped by the part of the tree that owns it.

    A tree is a ``tests/`` directory plus the service or package it sits in.
    Grouping is derived from the paths, not from a list of services: one added
    tomorrow is scanned with no edit here, which is the whole point.

    Which filename patterns count is read from each owner's own pytest
    configuration when it sets ``python_files``, because a tree that renames
    the pattern renames what "a test file" means for that tree — scanning for
    the default there would look for files that cannot exist and credit the
    tree with nothing to find.
    """
    by_tree: dict[tuple[str, str], list[str]] = {}
    for rel in tracked_files(root):
        tests_dir = _owning_tests_dir(rel)
        owner = Path(tests_dir).parent.as_posix() if tests_dir else Path(rel).parent.as_posix()
        owner = owner if owner not in {"", "."} else "."
        patterns = python_files_patterns(root / owner if owner != "." else root)
        name = Path(rel).name
        if not any(Path(name).match(pattern) for pattern in patterns):
            continue
        key = (owner, tests_dir) if tests_dir else (LOOSE, LOOSE)
        by_tree.setdefault(key, []).append(rel)

    trees = [Tree(name=owner, tests_dir=tests_dir, files=sorted(files)) for (owner, tests_dir), files in sorted(by_tree.items())]
    if not trees:
        raise DiscoveryError(f"found no tracked Python test files under {root} — the patterns are wrong, or the tree is not there")
    return trees


# --------------------------------------------------------------------------
# conftest collect_ignore
# --------------------------------------------------------------------------
def collect_ignored(tests_dir: Path, root: Path) -> set[str]:
    """Paths a ``conftest.py`` removes from collection, read from its syntax tree.

    A file pytest is told not to collect is not reached, however an invocation
    names it — so a gate that ignored this would credit a file that never runs.
    """
    out: set[str] = set()
    # Both sides resolved, or a symlinked temporary directory (/var -> /private/var
    # on macOS) makes the relative_to below raise on paths that are plainly inside.
    root = root.resolve()
    for conftest in tests_dir.resolve().rglob("conftest.py"):
        try:
            tree = ast.parse(conftest.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if not names & {"collect_ignore", "collect_ignore_glob"}:
                continue
            for element in ast.walk(node.value):
                if isinstance(element, ast.Constant) and isinstance(element.value, str):
                    for match in conftest.parent.glob(element.value):
                        if match.is_file():
                            out.add(match.resolve().relative_to(root).as_posix())
    return out


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------
def scan(root: Path) -> tuple[list[Tree], list[Invocation], list[tuple[str, str, str]]]:
    """(trees, invocations, paths named by an invocation that are not in the tree)."""
    surface = coverage.Surface(root)
    invocations = parse_invocations(surface)
    if not invocations:
        raise DiscoveryError(
            f"parsed zero pytest invocations from the workflows under {root} — the parser is wrong, or the tree is not there"
        )

    trees = discover_trees(root)
    by_file: dict[str, Tree] = {f: tree for tree in trees for f in tree.files}
    missing: list[tuple[str, str, str]] = []

    for inv in invocations:
        base = (root / inv.working_dir).resolve() if inv.working_dir else root
        if inv.bare:
            targets = [base]
        else:
            targets = []
            for token in inv.paths:
                resolved = _resolve(token, base, root)
                if resolved is None:
                    continue
                if not resolved.exists():
                    missing.append((inv.workflow, inv.command, resolved.relative_to(root).as_posix()))
                    continue
                targets.append(resolved)

        ignored = {r for token in inv.ignores if (r := _resolve(token, base, root)) is not None}
        label = f"{inv.workflow}: {_abbreviate(inv.command)}"

        for target in targets:
            for rel, tree in by_file.items():
                path = root / rel
                covered = path == target or target in path.parents
                if not covered:
                    continue
                if any(path == ig or ig in path.parents for ig in ignored):
                    continue
                if inv.markers and deselects_module(inv.markers, module_markers(path)):
                    continue
                tree.reached.add(rel)
                if label not in tree.invocations:
                    tree.invocations.append(label)

    # A file in no tests/ directory is never collected by a directory argument,
    # so the only way it runs is a workflow executing it outright. That is how
    # scripts/integration/spine_test.py runs, and treating it as unreachable
    # would be this gate reporting a gap it had invented.
    _credit_directly_executed(surface, by_file, root)

    for tree in trees:
        if tree.tests_dir == LOOSE:
            continue
        for rel in collect_ignored(root / tree.tests_dir, root):
            tree.reached.discard(rel)

    return trees, invocations, missing


def _credit_directly_executed(surface: coverage.Surface, by_file: dict[str, Tree], root: Path) -> None:
    """Mark a loose test file reached when a workflow runs it as a program.

    The path has to resolve, from the step's own directory, to exactly that
    file. Matching a bare filename instead would credit any step that happened
    to mention the name — the shape that counted eleven services as covered on
    the strength of a quoted path inside an ``echo``.
    """
    loose = {rel: tree for rel, tree in by_file.items() if tree.tests_dir == LOOSE}
    if not loose:
        return
    for workflow, working_dir, text in surface.texts():
        cwd = working_dir
        for segment in _segments(text):
            moved = _cd_target(segment, cwd)
            if moved is not None:
                cwd = moved
                continue
            try:
                tokens = shlex.split(segment, comments=True)
            except ValueError:
                continue
            args = _args_after_interpreter(tokens)
            if not args:
                continue
            base = (root / cwd).resolve() if cwd else root
            resolved = _resolve(args[0], base, root)
            if resolved is None:
                continue
            rel = resolved.relative_to(root).as_posix()
            tree = loose.get(rel)
            if tree is None:
                continue
            tree.reached.add(rel)
            label = f"{workflow}: {_abbreviate(segment)}"
            if label not in tree.invocations:
                tree.invocations.append(label)


def _args_after_interpreter(tokens: list[str]) -> list[str] | None:
    """Arguments to ``python <script>``, or None if this is not that shape."""
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index >= len(tokens) or not re.fullmatch(r"python3?(?:\.\d+)?", tokens[index]):
        return None
    index += 1
    # `python -m pkg` runs a module, and `python -c '...'` runs a string.
    if index >= len(tokens) or tokens[index].startswith("-"):
        return None
    return tokens[index:]


def _abbreviate(command: str, limit: int = 90) -> str:
    flat = " ".join(command.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
def evaluate(
    trees: Iterable[Tree],
    missing: Iterable[tuple[str, str, str]],
    *,
    quarantine: dict[str, str],
) -> list[tuple[str, str]]:
    """Every finding, as (code, detail). Pure, so the self-test can drive it."""
    findings: list[tuple[str, str]] = []
    trees = list(trees)
    all_files = {f for tree in trees for f in tree.files}

    for tree in trees:
        unreached = [f for f in tree.unreached if f not in quarantine]
        if unreached:
            findings.append(
                (
                    "unreached",
                    f"{tree.name}: {len(unreached)} of {len(tree.files)} test file(s) are collected by no workflow invocation. "
                    f"A file nothing runs reports nothing and reads exactly like a file that passed. "
                    f"Run the directory rather than a list of files, or quarantine it with a stated reason.\n"
                    + "\n".join(f"        {f}" for f in unreached),
                )
            )

    for workflow, command, path in missing:
        findings.append(
            (
                "names-nothing",
                f"{workflow} runs `{_abbreviate(command)}` which names {path}, and that path is not in the tree. "
                "A step listing a path that is not there no longer does what it reads as doing.",
            )
        )

    for path, reason in sorted(quarantine.items()):
        if path not in all_files:
            findings.append(("quarantine-names-nothing", f"QUARANTINE lists {path!r}, which is not a test file in the tree"))
        elif not reason.strip():
            findings.append(("quarantine-unexplained", f"QUARANTINE[{path!r}] carries no reason"))
    reached_all = {f for tree in trees for f in tree.reached}
    for path in sorted(set(quarantine) & reached_all):
        findings.append(
            (
                "quarantine-stale",
                f"{path} is quarantined and is now collected by a workflow. Remove the entry — a quarantine list that "
                "names running tests stops describing anything.",
            )
        )

    return findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect (default: git rev-parse)")
    parser.add_argument("--list", action="store_true", help="print every tree with its coverage")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true", help="accepted for symmetry; this script is always a gate")
    parser.add_argument("--self-test", action="store_true", help="prove this gate detects the drift it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    try:
        trees, invocations, missing = scan(root)
    except (DiscoveryError, coverage.GateError, FileNotFoundError) as exc:
        print(f"check_test_discovery: FAILED to run the scan: {exc}", file=sys.stderr)
        return 2

    findings = evaluate(trees, missing, quarantine=QUARANTINE)

    total = sum(len(t.files) for t in trees)
    covered = sum(len(t.reached) for t in trees)

    if args.json:
        print(
            json.dumps(
                {
                    "root": str(root),
                    "trees": [asdict(t) | {"reached": sorted(t.reached), "unreached": t.unreached} for t in trees],
                    "invocations": [asdict(i) for i in invocations],
                    "missing_paths": [{"workflow": w, "command": c, "path": p} for w, c, p in missing],
                    "quarantine": QUARANTINE,
                    "findings": [{"code": c, "detail": d} for c, d in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if findings else 0

    print(f"repo root        {root}")
    print(f"workflows        {len(invocations)} pytest invocation(s) across .github/workflows/")
    print(f"test trees       {len(trees)} ({total} test file(s), {covered} reached, {total - covered} not)")
    print(f"quarantine       {len(QUARANTINE)} recorded, each with a reason")
    print()

    if args.list:
        width = max((len(t.name) for t in trees), default=10)
        for tree in sorted(trees, key=lambda t: t.name):
            gap = len(tree.files) - len(tree.reached)
            mark = "OK  " if gap == 0 else "GAP "
            print(f"  {mark} {tree.name:{width}}  {len(tree.reached):>3}/{len(tree.files):<3} reached")
            for label in tree.invocations:
                print(f"       {'':{width}}  via {label}")
            if not tree.invocations:
                print(f"       {'':{width}}  via nothing")
            for path in tree.unreached:
                note = f"  [quarantined: {QUARANTINE[path]}]" if path in QUARANTINE else ""
                print(f"       {'':{width}}  NOT REACHED {path}{note}")
        print()

    if findings:
        print(f"FAIL — {len(findings)} finding(s):")
        for code, detail in findings:
            print(f"  [{code}] {detail}")
        return 1
    print(f"OK — every one of {total} test file(s) across {len(trees)} tree(s) is collected by an invocation CI runs,")
    print(f"     and every path those invocations name is in the tree. {len(QUARANTINE)} quarantined, each with a reason.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test() -> int:
    """Inject each defect this gate exists to catch and require it to be caught."""

    def tree(files: list[str], reached: list[str]) -> Tree:
        t = Tree(name="services/x", tests_dir="services/x/tests", files=files)
        t.reached = set(reached)
        return t

    one = ["services/x/tests/test_a.py"]
    clean = [tree(one, one)]

    def run(trees, missing=(), *, quarantine=None):
        return {code for code, _ in evaluate(trees, missing, quarantine=quarantine or {})}

    cases: list[tuple[str, str, set[str]]] = [
        (
            "a test file in a tree that no invocation reaches",
            "unreached",
            run([tree([*one, "services/x/tests/test_b.py"], one)]),
        ),
        (
            "an invocation naming a path that is not in the tree",
            "names-nothing",
            run(clean, [("ci.yml", "pytest tests/test_gone.py", "services/x/tests/test_gone.py")]),
        ),
        (
            "a quarantine entry naming a file that does not exist",
            "quarantine-names-nothing",
            run(clean, quarantine={"services/x/tests/test_ghost.py": "reason"}),
        ),
        (
            "a quarantine entry with no reason given",
            "quarantine-unexplained",
            run([tree([*one, "services/x/tests/test_b.py"], one)], quarantine={"services/x/tests/test_b.py": "  "}),
        ),
        (
            "a quarantined file that CI has started running",
            "quarantine-stale",
            run(clean, quarantine={"services/x/tests/test_a.py": "reason"}),
        ),
    ]

    print("check_test_discovery self-test")
    print("baseline: one tree, one file, reached; 0 findings (every case below perturbs exactly that)\n")
    ok = not run(clean)
    print(f"  {'PASS' if ok else 'FAIL'}  the unperturbed baseline reports nothing")

    for description, expected, codes in cases:
        caught = expected in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected}]  got {sorted(codes) or 'nothing'}")

    # The argument reader. Crediting a file an invocation never named is the
    # failure that matters here, so the parser is asserted directly rather
    # than inferred from the findings above.
    reader: list[tuple[str, object, object]] = [
        ("a directory argument is a path", _split_args(["tests/", "-q"]), (["tests/"], [], "")),
        ("--ignore= subtracts", _split_args(["tests/", "--ignore=tests/slow"]), (["tests/"], ["tests/slow"], "")),
        ("--ignore with a space subtracts", _split_args(["tests/", "--ignore", "tests/slow"]), (["tests/"], ["tests/slow"], "")),
        ("-k takes a value that is not a path", _split_args(["tests/", "-k", "not_slow"]), (["tests/"], [], "")),
        ("-m is captured, not discarded", _split_args(["tests/", "-m", "not integration"]), (["tests/"], [], "not integration")),
        ("--cov=app is not a path", _split_args(["tests/", "--cov=app"]), (["tests/"], [], "")),
        ("a node id resolves to its file", _split_args(["tests/test_a.py::test_one"]), (["tests/test_a.py::test_one"], [], "")),
    ]
    for label, got, want in reader:
        correct = got == want
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  READER: {label}")
        print(f"        expected {want}  got {got}")

    chooser: list[tuple[str, object, object]] = [
        ("a plain invocation yields its arguments", _args_after_pytest(shlex.split("pytest tests/ -q")), ["tests/", "-q"]),
        ("python -m pytest reaches the same place", _args_after_pytest(shlex.split("python3 -m pytest tests/")), ["tests/"]),
        ("an env prefix is stepped over", _args_after_pytest(shlex.split("PYTHONPATH=. python -m pytest tests/")), ["tests/"]),
        ("poetry run reaches the same place", _args_after_pytest(shlex.split("poetry run pytest tests/")), ["tests/"]),
        ("a pip install line is not an invocation", _args_after_pytest(shlex.split("pip install pytest pytest-asyncio")), None),
        ("another program is not an invocation", _args_after_pytest(shlex.split("ruff check services/")), None),
    ]
    for label, got, want in chooser:
        correct = got == want
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  CHOOSER: {label}")
        print(f"        expected {want}  got {got}")

    # Marker deselection. `not integration` and `integration` differ by three
    # characters and invert the answer, so both directions are asserted —
    # getting this backwards would credit exactly the files nothing runs.
    integration = frozenset({"integration"})
    marks: list[tuple[str, bool, bool]] = [
        ("`not integration` deselects an integration module", deselects_module("not integration", integration), True),
        ("`not integration` keeps an unmarked module", deselects_module("not integration", frozenset()), False),
        ("`integration` keeps an integration module", deselects_module("integration", integration), False),
        ("`integration` deselects an unmarked module", deselects_module("integration", frozenset()), True),
        ("`not a and not b` deselects a module carrying b", deselects_module("not a and not b", frozenset({"b"})), True),
        ("`not a and not b` keeps a module carrying neither", deselects_module("not a and not b", frozenset({"c"})), False),
        ("an empty expression deselects nothing", deselects_module("", integration), False),
        ("an expression that will not parse deselects nothing", deselects_module("not and or", integration), False),
    ]
    for label, got_mark, want_mark in marks:
        correct = got_mark == want_mark
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  MARKERS: {label}")
        print(f"        expected {want_mark}  got {got_mark}")

    # And the corpus itself, against a real git repository — every count above
    # is only as good as the claim that the files were found in the first
    # place, and this is the half of the gate that decides what "a test file"
    # is. An untracked file must not be counted: the whole reason the corpus
    # comes from git is that an install directory is not this tree's tests.
    import subprocess  # noqa: PLC0415 - only the self-test builds a scratch repository
    import tempfile  # noqa: PLC0415

    with tempfile.TemporaryDirectory(prefix="aisoc-discovery-") as tmp:
        sandbox = Path(tmp)
        for rel, body in (
            ("services/x/tests/test_a.py", ""),
            ("services/x/tests/b_test.py", ""),
            ("services/x/tests/helper.py", ""),
            ("scripts/integration/spine_test.py", ""),
        ):
            (sandbox / rel).parent.mkdir(parents=True, exist_ok=True)
            (sandbox / rel).write_text(body)
        # Tracked by nothing, so the corpus must not see it.
        (sandbox / "node_modules/pkg/tests").mkdir(parents=True)
        (sandbox / "node_modules/pkg/tests/test_vendor.py").write_text("")
        git = ["git", "-c", "user.name=gate", "-c", "user.email=gate@invalid", "-c", "commit.gpgsign=false"]
        for argv in (["init", "-q", "-b", "main"], ["add", "services", "scripts"], ["commit", "-qm", "scratch"]):
            subprocess.run(git + argv, cwd=sandbox, check=True, capture_output=True)  # noqa: S603

        (sandbox / "services/x/tests/test_a.py").write_text("import pytest\npytestmark = pytest.mark.integration\n")
        read_marks = module_markers(sandbox / "services/x/tests/test_a.py")
        correct = read_marks == frozenset({"integration"})
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  MARKERS: a module-level pytestmark is read off the syntax tree")
        print(f"        expected {{'integration'}}  got {set(read_marks) or 'nothing'}")
        (sandbox / "services/x/tests/test_a.py").write_text("")

        walked = discover_trees(sandbox)
        names = sorted(f for t in walked for f in t.files)
        want_names = ["scripts/integration/spine_test.py", "services/x/tests/b_test.py", "services/x/tests/test_a.py"]
        correct = names == want_names
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  CORPUS: both default patterns count; a helper and an untracked tree do not")
        print(f"        expected {want_names}  got {names}")

        loose = sorted(t.name for t in walked if t.tests_dir == LOOSE)
        correct = loose == [LOOSE]
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  CORPUS: a test-shaped file in no tests/ directory is its own tree, not invisible")
        print(f"        expected [{LOOSE!r}]  got {loose}")

        # conftest collect_ignore, which is the one way a named file is still
        # not reached — a gate blind to it would credit a file that never runs.
        (sandbox / "services/x/tests/conftest.py").write_text('collect_ignore = ["test_a.py"]\n')
        ignored = collect_ignored(sandbox / "services/x/tests", sandbox)
        correct = ignored == {"services/x/tests/test_a.py"}
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  CORPUS: conftest collect_ignore removes a file from reach")
        print(f"        expected {{'services/x/tests/test_a.py'}}  got {ignored or 'nothing'}")

    print()
    if not ok:
        print("self-test FAILED: this gate did not catch drift it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects and {len(reader) + len(chooser) + len(marks) + 5} component assertions")

    # And the property the meta-gate exists for: this gate must refuse a tree
    # with no content rather than reporting it clean.
    return self_test_main(Path(__file__).name, [])


if __name__ == "__main__":
    sys.exit(main())
