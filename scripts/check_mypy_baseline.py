#!/usr/bin/env python3
"""Run mypy, and refuse to let the result get worse.

`ci.yml` has a job called **Python — Lint & Type-check**. It installed mypy
and never invoked it. Six manifests carry a `[tool.mypy]` table and three of
them set `strict = true`, so three authors explicitly asked for type checking
that has never once run. A tool in the install list that never executes
implies a check that is not happening, which is this repository's dominant
defect wearing yet another costume — a workflow green on eight consecutive
weekly runs with every real step skipped, a lint job printing "2/2 passed"
while 32 of 62 packs did not match, three check scripts wired into no
workflow at all.

Two honest options existed: stop installing mypy, or run it. Running it wins,
because the configuration says six trees want it.

What this does *not* do is soften the answer to make it pass. There is no new
`ignore_errors`, no added `ignore_missing_imports`, no `--no-strict-optional`,
and no tree excluded from the check. `strict = true` stays strict and the
tests are checked along with the source. The findings — 673 of them at the
time of writing — are recorded in `scripts/mypy_baseline.json` exactly as
mypy reports them, and the gate fails when any of them grows. A recorded
finding is reported; a suppressed one is hidden, and the difference is the
whole point.

The baseline is keyed on `(tree, file, error-code)`. A bare per-tree total
would let one error be introduced while an unrelated one is fixed, leaving
the count flat and the gate silent — the same "compares a tally against
everything except itself" shape that left a gate off by one while CI stayed
green.

Environment. mypy's answer depends on what is importable, so the baseline is
only meaningful against a fixed environment: **mypy alone, no project
dependencies installed, on the interpreter `ci.yml` uses**. That is what CI
does and what `--update` must be run under. Anything else produces a
different set of `import-untyped` findings and a baseline nobody can
reproduce.

Directions, because a one-directional gate is how drift escapes here:

  findings -> baseline  a finding not in the baseline, or more of one than
                        the baseline records, fails
  baseline -> findings  a baseline entry mypy no longer reports fails, so a
                        fixed error must be banked rather than left as
                        headroom for the next one
  config -> baseline    a tree declaring [tool.mypy] and absent from the
                        baseline fails, so adding a config does not quietly
                        add an unchecked tree
  baseline -> config    a baseline entry for a tree with no config fails
  tree -> config        a Python tree on disk that declares no [tool.mypy]
                        fails, so a new service is type-checked from its
                        first commit rather than from whenever somebody
                        notices
  config -> tree        a config, or a baseline entry, naming a tree that is
                        no longer on disk fails
  file -> scope         a Python file this repository tracks that no tree and
                        no scope covers fails

The last three are the coverage gate, and they exist because of what this
started as: six of twenty trees declared `[tool.mypy]`, and the job named
"Lint & Type-check" reported green over the fourteen it never opened. A tool
that appears to cover the repository while covering a third of it is
indistinguishable from no tool at all, only more reassuring. `tree -> config`
is the direction that catches a new service; `config -> tree` is the one that
rots quietly, because nothing ever fails when a stale entry is simply never
consulted.

Discovery is structural — every directory holding a `pyproject.toml` — not
`services/*` plus `packages/*`. The glob was a naming convention, and a
Python tree added anywhere else would have satisfied a coverage gate written
against the same glob while being checked by nothing, which is the shape this
file exists to refuse.

The unmanaged scope
-------------------
`tree -> config` asks whether every tree is configured. It cannot ask whether
every *file* is in a tree, and 153 were not: `scripts/`, `tests/`, `tools/`
and `plugins/` hold Python that belongs to no manifest, so giving all twenty
trees a `[tool.mypy]` table still left those unchecked. Most of them are
under `scripts/`, which is where the CI gates live — the code the rest of
this repository's claims are verified by was the only Python in it nothing
type-checked.

They are covered by a scoped invocation rather than by a repo-root manifest.
`mypy-unmanaged.toml` records the three measurements behind that choice; the
short version is that a root `pyproject.toml` makes `poetry check` invalid
from every directory without a manifest of its own, hands pytest a configfile
it did not have, and would be a 21st Python tree that the packaging gates
miss only because their globs stop at `services/*` + `packages/*`.

The scope is **computed, never listed**: `git ls-files '*.py'` minus every
manifest tree minus the archived prototype. A list would be a path-glob
convention wearing different clothes, and the file added outside it is
exactly the one a convention cannot see. Adding a script anywhere puts it in
scope with no edit; deleting a tree's manifest moves that tree's files into
this scope rather than out of coverage, so the two directions cannot both be
satisfied by removing something.

Scanned, not assumed. mypy is invoked with an explicit file list and
`--linecount-report`, and the run fails unless mypy's own report accounts for
every module asked of it. "Found nothing" and "opened nothing" print the same
word otherwise, which is the failure mode this file was written against.

Usage:
    python scripts/check_mypy_baseline.py
    python scripts/check_mypy_baseline.py --update     # re-record, then read the diff
    python scripts/check_mypy_baseline.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from collections import defaultdict
from pathlib import Path

BASELINE = Path("scripts/mypy_baseline.json")

#: The config the unmanaged scope is checked under, and the name it is
#: recorded against. The name is bracketed so it cannot be mistaken for the
#: directory paths every other key in the baseline is.
UNMANAGED_CONFIG = Path("mypy-unmanaged.toml")
UNMANAGED_SCOPE = "(unmanaged)"

# The archived prototype. `.github/workflows/codeql.yml` carries the same
# exclusion and the project rules forbid editing anything under it, so a
# finding there is not actionable.
_EXCLUDED_PREFIXES = ("plans/",)
_SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git", "dist", "build"})

# `file:line: error: message  [code]`
_FINDING = re.compile(r"^(?P<file>[^:]+):\d+:(?:\d+:)?\s*error:\s*(?P<message>.*?)\s*(?:\[(?P<code>[\w-]+)\])?$")


def repo_root() -> Path:
    """The repository, per git — not per this file's location.

    A sibling gate resolved its root from ``Path(__file__).parent.parent``,
    so a copy run from anywhere else would scan whatever happened to sit two
    levels above it and print a confident OK about a tree it never opened.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parent,
    )
    if out.returncode == 0 and out.stdout.strip():
        return Path(out.stdout.strip()).resolve()
    return Path(__file__).resolve().parent.parent


def python_trees(root: Path) -> list[str]:
    """Every directory in the repository that holds a `pyproject.toml`.

    Structural rather than `services/*` + `packages/*`: a glob is a naming
    convention, and a Python tree added anywhere else is exactly the one a
    convention-shaped gate would miss.
    """
    trees: list[str] = []
    for manifest in root.rglob("pyproject.toml"):
        if any(part in _SKIP_DIRS for part in manifest.parts):
            continue
        rel = manifest.parent.relative_to(root).as_posix()
        if rel == "." or rel.startswith(_EXCLUDED_PREFIXES):
            continue
        trees.append(rel)
    return sorted(trees)


def tracked_python_files(root: Path) -> list[str]:
    """Every `.py` file this repository tracks, per git.

    git rather than a filesystem walk because the question is "what does this
    repository contain", and a walk answers "what is on this disk" — which
    includes a contributor's virtualenv, a stale build directory and whatever
    a previous run wrote. Those are the inputs that make a coverage number
    depend on who ran it.

    Fails closed: if git cannot enumerate, the caller gets an exception rather
    than an empty list, because an empty list here reads as "no file is
    unmanaged" and would turn the coverage claim into its own opposite.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z", "--", "*.py"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        raise RuntimeError(f"git ls-files failed in {root}: {out.stderr.strip()[:300]}")
    return sorted(f for f in out.stdout.split("\0") if f)


def unmanaged_files(root: Path, trees: list[str]) -> list[str]:
    """Tracked Python belonging to no manifest tree.

    Computed as a complement, so it is not a list anybody has to remember to
    extend. The two memberships move together: a file leaves this set only by
    a tree's manifest appearing above it, which `tree -> config` then requires
    to declare `[tool.mypy]`.
    """
    prefixes = tuple(f"{tree}/" for tree in trees)
    return [
        rel
        for rel in tracked_python_files(root)
        if not rel.startswith(_EXCLUDED_PREFIXES) and not rel.startswith(prefixes) and rel not in trees
    ]


def module_name(root: Path, rel: str) -> str:
    """The module name mypy will give a file, by mypy's own rule.

    Walk up while the directory holds an `__init__.py`; everything above that
    is the search path. Needed because two files that resolve to the same
    module name cannot be checked in one invocation, and sixteen do:
    `plugins/*/plugin.py`, in directories whose hyphens keep them from ever
    being packages.
    """
    path = Path(rel)
    parts = [] if path.stem == "__init__" else [path.stem]
    parent = path.parent
    while parent != Path(".") and (root / parent / "__init__.py").is_file():
        parts.insert(0, parent.name)
        parent = parent.parent
    return ".".join(parts) or path.parent.name


def batch(root: Path, files: list[str]) -> list[list[str]]:
    """Split a file list so no invocation sees one module name twice.

    Computed rather than configured. The collision today is
    `plugins/*/plugin.py`; the point of deriving it is that the seventeenth
    plugin, or any other future collision, costs nobody a code change.
    """
    batches: list[list[str]] = []
    taken: list[set[str]] = []
    for rel in files:
        name = module_name(root, rel)
        for index, names in enumerate(taken):
            if name not in names:
                batches[index].append(rel)
                names.add(name)
                break
        else:
            batches.append([rel])
            taken.append({name})
    return batches


def declares_mypy(root: Path, tree: str) -> bool:
    data = tomllib.loads((root / tree / "pyproject.toml").read_text(encoding="utf-8"))
    return "mypy" in data.get("tool", {})


def discover(root: Path) -> list[str]:
    """Every Python tree whose manifest declares a [tool.mypy] table."""
    return [tree for tree in python_trees(root) if declares_mypy(root, tree)]


def coverage_problems(root: Path, trees: list[str], recorded: dict) -> list[str]:
    """Every direction of "is every Python file actually type-checked?"."""
    problems: list[str] = []
    for tree in python_trees(root):
        if tree not in trees:
            problems.append(
                f"{tree}/pyproject.toml declares no [tool.mypy] — a Python tree nothing "
                f"type-checks (tree -> config). Copy the table from a sibling: the services "
                f"use python_version/strict=false/ignore_missing_imports, the packages use "
                f"strict=true. Then run --update to record what it surfaces"
            )
    for tree in sorted((set(recorded) | set(trees)) - {UNMANAGED_SCOPE}):
        if not (root / tree / "pyproject.toml").is_file():
            problems.append(
                f"`{tree}` is configured or recorded but has no pyproject.toml on disk — "
                f"a config for a tree that no longer exists never fails on its own, which is "
                f"why it is checked here (config -> tree)"
            )

    # file -> scope. The manifest trees cover what is under them; this scope
    # covers the rest, and it only covers the rest while its config exists.
    # Deleting that file would return 153 files to being checked by nothing
    # while every other direction above kept printing OK, so it is the one
    # thing here that is checked by name.
    if not (root / UNMANAGED_CONFIG).is_file():
        orphans = unmanaged_files(root, trees)
        problems.append(
            f"{UNMANAGED_CONFIG} is missing, so {len(orphans)} tracked Python file(s) under "
            f"{', '.join(sorted({f.split('/')[0] for f in orphans})) or '(none)'} belong to no "
            f"tree and no scope — nothing type-checks them (file -> scope)"
        )
    return problems


def run_mypy(root: Path, tree: str) -> tuple[dict[str, dict[str, int]], str]:
    """Findings for one tree, as {relative file: {error code: count}}."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "mypy", "--no-color-output", "--no-error-summary", "."],
        cwd=root / tree,
        capture_output=True,
        text=True,
        check=False,
    )
    findings: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for line in completed.stdout.splitlines():
        match = _FINDING.match(line.strip())
        if not match:
            continue
        findings[match.group("file")][match.group("code") or "no-code"] += 1
    # mypy exits 1 for findings and 2 for a crash or a bad invocation. Treating
    # those the same would turn "mypy could not run" into "mypy found nothing",
    # which is the failure this whole file exists to stop.
    if completed.returncode not in (0, 1):
        return {}, f"{tree}: mypy exited {completed.returncode} — {completed.stderr.strip()[:400]}"
    return {f: dict(c) for f, c in findings.items()}, ""


def _reported_modules(report_dir: Path) -> set[str]:
    """The modules mypy says it opened, from `--linecount-report`."""
    path = report_dir / "linecount.txt"
    if not path.is_file():
        return set()
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-1] != "total":
            seen.add(fields[-1])
    return seen


def run_mypy_unmanaged(root: Path, files: list[str]) -> tuple[dict[str, dict[str, int]], str]:
    """Findings for the files that belong to no manifest tree.

    Three properties the per-tree runner gets for free and this one has to
    assert, because it passes a computed list rather than a directory:

    * mypy is asked for `--linecount-report` and the run fails unless its own
      report accounts for every module handed to it. Passing a path mypy
      cannot read is a crash, not a silence — but "the list was empty" and
      "the list was checked" are indistinguishable from the exit code alone,
      and that is precisely the confusion this gate exists to refuse.
    * a finding against a file outside the scope fails rather than being
      recorded. `follow_imports = "silent"` should make that impossible; if
      it ever stops being true, the baseline would start double-counting a
      file its own tree already checks, under a different config.
    * an empty scope fails. It is legitimate only if the repository has no
      unmanaged Python at all, and reaching that state by breaking the walk
      is far likelier than reaching it by tidying.
    """
    if not files:
        return {}, (
            f"{UNMANAGED_SCOPE}: the scope is empty — every tracked .py file resolved to a "
            f"manifest tree, which is either a repository nobody expects or a broken walk"
        )
    config = root / UNMANAGED_CONFIG
    if not config.is_file():
        return {}, f"{UNMANAGED_SCOPE}: {UNMANAGED_CONFIG} is missing, so the scope has no config to be checked under"

    findings: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    in_scope = set(files)
    wanted = {module_name(root, rel) for rel in files}
    opened: set[str] = set()
    stray: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="mypy_unmanaged_") as tmp:
        for index, group in enumerate(batch(root, files)):
            report = Path(tmp) / str(index)
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    sys.executable,
                    "-m",
                    "mypy",
                    "--no-color-output",
                    "--no-error-summary",
                    "--config-file",
                    str(config),
                    "--linecount-report",
                    str(report),
                    *group,
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode not in (0, 1):
                return {}, f"{UNMANAGED_SCOPE}: mypy exited {completed.returncode} — {completed.stderr.strip()[:400]}"
            opened |= _reported_modules(report)
            for line in completed.stdout.splitlines():
                match = _FINDING.match(line.strip())
                if not match:
                    continue
                file = match.group("file")
                if file not in in_scope:
                    stray.add(file)
                    continue
                findings[file][match.group("code") or "no-code"] += 1

    if stray:
        return {}, (
            f"{UNMANAGED_SCOPE}: mypy reported findings for {len(stray)} file(s) outside the scope "
            f"({', '.join(sorted(stray)[:3])}...) — follow_imports is leaking into trees that are "
            f"checked under their own config, so these would be counted twice"
        )
    missed = wanted - opened
    if missed:
        return {}, (
            f"{UNMANAGED_SCOPE}: mypy's linecount report accounts for {len(opened)} module(s) but "
            f"{len(missed)} of the {len(wanted)} asked for are absent ({', '.join(sorted(missed)[:5])}) — "
            f"the scope was not scanned, and an empty finding list here would have read as clean"
        )
    return {f: dict(c) for f, c in findings.items()}, ""


def compare(tree: str, found: dict[str, dict[str, int]], recorded: dict[str, dict[str, int]]) -> list[str]:
    problems: list[str] = []
    for file in sorted(set(found) | set(recorded)):
        seen, known = found.get(file, {}), recorded.get(file, {})
        for code in sorted(set(seen) | set(known)):
            now, before = seen.get(code, 0), known.get(code, 0)
            if now > before:
                problems.append(
                    f"{tree}/{file}: {now} `{code}` finding(s), baseline records {before} "
                    f"(findings -> baseline). Fix it, or if it is genuinely correct add a "
                    f"targeted `# type: ignore[{code}]` with a comment — do not widen the config"
                )
            elif now < before:
                problems.append(
                    f"{tree}/{file}: {now} `{code}` finding(s), baseline still records {before} "
                    f"(baseline -> findings). Run --update to bank the fix, so the headroom "
                    f"does not silently absorb the next one"
                )
    return problems


def load(root: Path) -> dict:
    path = root / BASELINE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _python_file_count(root: Path, tree: str) -> int:
    return sum(1 for path in (root / tree).rglob("*.py") if not any(part in _SKIP_DIRS for part in path.parts))


def run(root: Path, update: bool = False) -> int:
    all_trees = python_trees(root)
    trees = discover(root)
    if not trees:
        print(f"check_mypy_baseline: no tree under {root} declares [tool.mypy]")
        return 1

    recorded = load(root)
    results: dict[str, dict[str, dict[str, int]]] = {}
    problems: list[str] = coverage_problems(root, trees, recorded)

    unmanaged = unmanaged_files(root, all_trees)
    scanned = sum(_python_file_count(root, tree) for tree in trees)
    print(f"check_mypy_baseline: root {root}")
    # Name what was scanned. "OK" over a tree that was never opened is the
    # failure this gate exists to make impossible, and a count is the cheapest
    # way for a reader to notice it happened.
    print(f"  {len(trees)}/{len(all_trees)} Python tree(s) configured, {scanned} .py file(s) in scope")
    print(
        f"  {UNMANAGED_SCOPE}: {len(unmanaged)} tracked .py file(s) in no tree, "
        f"checked under {UNMANAGED_CONFIG} in {len(batch(root, unmanaged))} invocation(s)"
    )
    for tree in trees:
        found, error = run_mypy(root, tree)
        if error:
            problems.append(error)
            continue
        results[tree] = found
        total = sum(sum(c.values()) for c in found.values())
        print(f"  {tree}: {total} finding(s) across {len(found)} file(s)")

    found, error = run_mypy_unmanaged(root, unmanaged)
    if error:
        problems.append(error)
    else:
        results[UNMANAGED_SCOPE] = found
        total = sum(sum(c.values()) for c in found.values())
        print(f"  {UNMANAGED_SCOPE}: {total} finding(s) across {len(found)} file(s)")

    if update:
        (root / BASELINE).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        total = sum(sum(sum(c.values()) for c in f.values()) for f in results.values())
        print(f"check_mypy_baseline: recorded {total} finding(s) across {len(results)} tree(s) in {BASELINE}")
        return 1 if problems else 0

    for tree in sorted(results):
        if tree not in recorded:
            what = "is checked but" if tree == UNMANAGED_SCOPE else "declares [tool.mypy] but"
            problems.append(
                f"{tree} {what} has no baseline entry — a scope added "
                f"without being recorded is a scope nothing checks (config -> baseline)"
            )
            continue
        problems += compare(tree, results[tree], recorded[tree])
    for tree in sorted(set(recorded) - set(trees) - {UNMANAGED_SCOPE}):
        problems.append(
            f"{BASELINE} records `{tree}`, which no longer declares [tool.mypy] — "
            f"remove it rather than leaving a baseline for a tree nobody checks "
            f"(baseline -> config)"
        )

    total = sum(sum(sum(c.values()) for c in f.values()) for f in results.values())
    print(f"  {total} finding(s) total, {len(trees)} tree(s) + {UNMANAGED_SCOPE} checked: {', '.join(trees)}")

    if problems:
        print("check_mypy_baseline: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("check_mypy_baseline: OK — no tree got worse")
    return 0


def _coverage_self_test() -> tuple[list[str], int]:
    """Inject coverage drift each way against a throwaway repository.

    A fixture is worth building here, unlike for `compare`, because the
    property under test is discovery — whether the walk *finds* a tree — and
    that cannot be exercised by handing a function two dictionaries.
    """
    failures: list[str] = []
    service = '[tool.poetry]\nname = "x"\n\n[tool.mypy]\npython_version = "3.11"\n'
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # `unmanaged_files` reads the tree through git and fails closed when
        # it cannot, so the fixture has to be a real repository.
        subprocess.run(["git", "init", "-q"], cwd=root, check=False, capture_output=True)  # noqa: S603 - fixed argv
        (root / "services" / "alpha").mkdir(parents=True)
        (root / "services" / "alpha" / "pyproject.toml").write_text(service, encoding="utf-8")
        # A tree somewhere the old `services/*` + `packages/*` glob never looked.
        (root / "tools" / "gamma").mkdir(parents=True)
        (root / "tools" / "gamma" / "pyproject.toml").write_text(service, encoding="utf-8")
        # The prototype subtree, which is excluded on purpose.
        (root / "plans" / "cyble-aisoc" / "platform").mkdir(parents=True)
        (root / "plans" / "cyble-aisoc" / "platform" / "pyproject.toml").write_text("[tool.poetry]\nname = 'old'\n", encoding="utf-8")

        cases: list[tuple[str, str]] = []

        found = python_trees(root)
        cases.append(
            (
                "discovery is structural, not services/* + packages/*",
                "" if set(found) == {"services/alpha", "tools/gamma"} else f"walk found {found}",
            )
        )

        # tree -> config: a Python tree with no [tool.mypy].
        (root / "services" / "beta").mkdir()
        (root / "services" / "beta" / "pyproject.toml").write_text("[tool.poetry]\nname = 'beta'\n", encoding="utf-8")
        problems = coverage_problems(root, discover(root), {})
        cases.append(
            (
                "an unconfigured Python tree is reported",
                "" if any("tree -> config" in p and "services/beta" in p for p in problems) else f"got {problems}",
            )
        )

        # config -> tree: a baseline entry whose directory is gone.
        problems = coverage_problems(root, ["services/alpha"], {"services/alpha": {}, "services/deleted": {}})
        cases.append(
            (
                "a recorded tree that no longer exists is reported",
                "" if any("config -> tree" in p and "services/deleted" in p for p in problems) else f"got {problems}",
            )
        )

        # And the excluded prototype must not be demanded.
        problems = coverage_problems(root, discover(root), {})
        cases.append(
            (
                "the archived plans/ subtree is not demanded",
                "" if not any("plans/" in p for p in problems) else f"got {problems}",
            )
        )

        # file -> scope, against a real git repository: the complement has to
        # be computed from the tree, because a listed one is the convention
        # this gate exists to refuse.
        (root / "scripts").mkdir()
        (root / "scripts" / "gate.py").write_text("x = 1\n", encoding="utf-8")
        (root / "services" / "alpha" / "mod.py").write_text("y = 2\n", encoding="utf-8")
        # A tree in a directory no convention would have thought to look in.
        (root / "bench").mkdir()
        (root / "bench" / "runner.py").write_text("z = 3\n", encoding="utf-8")
        (root / "plans" / "cyble-aisoc" / "old.py").write_text("w = 4\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=root, check=False, capture_output=True)  # noqa: S603 - fixed argv

        orphans = set(unmanaged_files(root, python_trees(root)))
        cases.append(
            (
                "a file in no tree is unmanaged, wherever it sits",
                "" if {"scripts/gate.py", "bench/runner.py"} <= orphans else f"got {sorted(orphans)}",
            )
        )
        cases.append(
            (
                "a file inside a tree is not unmanaged, and plans/ is excluded",
                "" if not ({"services/alpha/mod.py", "plans/cyble-aisoc/old.py"} & orphans) else f"got {sorted(orphans)}",
            )
        )

        # Deleting a manifest must move its files into the unmanaged scope
        # rather than out of coverage — the two directions cannot both be
        # satisfied by removing something.
        (root / "services" / "alpha" / "pyproject.toml").unlink()
        moved = set(unmanaged_files(root, python_trees(root)))
        cases.append(
            (
                "deleting a manifest moves its files into the scope, not out of coverage",
                "" if "services/alpha/mod.py" in moved else f"got {sorted(moved)}",
            )
        )

        # And the scope loses its config: 153 files returning to nothing must
        # fail, not pass quietly.
        problems = coverage_problems(root, discover(root), {})
        cases.append(
            (
                "a missing unmanaged config is reported",
                "" if any("file -> scope" in p for p in problems) else f"got {problems}",
            )
        )

        # Module-name batching, which is what makes plugins/*/plugin.py
        # checkable at all. Derived from the tree, so a future collision costs
        # nobody a code change.
        for plugin in ("one", "two"):
            (root / "plugins" / plugin).mkdir(parents=True)
            (root / "plugins" / plugin / "plugin.py").write_text("v = 5\n", encoding="utf-8")
        groups = batch(root, ["plugins/one/plugin.py", "plugins/two/plugin.py", "scripts/gate.py"])
        cases.append(
            (
                "two files with one module name go to separate invocations",
                "" if len(groups) == 2 and all(len({module_name(root, f) for f in g}) == len(g) for g in groups) else f"got {groups}",
            )
        )
        # `tools/__init__.py` makes `tools.detection_import.common` rather
        # than `common`, and getting that wrong invents collisions that split
        # the run into hundreds of invocations.
        (root / "pkg").mkdir()
        (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (root / "pkg" / "leaf.py").write_text("", encoding="utf-8")
        cases.append(
            (
                "module names follow __init__.py up the tree",
                ""
                if (module_name(root, "pkg/leaf.py"), module_name(root, "scripts/gate.py")) == ("pkg.leaf", "gate")
                else f"got {module_name(root, 'pkg/leaf.py')} / {module_name(root, 'scripts/gate.py')}",
            )
        )

        # An empty scope is a broken walk far more often than a tidy tree.
        empty, error = run_mypy_unmanaged(root, [])
        cases.append(
            (
                "an empty scope fails rather than reporting clean",
                "" if error and not empty else f"got {error!r}",
            )
        )

        for name, failure in cases:
            if failure:
                failures.append(f"{name}: {failure}")
            print(f"  self-test [{'FAIL' if failure else 'ok'}] {name}")
        return failures, len(cases)


def self_test(root: Path) -> int:
    """Prove the comparison reports drift in each direction.

    `compare` is tested directly rather than through a throwaway repository:
    a fixture would need a working mypy install per case, and the property
    under test is the comparison, not mypy.
    """
    cases = [
        ("a new finding", {"a.py": {"arg-type": 1}}, {}, "findings -> baseline"),
        ("more of a known finding", {"a.py": {"arg-type": 2}}, {"a.py": {"arg-type": 1}}, "findings -> baseline"),
        ("a fixed finding left banked", {}, {"a.py": {"arg-type": 1}}, "baseline -> findings"),
        (
            "one swapped for another, total unchanged",
            {"a.py": {"union-attr": 1}},
            {"a.py": {"arg-type": 1}},
            "findings -> baseline",
        ),
        ("unchanged", {"a.py": {"arg-type": 1}}, {"a.py": {"arg-type": 1}}, None),
    ]
    failures: list[str] = []
    for name, found, recorded, expect in cases:
        problems = compare("t", found, recorded)
        blob = " ".join(problems)
        if expect is None:
            failure = f"{name}: expected no problem, got {problems}" if problems else None
        elif not problems:
            failure = f"{name}: injected drift went UNDETECTED"
        elif expect not in blob:
            failure = f"{name}: detected something else — {problems}"
        else:
            failure = None
        if failure:
            failures.append(failure)
        print(f"  self-test [{'FAIL' if failure else 'ok'}] {name}")

    # The baseline must describe this tree, not a remembered one.
    trees, recorded = discover(root), load(root)
    if trees and recorded and set(trees) | {UNMANAGED_SCOPE} != set(recorded):
        failures.append(f"baseline covers {sorted(recorded)} but the tree declares {sorted(trees)} plus {UNMANAGED_SCOPE}")
    print(f"  self-test [{'FAIL' if failures and 'baseline covers' in failures[-1] else 'ok'}] baseline matches the tree")

    coverage_failures, coverage_cases = _coverage_self_test()
    failures += coverage_failures

    if failures:
        print("\ncheck_mypy_baseline --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_mypy_baseline --self-test: OK — {len(cases) + 1 + coverage_cases} cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--update", action="store_true", help="re-record the baseline from this run")
    parser.add_argument("--self-test", action="store_true", help="prove the comparison detects drift")
    args = parser.parse_args()

    root = (args.repo_root or repo_root()).resolve()
    if not (root / "services").is_dir():
        print(f"{root} does not look like the AiSOC repository (no services/)")
        return 1
    return self_test(root) if args.self_test else run(root, update=args.update)


if __name__ == "__main__":
    sys.exit(main())
