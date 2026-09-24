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

The last two are the coverage gate, and they exist because of what this
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


def declares_mypy(root: Path, tree: str) -> bool:
    data = tomllib.loads((root / tree / "pyproject.toml").read_text(encoding="utf-8"))
    return "mypy" in data.get("tool", {})


def discover(root: Path) -> list[str]:
    """Every Python tree whose manifest declares a [tool.mypy] table."""
    return [tree for tree in python_trees(root) if declares_mypy(root, tree)]


def coverage_problems(root: Path, trees: list[str], recorded: dict) -> list[str]:
    """Both directions of "is every Python tree actually type-checked?"."""
    problems: list[str] = []
    for tree in python_trees(root):
        if tree not in trees:
            problems.append(
                f"{tree}/pyproject.toml declares no [tool.mypy] — a Python tree nothing "
                f"type-checks (tree -> config). Copy the table from a sibling: the services "
                f"use python_version/strict=false/ignore_missing_imports, the packages use "
                f"strict=true. Then run --update to record what it surfaces"
            )
    for tree in sorted(set(recorded) | set(trees)):
        if not (root / tree / "pyproject.toml").is_file():
            problems.append(
                f"`{tree}` is configured or recorded but has no pyproject.toml on disk — "
                f"a config for a tree that no longer exists never fails on its own, which is "
                f"why it is checked here (config -> tree)"
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

    scanned = sum(_python_file_count(root, tree) for tree in trees)
    print(f"check_mypy_baseline: root {root}")
    # Name what was scanned. "OK" over a tree that was never opened is the
    # failure this gate exists to make impossible, and a count is the cheapest
    # way for a reader to notice it happened.
    print(f"  {len(trees)}/{len(all_trees)} Python tree(s) configured, {scanned} .py file(s) in scope")
    for tree in trees:
        found, error = run_mypy(root, tree)
        if error:
            problems.append(error)
            continue
        results[tree] = found
        total = sum(sum(c.values()) for c in found.values())
        print(f"  {tree}: {total} finding(s) across {len(found)} file(s)")

    if update:
        (root / BASELINE).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        total = sum(sum(sum(c.values()) for c in f.values()) for f in results.values())
        print(f"check_mypy_baseline: recorded {total} finding(s) across {len(results)} tree(s) in {BASELINE}")
        return 1 if problems else 0

    for tree in sorted(results):
        if tree not in recorded:
            problems.append(
                f"{tree} declares [tool.mypy] but has no baseline entry — a tree added "
                f"without being recorded is a tree nothing checks (config -> baseline)"
            )
            continue
        problems += compare(tree, results[tree], recorded[tree])
    for tree in sorted(set(recorded) - set(trees)):
        problems.append(
            f"{BASELINE} records `{tree}`, which no longer declares [tool.mypy] — "
            f"remove it rather than leaving a baseline for a tree nobody checks "
            f"(baseline -> config)"
        )

    total = sum(sum(sum(c.values()) for c in f.values()) for f in results.values())
    print(f"  {total} finding(s) total, {len(trees)} tree(s) checked: {', '.join(trees)}")

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
    if trees and recorded and set(trees) != set(recorded):
        failures.append(f"baseline covers {sorted(recorded)} but the tree declares {sorted(trees)}")
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
