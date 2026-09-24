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
import tomllib
from collections import defaultdict
from pathlib import Path

BASELINE = Path("scripts/mypy_baseline.json")

# `file:line: error: message  [code]`
_FINDING = re.compile(r"^(?P<file>[^:]+):\d+:(?:\d+:)?\s*error:\s*(?P<message>.*?)\s*(?:\[(?P<code>[\w-]+)\])?$")


def discover(root: Path) -> list[str]:
    """Every tree whose manifest declares a [tool.mypy] table.

    Structural: it asks the manifests what they configured, rather than
    matching a directory naming convention that a new service would not
    follow.
    """
    trees: list[str] = []
    for manifest in sorted(root.glob("services/*/pyproject.toml")) + sorted(root.glob("packages/*/pyproject.toml")):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        if "mypy" in data.get("tool", {}):
            trees.append(manifest.parent.relative_to(root).as_posix())
    return trees


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


def run(root: Path, update: bool = False) -> int:
    trees = discover(root)
    if not trees:
        print(f"check_mypy_baseline: no tree under {root} declares [tool.mypy]")
        return 1

    recorded = load(root)
    results: dict[str, dict[str, dict[str, int]]] = {}
    problems: list[str] = []

    print(f"check_mypy_baseline: root {root}")
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

    if failures:
        print("\ncheck_mypy_baseline --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_mypy_baseline --self-test: OK — {len(cases) + 1} cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--update", action="store_true", help="re-record the baseline from this run")
    parser.add_argument("--self-test", action="store_true", help="prove the comparison detects drift")
    args = parser.parse_args()

    root = (args.repo_root or Path(__file__).resolve().parent.parent).resolve()
    if not (root / "services").is_dir():
        print(f"{root} does not look like the AiSOC repository (no services/)")
        return 1
    return self_test(root) if args.self_test else run(root, update=args.update)


if __name__ == "__main__":
    sys.exit(main())
