#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/aisoc_benchmark/`` in lockstep with its source.

Gap-closure Phase 1.4.

The replay evaluation job is orchestrated by ``services/api``: that service
holds the vault and the tenant session, and it is already the one that proxies
to ``services/agents`` and ``services/actions``. Scoring is the one link in
that chain with no round trip, because ``packages/aisoc-benchmark`` is a
distribution rather than a service.

It still cannot be imported directly. The ``aisoc-core-api`` image is built
with ``services/api`` as its build context, so nothing under ``packages/`` is
present at runtime. Same constraint that already produced
``_vendor/narrative.py``, ``_vendor/llm_contract_rules.py`` and
``_vendor/nl_query/``, and the same answer: a mirror plus a gate.

The alternative was a second scorer inside the API, and the module being
mirrored opens by explaining why there is exactly one grader. A copy that
drifted would publish two definitions of "hallucination rate" while both
called themselves the same number.

Run modes
---------
* ``python scripts/sync_vendored_benchmark.py``         - copy source to vendored.
* ``python scripts/sync_vendored_benchmark.py --check`` - fail (exit 1) if the
  mirror is missing, stale, or has grown a file the source does not have. CI
  uses this mode.

Both directions are compared. A file present in the mirror and absent from the
source fails too, because the failure this repository keeps finding is the
one-directional check that prints OK while drift accumulates in the direction
things actually move.

Dependency-free so it runs on a bare interpreter.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

SOURCE_REL = Path("packages/aisoc-benchmark/aisoc_benchmark")
VENDORED_REL = Path("services/api/app/_vendor/aisoc_benchmark")

#: Files that live only in the mirror and have no source counterpart.
#: ``VENDORED.md`` documents the mirror; it is not part of the package.
MIRROR_ONLY = frozenset({"VENDORED.md"})


def _python_files(directory: Path) -> dict[str, Path]:
    return {p.name: p for p in sorted(directory.glob("*.py"))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    root = repo_root()
    source = root / SOURCE_REL
    vendored = root / VENDORED_REL

    if not source.is_dir():
        print(f"FAIL: source package missing at {SOURCE_REL}")
        return 2

    source_files = _python_files(source)
    if not source_files:
        # A gate that passes over an empty tree has verified nothing.
        print(f"FAIL: no Python modules found under {SOURCE_REL}; refusing to report a clean mirror")
        return 2

    if not args.check:
        vendored.mkdir(parents=True, exist_ok=True)
        for name, path in source_files.items():
            shutil.copy2(path, vendored / name)
        for stale in _python_files(vendored):
            if stale not in source_files:
                (vendored / stale).unlink()
        print(f"OK: mirrored {len(source_files)} modules into {VENDORED_REL}")
        return 0

    if not vendored.is_dir():
        print(f"FAIL: vendored mirror missing at {VENDORED_REL}. Run: python {Path(__file__).name}")
        return 1

    problems: list[str] = []
    vendored_files = _python_files(vendored)

    for name, path in source_files.items():
        mirror = vendored_files.get(name)
        if mirror is None:
            problems.append(f"missing in mirror: {name}")
            continue
        if not filecmp.cmp(path, mirror, shallow=False):
            problems.append(f"differs from source: {name}")

    for name in vendored_files:
        if name not in source_files and name not in MIRROR_ONLY:
            problems.append(f"present in mirror but not in source: {name}")

    if problems:
        print(f"FAIL: {VENDORED_REL} has drifted from {SOURCE_REL}")
        for problem in problems:
            print(f"  - {problem}")
        print(f"\nRun: python scripts/{Path(__file__).name}")
        return 1

    print(f"OK: {len(source_files)} modules mirrored byte-identically from {SOURCE_REL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
