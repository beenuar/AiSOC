#!/usr/bin/env python3
"""Keep the GitHub Action's vendored verdict engine in lockstep with its source.

The deterministic verdict engine lives canonically in
``packages/aisoc-lite/src/verdict/`` (published as the `aisoc` CLI). The GitHub
Action (``packages/aisoc-action``) triages a repo's security signals with the
same engine, but a GitHub Action ships a single committed ``dist/index.js`` with
no npm install at run time — so it bundles a **vendored** copy of the pure
verdict modules rather than taking a workspace dependency on the CLI package
(whose bare name ``aisoc`` also makes cross-package workspace linking brittle).

These three modules are pure (no I/O, no Node built-ins), so copying is exact.

Run modes
---------
* ``python scripts/sync_vendored_verdict.py``           — copy source → vendored.
* ``python scripts/sync_vendored_verdict.py --check``   — fail (exit 1) if any
  vendored file is missing or differs from source. CI uses this mode.
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

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
SRC_DIR = REPO_ROOT / "packages" / "aisoc-lite" / "src" / "verdict"
DST_DIR = REPO_ROOT / "packages" / "aisoc-action" / "src" / "_vendor" / "verdict"
FILES = ("types.ts", "stages.ts", "engine.ts")


def _check() -> int:
    ok = True
    for name in FILES:
        src = SRC_DIR / name
        dst = DST_DIR / name
        if not src.is_file():
            print(f"FAIL: source missing: {src}", file=sys.stderr)
            ok = False
        elif not dst.is_file():
            print(f"FAIL: vendored missing: {dst}", file=sys.stderr)
            ok = False
        elif not filecmp.cmp(src, dst, shallow=False):
            print(f"FAIL: out of sync: {dst.relative_to(REPO_ROOT)} — run scripts/sync_vendored_verdict.py", file=sys.stderr)
            ok = False
    if ok:
        print("OK: vendored verdict engine matches source.")
        return 0
    return 1


def _sync() -> int:
    DST_DIR.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        src = SRC_DIR / name
        if not src.is_file():
            print(f"FAIL: source missing: {src}", file=sys.stderr)
            return 1
        shutil.copy2(src, DST_DIR / name)
        print(f"copied {src.relative_to(REPO_ROOT)} → {(DST_DIR / name).relative_to(REPO_ROOT)}")
    print("\nDone. Commit packages/aisoc-action/src/_vendor/verdict/*.ts")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the vendored copy is out of sync.")
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
