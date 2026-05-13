#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/narrative.py`` in lockstep with its source.

The correlation-narrative builder lives canonically under
``services/fusion/app/services/narrative.py`` and is consumed by both the
fusion service (at fusion time, to populate ``FusedAlert.narrative``) and the
API service (lazily, when a row's ``narrative`` column is ``NULL``). Because
the ``aisoc-api`` Docker image is built with ``services/api`` as its build
context, anything under ``services/fusion`` is not available at runtime. To
keep the API container self-contained we ship a vendored mirror of
``narrative.py`` inside the API package.

Run modes
---------
* ``python scripts/sync_vendored_narrative.py``           — copy source → vendored.
* ``python scripts/sync_vendored_narrative.py --check``   — fail (exit 1) if the
  vendored file is missing or differs from the source. CI uses this mode.

The script is intentionally tiny and dependency-free so it can run in any CI
runner.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = REPO_ROOT / "services" / "fusion" / "app" / "services" / "narrative.py"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "narrative.py"


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if not filecmp.cmp(SOURCE_FILE, VENDORED_FILE, shallow=False):
        print(
            "FAIL: vendored narrative.py is out of sync with source.\n"
            f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
            f"  Vendored: {VENDORED_FILE.relative_to(REPO_ROOT)}\n\n"
            "Re-run: python scripts/sync_vendored_narrative.py",
            file=sys.stderr,
        )
        return 1
    print("OK: vendored narrative.py matches source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_FILE, VENDORED_FILE)
    print(
        f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} → "
        f"{VENDORED_FILE.relative_to(REPO_ROOT)}"
    )
    print("\nDone. Don't forget to commit services/api/app/_vendor/narrative.py.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail with a non-zero exit code if the vendored file is out of sync.",
    )
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
