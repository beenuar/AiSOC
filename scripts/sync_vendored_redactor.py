#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/redactor.py`` in lockstep with its source.

The reversible pseudonymizer lives canonically under
``services/agents/app/privacy/redactor.py``. The public-replay publish flow in
the API service (``services/api/app/services/replay_redaction.py``) reuses it to
strip customer PII before a ledger snapshot is served at ``/r/<slug>``. Because
the ``aisoc-api`` Docker image is built with ``services/api`` as its build
context, anything under ``services/agents`` is unavailable at runtime, so we
ship a vendored mirror inside the API package.

Run modes
---------
* ``python scripts/sync_vendored_redactor.py``           — copy source → vendored.
* ``python scripts/sync_vendored_redactor.py --check``   — fail (exit 1) if the
  vendored file is missing or differs from the source. CI uses this mode.

The script is intentionally tiny and dependency-free so it can run in any CI
runner.

AiSOC — open-source AI Security Operations Center (MIT License).
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
SOURCE_FILE = REPO_ROOT / "services" / "agents" / "app" / "privacy" / "redactor.py"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "redactor.py"


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if not filecmp.cmp(SOURCE_FILE, VENDORED_FILE, shallow=False):
        print(
            "FAIL: vendored redactor.py is out of sync with source.\n"
            f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
            f"  Vendored: {VENDORED_FILE.relative_to(REPO_ROOT)}\n\n"
            "Re-run: python scripts/sync_vendored_redactor.py",
            file=sys.stderr,
        )
        return 1
    print("OK: vendored redactor.py matches source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_FILE, VENDORED_FILE)
    print(f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} → {VENDORED_FILE.relative_to(REPO_ROOT)}")
    print("\nDone. Don't forget to commit services/api/app/_vendor/redactor.py.")
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
