#!/usr/bin/env python3
"""Keep the API's copy of the autonomy evidence rules byte-identical to the source.

Gap-closure Phase 2.3.

``services/actions/app/services/autonomy_evidence_rules.py`` decides what a
track record has to show before a tenant may act unattended. Two services need
that answer and neither can import the other: ``services/actions`` enforces it
at dispatch, ``services/api`` decides it at promotion time and owns the
hash-chained audit log the transition is written to. Both package their code
as top-level ``app``, and each Docker image is built with only its own service
directory as the build context, so the file has to exist twice.

A safety control that exists twice and is allowed to differ is a control that
is off in whichever copy is more generous, and nobody finds out until an
action executes that the other half would have refused. So the copy is
byte-compared rather than spot-checked, and ``--check`` runs in CI.

Run modes
---------
* ``python scripts/sync_vendored_autonomy_evidence.py``         copy source to vendored.
* ``python scripts/sync_vendored_autonomy_evidence.py --check`` fail when they differ.

Same shape and same reasoning as ``sync_vendored_llm_contract.py``; dependency
free so it runs on a bare interpreter before any install step.

AiSOC, open-source AI Security Operations Center (MIT License).
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

REPO_ROOT = repo_root()
SOURCE_FILE = REPO_ROOT / "services" / "actions" / "app" / "services" / "autonomy_evidence_rules.py"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "autonomy_evidence_rules.py"


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if not filecmp.cmp(SOURCE_FILE, VENDORED_FILE, shallow=False):
        print(
            "FAIL: vendored autonomy_evidence_rules.py is out of sync with source.\n"
            f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
            f"  Vendored: {VENDORED_FILE.relative_to(REPO_ROOT)}\n\n"
            "The promotion gate would then mean two different things: one answer at\n"
            "dispatch and another at promotion time.\n"
            "Re-run: python scripts/sync_vendored_autonomy_evidence.py",
            file=sys.stderr,
        )
        return 1
    print("OK: vendored autonomy_evidence_rules.py matches source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_FILE, VENDORED_FILE)
    print(f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} -> {VENDORED_FILE.relative_to(REPO_ROOT)}")
    print("\nDone. Commit services/api/app/_vendor/autonomy_evidence_rules.py.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync the vendored autonomy evidence rules.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the vendored copy matches the source; do not write.",
    )
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
