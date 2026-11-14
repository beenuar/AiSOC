#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/ai_redaction.py`` in lockstep with its source.

The secret-shape classifier lives canonically in
``packages/aisoc-ai-sdk/aisoc_ai/redaction.py``, where it decides what the AI
SDK will transmit for a prompt. The AI-chat compliance collector
(``services/api/app/services/ai_chat_compliance/``) has to answer the same
question about a conversation it is deliberately not keeping, and the answer
must be the same answer: a prompt and a chat message that both contain an AWS
key should produce the same shape name on both surfaces.

Because the ``aisoc-core-api`` Docker image is built with ``services/api`` as
its build context, nothing under ``packages/`` is importable at runtime, so a
vendored mirror ships inside the API package. The alternative — a second copy
of the patterns written by hand — is how two surfaces come to disagree about
the same rows.

Run modes
---------
* ``python scripts/sync_vendored_ai_redaction.py``           — copy source → vendored.
* ``python scripts/sync_vendored_ai_redaction.py --check``   — fail (exit 1) if the
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

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
SOURCE_FILE = REPO_ROOT / "packages" / "aisoc-ai-sdk" / "aisoc_ai" / "redaction.py"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "ai_redaction.py"


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
            "Re-run: python scripts/sync_vendored_ai_redaction.py",
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
    print("\nDone. Don't forget to commit services/api/app/_vendor/ai_redaction.py.")
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
