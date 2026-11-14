#!/usr/bin/env python3
"""Keep the API's copy of the action contracts byte-identical to the source.

``services/actions`` decides whether a response verb may run without a human:
``contract.py`` defines the vocabulary, ``capability_contracts.py`` declares
what each verb does to an estate, and ``approval_rules.py`` grades the two
against the tenant's autonomy tier.

``services/api`` serves the console's autonomy page, which has to tell an
operator whether a verb would actually auto-execute. It cannot import the
actions service: both package their code as top-level ``app`` and each image
is built with only its own service directory as context. So the three modules
exist twice.

They are byte-compared rather than spot-checked because this exact file is a
worked example of why. The console used to answer the question with a rule of
its own — a per-action confidence threshold read from a table no dispatch path
consults — and concluded that seven high-blast verbs ran unattended on a
deployment whose dispatcher queues every one of them for a human. A safety
claim that two services compute differently is wrong in whichever one is more
generous, and a settings page is the more dangerous place to be wrong: nothing
executes, so nothing contradicts it.

Run modes
---------
* ``python scripts/sync_vendored_action_contracts.py``         copy source to vendored.
* ``python scripts/sync_vendored_action_contracts.py --check`` fail when they differ.

Same shape and same reasoning as ``sync_vendored_autonomy_evidence.py`` and
``sync_vendored_nl_query.py``; dependency free so it runs on a bare
interpreter before any install step.

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
SOURCE_DIR = REPO_ROOT / "services" / "actions" / "app" / "live_actions"
VENDORED_DIR = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "action_contracts"

#: The three modules the grading needs, and nothing else from that package.
#: ``live_actions/`` also holds the dispatcher, the registry and every vendor
#: adapter; those reach httpx, the credential vault and the tenant database,
#: none of which belong in the API's copy. The three below import only each
#: other and the standard library, which is what makes the mirror possible.
SYNCED_FILES: tuple[str, ...] = ("contract.py", "capability_contracts.py", "approval_rules.py")

#: Present only on the vendored side. ``__init__.py`` is the package marker —
#: the source copies live in a package whose own ``__init__`` imports the
#: dispatcher, so it cannot be mirrored.
VENDORED_ONLY: tuple[str, ...] = ("__init__.py", "VENDORED.md")


def _drift() -> list[str]:
    problems: list[str] = []

    if not SOURCE_DIR.is_dir():
        return [f"  - source directory missing: {SOURCE_DIR}"]
    if not VENDORED_DIR.is_dir():
        return [f"  - vendored directory missing: {VENDORED_DIR}"]

    for name in SYNCED_FILES:
        src = SOURCE_DIR / name
        dst = VENDORED_DIR / name
        if not src.is_file():
            problems.append(f"  - missing in source tree: {name}")
            continue
        if not dst.is_file():
            problems.append(f"  - missing in vendored tree: {name}")
            continue
        if not filecmp.cmp(src, dst, shallow=False):
            problems.append(f"  - out of date: {name}")

    for name in VENDORED_ONLY:
        if not (VENDORED_DIR / name).is_file():
            problems.append(f"  - missing vendored-only file: {name}")

    # A stray module in the vendored tree is the drift that runs the other
    # way: something copied in once and then diverged with nothing comparing
    # it. Named rather than ignored.
    declared = set(SYNCED_FILES) | set(VENDORED_ONLY)
    for path in sorted(VENDORED_DIR.iterdir()):
        if path.is_file() and path.suffix == ".py" and path.name not in declared:
            problems.append(f"  - unexpected file in vendored tree: {path.name}")

    return problems


def _check() -> int:
    problems = _drift()
    if problems:
        print(
            "FAIL: the vendored action contracts are out of sync with the source.\n"
            + "\n".join(problems)
            + "\n\nThe console would then answer 'would this verb auto-execute' with a\n"
            "different rule than the dispatcher applies, which is the defect this\n"
            "mirror exists to prevent.\n"
            "Re-run: python scripts/sync_vendored_action_contracts.py",
            file=sys.stderr,
        )
        return 1
    print(f"OK: vendored action contracts match source ({len(SYNCED_FILES)} modules).")
    return 0


def _sync() -> int:
    if not SOURCE_DIR.is_dir():
        print(f"FAIL: source directory missing: {SOURCE_DIR}", file=sys.stderr)
        return 1

    VENDORED_DIR.mkdir(parents=True, exist_ok=True)
    for name in SYNCED_FILES:
        src = SOURCE_DIR / name
        if not src.is_file():
            print(f"FAIL: source file missing: {src}", file=sys.stderr)
            return 1
        dst = VENDORED_DIR / name
        shutil.copy2(src, dst)
        print(f"copied {src.relative_to(REPO_ROOT)} -> {dst.relative_to(REPO_ROOT)}")

    print(f"\nDone. Commit the changes under {VENDORED_DIR.relative_to(REPO_ROOT)}/.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync the vendored action contracts.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the vendored copies match the source; do not write.",
    )
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
