#!/usr/bin/env python3
"""
List every Python service under ``services/`` that ships a ``tests/``
directory, and whether it is currently gated by a job in
``.github/workflows/ci.yml``.

This script is the audit tool behind Phase 2.1 of the
``aisoc_missing_pieces_plan``. Before that pass, seven services had
real test files that produced zero CI signal — every change to
``services/connectors`` (720 tests!) or ``services/actions`` could
silently break ``main``. The Phase 2.1 commit wires those seven into
the workflow; this script makes the audit reproducible so we catch
the next service that ships tests-without-a-gate.

Usage::

    # Show the audit table.
    python3 scripts/list_python_services_with_tests.py

    # Fail with a non-zero exit code if any tested service is NOT
    # already named in ``.github/workflows/ci.yml`` — wire this into
    # CI itself once the matrix has stabilised.
    python3 scripts/list_python_services_with_tests.py --check

The check is intentionally substring-based against the workflow file
rather than a YAML-aware traversal: every job that runs a service's
tests references the service name in either ``working-directory`` or
the matrix list, so the substring is a faithful proxy for "this
service is gated".
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVICES_DIR = REPO_ROOT / "services"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def discover_services_with_tests() -> list[tuple[str, int]]:
    """Return ``[(service_name, test_file_count), ...]`` sorted by name.

    A "service with tests" is any directory under ``services/`` whose
    ``tests/`` subdirectory contains at least one ``test_*.py`` or
    ``*_test.py`` file. Empty ``tests/`` directories don't count —
    they're scaffolding without signal.
    """
    out: list[tuple[str, int]] = []
    for svc_dir in sorted(SERVICES_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        tests_dir = svc_dir / "tests"
        if not tests_dir.is_dir():
            continue
        files = [
            *tests_dir.rglob("test_*.py"),
            *tests_dir.rglob("*_test.py"),
        ]
        if files:
            out.append((svc_dir.name, len(files)))
    return out


def is_gated(service: str, workflow_text: str) -> bool:
    """True if the workflow names the service in any job."""
    # Both ``working-directory: services/<svc>`` and matrix entries
    # like ``- <svc>`` are checked. The matrix-entry check would
    # over-match for short names (e.g. "api" inside "actions") if we
    # didn't bracket it with whitespace + dash, so we check exact
    # tokens.
    return f"services/{service}" in workflow_text or f"- {service}\n" in workflow_text or f"- {service} " in workflow_text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any service with tests is not gated in CI",
    )
    args = parser.parse_args()

    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    rows = discover_services_with_tests()

    print(f"{'service':<20} {'tests':>6}  CI gated?")
    print(f"{'-' * 20} {'-' * 6}  ---------")
    ungated: list[str] = []
    for name, count in rows:
        gated = is_gated(name, workflow_text)
        marker = "yes" if gated else "NO  <-- ungated"
        print(f"{name:<20} {count:>6}  {marker}")
        if not gated:
            ungated.append(name)

    if args.check and ungated:
        print(
            "\nFAIL: the following services ship tests but are not " "named in .github/workflows/ci.yml:\n  - " + "\n  - ".join(ungated),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
