#!/usr/bin/env python3
"""
Phase 2.5 — verify every `runbook_url` referenced from
``infra/docker/alerts/aisoc.rules.yml`` points at a file that
actually exists under ``docs/runbooks/``.

The alert rules embed runbook URLs like
``https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/
service-down.md`` so Alertmanager's notification template can
deep-link the on-call. If those files don't exist, the on-call
gets a 404 at the worst possible moment.

This script enforces the invariant: every URL pointing into the
repo's ``docs/runbooks/`` directory must resolve to a tracked file.
External URLs (vendor docs, RFC pages) are skipped.

Usage::

    python3 scripts/audit_runbook_links.py            # report mode
    python3 scripts/audit_runbook_links.py --check    # CI mode
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ALERTS = REPO_ROOT / "infra" / "docker" / "alerts" / "aisoc.rules.yml"
RUNBOOK_PATH_PREFIX = "docs/runbooks/"

RUNBOOK_LINK_RE = re.compile(r"runbook_url:\s*(\S+)")


def extract_runbook_paths() -> list[str]:
    """Return runbook relative paths referenced from alert rules.

    Accepts both repo-rooted paths (``docs/runbooks/foo.md``) and
    GitHub blob URLs (``https://github.com/.../docs/runbooks/foo.md``)
    — both should resolve to the same on-disk file.
    """
    text = ALERTS.read_text(encoding="utf-8")
    paths: list[str] = []
    for m in RUNBOOK_LINK_RE.finditer(text):
        raw = m.group(1).strip().rstrip(",")
        idx = raw.find(RUNBOOK_PATH_PREFIX)
        if idx == -1:
            continue
        paths.append(raw[idx:])
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any runbook URL points at a missing file",
    )
    args = parser.parse_args()

    paths = extract_runbook_paths()
    if not paths:
        print(
            f"WARN: no runbook URLs found in {ALERTS.relative_to(REPO_ROOT)} — " "did the alert rule schema change?",
            file=sys.stderr,
        )
        return 0 if not args.check else 1

    missing: list[str] = []
    print(f"Auditing {len(paths)} runbook URLs in " f"{ALERTS.relative_to(REPO_ROOT)}:")
    for rel in sorted(set(paths)):
        on_disk = REPO_ROOT / rel
        if on_disk.exists():
            print(f"  OK   {rel}")
        else:
            print(f"  MISS {rel}")
            missing.append(rel)

    if args.check and missing:
        print(
            "\nFAIL: alert rules reference runbooks that don't exist:\n  - "
            + "\n  - ".join(missing)
            + "\n\nEither create the runbook under docs/runbooks/ or remove "
            "the `runbook_url` from the alert.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
