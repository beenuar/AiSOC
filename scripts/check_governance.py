#!/usr/bin/env python3
"""Governance-completeness gate (Phase 12 — observability + governance).

Open-source trust rests on a small set of documents actually existing and being
non-trivial: governance model, maintainers, security policy, code of conduct,
trademark, and a DCO sign-off requirement. This gate fails if any is missing,
empty, or (for DCO) unreferenced — so the project's governance surface can't
silently rot.

Usage:
    python3 scripts/check_governance.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# file → (min non-whitespace chars, [required substrings])
_REQUIRED = {
    "GOVERNANCE.md": (600, ["maintainer", "Neutral home", "Decision-making"]),
    "MAINTAINERS.md": (150, ["Maintainers"]),
    "SECURITY.md": (300, []),
    "CODE_OF_CONDUCT.md": (300, []),
    "TRADEMARK.md": (150, []),
    "CONTRIBUTING.md": (600, ["Developer Certificate of Origin", "Signed-off-by"]),
    "docs/operations/slos.yaml": (300, ["availability_target"]),
    "docs/operations/observability.md": (500, ["golden signal", "trace"]),
}


def main() -> int:
    errors: list[str] = []
    for rel, (min_chars, substrings) in _REQUIRED.items():
        path = ROOT / rel
        if not path.exists():
            errors.append(f"missing required governance file: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        if len(text.strip()) < min_chars:
            errors.append(f"{rel} is too short ({len(text.strip())} < {min_chars} chars) — looks like a stub")
        low = text.lower()
        for sub in substrings:
            if sub.lower() not in low:
                errors.append(f"{rel} is missing required content: '{sub}'")

    if errors:
        print("ERROR: governance-completeness gate failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: all {len(_REQUIRED)} governance documents present and non-trivial")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
