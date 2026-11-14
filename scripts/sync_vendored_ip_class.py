#!/usr/bin/env python3
"""Keep the vendored IP-class loader byte-identical to the canonical one.

`scripts/ip_class_dataset.py` is canonical. `services/fusion/app/services/
ip_class.py` is the vendored copy, because a service image ships only its own
`app/` subtree and cannot import a repository-root script at runtime.

Same arrangement, and for the same reason, as the thirteen other
`sync_vendored_*.py` scripts here: two copies that can drift silently are
worse than one copy plus a gate. This one is a pure file copy with no
rewriting, so the gate is a digest comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

CANONICAL = Path("scripts/ip_class_dataset.py")
VENDORED = Path("services/fusion/app/services/ip_class.py")

_BANNER = (
    "# VENDORED COPY. Canonical source: scripts/ip_class_dataset.py\n"
    "# Regenerate with: python3 scripts/sync_vendored_ip_class.py\n"
    "# Held byte-identical by scripts/sync_vendored_ip_class.py --check.\n"
)


def render(canonical_text: str) -> str:
    return _BANNER + canonical_text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when the copy is stale")
    args = parser.parse_args()

    root = repo_root()
    source = root / CANONICAL
    if not source.is_file():
        print(f"FAIL {CANONICAL} is missing; refusing to report a vendored copy of nothing as current")
        return 1
    canonical = source.read_text(encoding="utf-8")
    want = render(canonical)
    target = root / VENDORED

    if args.check:
        have = target.read_text(encoding="utf-8") if target.is_file() else ""
        if have != want:
            print(f"FAIL {VENDORED} is stale against {CANONICAL}")
            print(f"  canonical sha256 {hashlib.sha256(want.encode()).hexdigest()[:16]}")
            print(f"  vendored  sha256 {hashlib.sha256(have.encode()).hexdigest()[:16]}")
            print("  run: python3 scripts/sync_vendored_ip_class.py")
            return 1
        print(f"OK {VENDORED} matches {CANONICAL}")
        return 0

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(want, encoding="utf-8")
    print(f"OK wrote {VENDORED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
