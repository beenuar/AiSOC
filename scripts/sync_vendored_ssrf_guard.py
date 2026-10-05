"""Keep `services/api/app/_vendor/ssrf_guard.py` byte-identical to the agents copy.

Why the API needs this one and not `destinations.py::_guard_url`
----------------------------------------------------------------
`POST /api/v1/llm/credentials/test` makes an outbound call to a base URL the
tenant supplied, so it needs an SSRF guard. The API already has one, and it is
the wrong shape for this: `_guard_url` in `app/services/destinations.py`
rejects every private and loopback address outright, which is correct for a
webhook and would refuse the `local-ollama`, `local-vllm` and `local-litellm`
providers that `migrations/038_tenant_llm_credentials.sql`'s own CHECK allows.
Those are the configurations this endpoint exists to serve.

`validate_outbound_url(url, allow_private=True)` is the shape that fits: it
permits a private host while still rejecting loopback and link-local, so the
cloud-metadata endpoint stays blocked even when private addresses are allowed.

Run modes
---------
* ``python scripts/sync_vendored_ssrf_guard.py``           — copy source → vendored.
* ``python scripts/sync_vendored_ssrf_guard.py --check``   — fail (exit 1) if the
  vendored file is missing or differs from the source. CI uses this mode.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
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
SOURCE_FILE = REPO_ROOT / "services" / "agents" / "app" / "playbook" / "ssrf_guard.py"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "ssrf_guard.py"


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if not filecmp.cmp(SOURCE_FILE, VENDORED_FILE, shallow=False):
        print(
            "FAIL: vendored ssrf_guard.py is out of sync with source.\n"
            f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
            f"  Vendored: {VENDORED_FILE.relative_to(REPO_ROOT)}\n\n"
            "Re-run: python scripts/sync_vendored_ssrf_guard.py",
            file=sys.stderr,
        )
        return 1
    print("OK: vendored ssrf_guard.py matches source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_FILE, VENDORED_FILE)
    print(f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} → {VENDORED_FILE.relative_to(REPO_ROOT)}")
    print("\nDone. Don't forget to commit services/api/app/_vendor/ssrf_guard.py.")
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
