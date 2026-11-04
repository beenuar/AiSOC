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
#: Every vendored copy, kept byte-identical to the agents source. The
#: connectors copy exists because that service opens outbound HTTP to
#: tenant-controlled base URLs on every connector (GHSA-cq4g-g6wp-4m2w) and a
#: guard that drifts from the one the playbook engine enforces is two SSRF
#: policies wearing one name.
VENDORED_FILES = (
    REPO_ROOT / "services" / "api" / "app" / "_vendor" / "ssrf_guard.py",
    REPO_ROOT / "services" / "connectors" / "app" / "security" / "ssrf_guard.py",
    # The actions copy exists because `live_actions.dispatch()` opens outbound
    # HTTP to addresses that, for the vendors with no entry in
    # VENDOR_CREDENTIAL_MAP, come from the caller's own `params` rather than
    # from a stored connector row the API guarded at write time
    # (GHSA-78jg-x2ch-638f). A guard that drifts from the one the playbook
    # engine enforces is two SSRF policies wearing one name.
    REPO_ROOT / "services" / "actions" / "app" / "security" / "ssrf_guard.py",
)


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    failed = False
    for vendored in VENDORED_FILES:
        if not vendored.is_file():
            print(f"FAIL: vendored file missing: {vendored}", file=sys.stderr)
            failed = True
            continue
        if not filecmp.cmp(SOURCE_FILE, vendored, shallow=False):
            print(
                "FAIL: vendored ssrf_guard.py is out of sync with source.\n"
                f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
                f"  Vendored: {vendored.relative_to(REPO_ROOT)}\n\n"
                "Re-run: python scripts/sync_vendored_ssrf_guard.py",
                file=sys.stderr,
            )
            failed = True
    if failed:
        return 1
    print(f"OK: {len(VENDORED_FILES)} vendored ssrf_guard.py copies match source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    for vendored in VENDORED_FILES:
        vendored.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE_FILE, vendored)
        print(f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} → {vendored.relative_to(REPO_ROOT)}")
    print("\nDone. Don't forget to commit the vendored copies.")
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
