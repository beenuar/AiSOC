#!/usr/bin/env python3
"""Keep every copy of ``app/security/tenant_scope.py`` in lockstep.

The tenant-scope resolver is the thing that decides which tenant a request may
read. It is vendored into each service that needs it rather than imported,
because every service is built with its own directory as the Docker build
context — the same reason ``service_auth.py`` and ``cors.py`` are vendored.

That makes drift the hazard. A fix to the verifier that lands in one copy and
not the others leaves the un-fixed services accepting what the fixed one
rejects, and the difference is invisible until somebody reads all six files
side by side. So the copies are byte-identical apart from one line:
``SERVICE_NAME``, which selects the per-service token override.

Run modes
---------
* ``python scripts/sync_vendored_tenant_scope.py``         — copy source → vendored.
* ``python scripts/sync_vendored_tenant_scope.py --check`` — fail (exit 1) if any
  copy is missing or differs. CI uses this mode.

The script is dependency-free so it runs in any CI runner.

AiSOC — open-source AI Security Operations Center (MIT License).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = REPO_ROOT / "services" / "fusion" / "app" / "security" / "tenant_scope.py"

#: The test travels with the module. Each service runs the copy it ships
#: rather than trusting that the one copy the cross-service isolation suite
#: exercises stands in for the other five — which is exactly the assumption
#: that lets a vendored fix land in one place and look like six.
SOURCE_TEST = REPO_ROOT / "services" / "fusion" / "tests" / "test_tenant_scope.py"

#: service directory name → the SERVICE_NAME literal its copy must carry.
#: The token override is ``AISOC_<SERVICE_NAME>_SERVICE_TOKEN``.
TARGETS: dict[str, str] = {
    "fusion": "FUSION",
    "agents": "AGENTS",
    "osquery-tls": "OSQUERY_TLS",
    "honeytokens": "HONEYTOKENS",
    "purple-team": "PURPLE_TEAM",
    "ueba": "UEBA",
}

_SERVICE_NAME_RE = re.compile(r'^SERVICE_NAME = ".*"$', re.MULTILINE)


def _target_path(service: str) -> Path:
    return REPO_ROOT / "services" / service / "app" / "security" / "tenant_scope.py"


def _target_test_path(service: str) -> Path:
    return REPO_ROOT / "services" / service / "tests" / "test_tenant_scope.py"


def _render(source: str, service_name: str) -> str:
    rendered, count = _SERVICE_NAME_RE.subn(f'SERVICE_NAME = "{service_name}"', source)
    if count != 1:
        raise SystemExit(f"expected exactly one SERVICE_NAME assignment in the source, found {count}")
    return rendered


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    source = SOURCE_FILE.read_text(encoding="utf-8")

    test_source = SOURCE_TEST.read_text(encoding="utf-8") if SOURCE_TEST.is_file() else None
    if test_source is None:
        print(f"FAIL: source test missing: {SOURCE_TEST}", file=sys.stderr)
        return 1

    failures = 0
    for service, service_name in sorted(TARGETS.items()):
        for path, want in (
            (_target_path(service), _render(source, service_name)),
            (_target_test_path(service), test_source),
        ):
            if not path.is_file():
                print(f"FAIL: vendored copy missing: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
                failures += 1
                continue
            if path.read_text(encoding="utf-8") != want:
                print(
                    f"FAIL: {path.relative_to(REPO_ROOT)} is out of sync with its source.\n"
                    "      Re-run: python scripts/sync_vendored_tenant_scope.py",
                    file=sys.stderr,
                )
                failures += 1

    if failures:
        return 1
    print(f"OK: {len(TARGETS)} vendored tenant_scope.py copies (+ their tests) match the source (differing only in SERVICE_NAME).")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    source = SOURCE_FILE.read_text(encoding="utf-8")

    test_source = SOURCE_TEST.read_text(encoding="utf-8")

    for service, service_name in sorted(TARGETS.items()):
        path = _target_path(service)
        path.parent.mkdir(parents=True, exist_ok=True)
        init = path.parent / "__init__.py"
        if not init.exists():
            init.write_text('"""Security helpers for this service."""\n', encoding="utf-8")
        path.write_text(_render(source, service_name), encoding="utf-8")
        print(f"  wrote {path.relative_to(REPO_ROOT)} (SERVICE_NAME={service_name})")

        test_path = _target_test_path(service)
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.write_text(test_source, encoding="utf-8")
        print(f"  wrote {test_path.relative_to(REPO_ROOT)}")
    print(f"OK: synced {len(TARGETS)} copies (+ tests) from {SOURCE_FILE.relative_to(REPO_ROOT)}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="verify the copies match instead of rewriting them")
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    sys.exit(main())
