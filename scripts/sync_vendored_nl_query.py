#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/nl_query`` in lockstep with its source.

The natural-language query translator lives under ``services/agents/app/nl_query``
and is consumed by both the agents runtime and the API's ``/nl-query/*``
endpoints. Because the ``aisoc-api`` Docker image is built with
``services/api`` as its build context, anything under ``services/agents`` is
not available at runtime. To keep the API container self-contained we ship a
vendored mirror of ``nl_query`` inside the API package.

Run modes
---------
* ``python scripts/sync_vendored_nl_query.py``           — copy source → vendored.
* ``python scripts/sync_vendored_nl_query.py --check``   — fail (exit 1) if the
  vendored tree is missing files or differs from the source. CI uses this mode.

The script is intentionally tiny and dependency-free so it can run in any CI
runner.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "services" / "agents" / "app" / "nl_query"
VENDORED_DIR = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "nl_query"

# Files we mirror. ``VENDORED.md`` lives only on the vendored side; everything
# else must match the source byte-for-byte.
SYNCED_FILES: tuple[str, ...] = ("__init__.py", "grammar.py", "translator.py")
VENDORED_ONLY: tuple[str, ...] = ("VENDORED.md",)


def _list_source_files() -> list[Path]:
    if not SOURCE_DIR.is_dir():
        raise SystemExit(f"Source tree missing: {SOURCE_DIR}")
    files = sorted(p for p in SOURCE_DIR.iterdir() if p.is_file() and p.suffix == ".py")
    return files


def _expected_filenames() -> set[str]:
    return {p.name for p in _list_source_files()}


def _check() -> int:
    expected = _expected_filenames()
    declared = set(SYNCED_FILES)
    if expected != declared:
        missing = expected - declared
        extra = declared - expected
        print(
            "FAIL: SYNCED_FILES is out of date with the source tree.\n"
            f"  Source files: {sorted(expected)}\n"
            f"  Declared:     {sorted(declared)}\n"
            f"  Missing from script: {sorted(missing)}\n"
            f"  No longer in source: {sorted(extra)}",
            file=sys.stderr,
        )
        return 1

    if not VENDORED_DIR.is_dir():
        print(f"FAIL: vendored directory missing: {VENDORED_DIR}", file=sys.stderr)
        return 1

    drift: list[str] = []
    for name in SYNCED_FILES:
        src = SOURCE_DIR / name
        dst = VENDORED_DIR / name
        if not dst.is_file():
            drift.append(f"  - missing in vendored tree: {name}")
            continue
        if not filecmp.cmp(src, dst, shallow=False):
            drift.append(f"  - out of date: {name}")

    # Make sure no stray extra .py files snuck into the vendored tree.
    vendored_pyfiles = {p.name for p in VENDORED_DIR.iterdir() if p.is_file() and p.suffix == ".py"}
    extra_py = vendored_pyfiles - set(SYNCED_FILES)
    for name in sorted(extra_py):
        drift.append(f"  - unexpected file in vendored tree: {name}")

    if drift:
        print(
            "FAIL: vendored nl_query is out of sync with source.\n"
            + "\n".join(drift)
            + "\n\nRe-run: python scripts/sync_vendored_nl_query.py",
            file=sys.stderr,
        )
        return 1

    print("OK: vendored nl_query matches source tree.")
    return 0


def _sync() -> int:
    expected = _expected_filenames()
    if expected != set(SYNCED_FILES):
        print(
            "WARNING: SYNCED_FILES is out of date with the source tree. "
            "Update the script's SYNCED_FILES tuple.\n"
            f"  Source: {sorted(expected)}\n"
            f"  Script: {sorted(SYNCED_FILES)}",
            file=sys.stderr,
        )
        return 1

    VENDORED_DIR.mkdir(parents=True, exist_ok=True)
    for name in SYNCED_FILES:
        src = SOURCE_DIR / name
        dst = VENDORED_DIR / name
        shutil.copy2(src, dst)
        print(f"copied {src.relative_to(REPO_ROOT)} → {dst.relative_to(REPO_ROOT)}")

    # Strip any stray .py files in the vendored tree that no longer exist in
    # the source (e.g. a renamed module). Leave VENDORED.md and __pycache__
    # untouched.
    for path in VENDORED_DIR.iterdir():
        if path.is_file() and path.suffix == ".py" and path.name not in SYNCED_FILES:
            print(f"removing stale {path.relative_to(REPO_ROOT)}")
            path.unlink()

    print("\nDone. Don't forget to commit the changes under "
          "services/api/app/_vendor/nl_query/.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail with a non-zero exit code if vendored nl_query is out of sync.",
    )
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
