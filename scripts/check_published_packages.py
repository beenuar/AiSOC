#!/usr/bin/env python3
"""The README's publishing claim must match what the registries actually hold.

The packaging milestone has now moved three times — v8.0 to v8.1 to v8.2 —
for the same reason each time: the blocker is registry credentials, not code,
so it cannot be scheduled by writing a version number. v9.0 stops moving the
number and states a fact instead: the pipeline builds and packs every
package on each tag, and the upload is blocked on an account action.

A fact can go stale in a way a promise cannot. The moment somebody adds an
`NPM_TOKEN`, "ready, unpublished" becomes false, and the README would keep
saying it — the same failure as a promise that never lands, just pointing the
other way.

So this checks the claim against the registries. Offline it skips rather than
fails, because a contributor on a plane must not be told the README is wrong
when the truth is that the network is absent. It is a scheduled check, not a
per-PR blocker, for the same reason.

Usage:
    python3 scripts/check_published_packages.py
    python3 scripts/check_published_packages.py --require-network
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
README = ROOT / "README.md"

#: The phrase the README uses while nothing is published.
UNPUBLISHED_CLAIM = "Ready, unpublished"

#: (registry, name) for every package `release.yml` would upload.
PACKAGES: tuple[tuple[str, str], ...] = (
    ("npm", "aisoc"),
    ("npm", "@aisoc/sdk"),
    ("npm", "@aisoc/mcp"),
    ("pypi", "aisoc-sandbox"),
    ("pypi", "aisoc-cli"),
    ("pypi", "aisoc-sdk"),
    ("pypi", "aisoc-plugin-sdk"),
    ("pypi", "aisoc-detections"),
)

_TIMEOUT = 10


class Offline(RuntimeError):
    """The registry could not be reached, which is not the same as absent."""


def _is_published(registry: str, name: str) -> bool:
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}" if registry == "npm" else f"https://pypi.org/pypi/{name}/json"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:  # noqa: S310 — fixed https hosts
            json.load(response)
        return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise Offline(f"{registry}:{name} returned {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise Offline(f"{registry}:{name} unreachable: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-network",
        action="store_true",
        help="fail instead of skipping when a registry cannot be reached",
    )
    args = parser.parse_args()

    readme = README.read_text(encoding="utf-8")
    claims_unpublished = UNPUBLISHED_CLAIM.lower() in readme.lower()

    published: list[str] = []
    for registry, name in PACKAGES:
        try:
            if _is_published(registry, name):
                published.append(f"{registry}:{name}")
        except Offline as exc:
            if args.require_network:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
            print(f"SKIP: {exc}")
            return 0

    if published and claims_unpublished:
        print("PUBLISHED-PACKAGES GATE FAILED:", file=sys.stderr)
        print(
            f"  - README still says {UNPUBLISHED_CLAIM!r}, but these are live: {', '.join(published)}.",
            file=sys.stderr,
        )
        print(
            "    Update the maturity table: the claim was true and is not any more.",
            file=sys.stderr,
        )
        return 1

    if not published and not claims_unpublished:
        print("PUBLISHED-PACKAGES GATE FAILED:", file=sys.stderr)
        print(
            f"  - Nothing is on npm or PyPI, and the README no longer says {UNPUBLISHED_CLAIM!r}. A reader following it will hit a 404.",
            file=sys.stderr,
        )
        return 1

    state = f"{len(published)}/{len(PACKAGES)} published" if published else "none published"
    print(f"OK: README matches registry state ({state}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
