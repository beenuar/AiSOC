#!/usr/bin/env python3
"""No two handlers register the same method and path in one app.

The blind spot this fills
------------------------
`check_route_shadowing.py` is a static AST pass, deliberately: one run reads
every service without needing any of them importable. Its own docstring
records what that costs, at line 27:

    Two modules included under one prefix can shadow each other and this
    will not see it.

That is not a theoretical gap. `services/agents` registered
`GET /api/v1/investigations/{run_id}` **twice**, from `app/api/router.py`
and `app/api/investigate.py`, each reading its own in-memory store. The one
included first answered every request, from the store the other module
writes, so console status polling returned 404 for runs that existed while
the sibling report routes under the same prefix worked.

The static pass could not see it for two reasons, both structural: it groups
by `(service, path, router)` and the two declared paths differ before
mounting (`/investigations/{run_id}` against `/api/v1/investigations/{run_id}`,
because one prefix comes from an app-level `include_router` the AST never
sees), and its `shadows()` only fires when a parameter segment faces a
literal one, so two identical paths compare equal and report nothing.

So this is the runtime half. It imports each app and reads the assembled
route table, which is the only place the prefixes are resolved.

Why it reads `app.router.routes` and counts what it found
---------------------------------------------------------
`app.openapi()` is the right corpus for asking *which paths exist*, and the
wrong one here: it keys paths in a dict, so a duplicate is silently
collapsed into one entry, which is exactly the thing being looked for.

Reading the router instead carries a known hazard. On FastAPI 0.141.x
`include_router` leaves an opaque object in `app.routes` and the `APIRoute`
count is zero, which has already made one gate in this repository compare
zero pairs and report success over an app serving 456 operations. So an app
that yields no routes is a failure here, not a pass.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Services with an importable FastAPI app.
SERVICES = ("api", "agents", "actions", "fusion", "connectors", "threatintel")

#: Duplicate pairs that are intentional, each with the reason. May only
#: shrink.
ALLOWED_DUPLICATES: dict[str, str] = {}

_COLLECT = """
import json, sys
sys.path.insert(0, '.')
from app.main import app
rows = []
for route in app.router.routes:
    path = getattr(route, 'path', None)
    methods = getattr(route, 'methods', None)
    if not path or not methods:
        continue
    name = getattr(route, 'name', '?')
    module = getattr(getattr(route, 'endpoint', None), '__module__', '?')
    for method in sorted(methods):
        rows.append([method, path, name, module])
print('@@ROUTES@@' + json.dumps(rows))
"""


@dataclass
class Report:
    scanned: dict[str, int] = field(default_factory=dict)
    duplicates: list[tuple[str, str, str, list[str]]] = field(default_factory=list)
    unimportable: list[str] = field(default_factory=list)
    empty: list[str] = field(default_factory=list)
    stale_allowlist: list[str] = field(default_factory=list)


def _routes(root: pathlib.Path, service: str) -> list[list[str]] | None:
    directory = root / "services" / service
    if not (directory / "app" / "main.py").is_file():
        return None
    try:
        out = subprocess.run(
            [sys.executable, "-c", _COLLECT],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=240,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.stdout.splitlines():
        if line.startswith("@@ROUTES@@"):
            try:
                return json.loads(line[len("@@ROUTES@@") :])
            except json.JSONDecodeError:
                return None
    return None


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    used_allowlist: set[str] = set()

    for service in SERVICES:
        rows = _routes(root, service)
        if rows is None:
            if (root / "services" / service / "app" / "main.py").is_file():
                report.unimportable.append(service)
            continue
        report.scanned[service] = len(rows)
        if not rows:
            # An app that assembled no route is a broken probe. This is the
            # FastAPI-minor hazard in the module docstring.
            report.empty.append(service)
            continue

        seen: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
        for method, path, name, module in rows:
            seen[(method, path)].append(f"{module}.{name}")
        for (method, path), owners in sorted(seen.items()):
            if len(owners) < 2:
                continue
            key = f"{service} {method} {path}"
            if key in ALLOWED_DUPLICATES:
                used_allowlist.add(key)
                continue
            report.duplicates.append((service, method, path, owners))

    report.stale_allowlist = [k for k in ALLOWED_DUPLICATES if k not in used_allowlist]
    return report


def _verdict(report: Report) -> int:
    if not report.scanned:
        print(
            "check_route_duplicates: no service produced a route table, so nothing was compared. That is a broken probe, not a clean tree.",
            file=sys.stderr,
        )
        return 2

    failed = False
    if report.empty:
        print(
            "check_route_duplicates: these apps imported and yielded zero routes, which on "
            f"FastAPI 0.141.x is what an opaque `_IncludedRouter` looks like: {report.empty}",
            file=sys.stderr,
        )
        failed = True

    if report.stale_allowlist:
        print("check_route_duplicates: allowlisted pairs that are no longer duplicated:", file=sys.stderr)
        for key in report.stale_allowlist:
            print(f"  {key}", file=sys.stderr)
        failed = True

    if report.duplicates:
        print(
            f"check_route_duplicates: {len(report.duplicates)} method and path pair(s) are "
            "registered twice. The one included first answers every request, and the other "
            "handler's state is unreachable:",
            file=sys.stderr,
        )
        for service, method, path, owners in report.duplicates:
            print(f"  {service}: {method} {path}", file=sys.stderr)
            for owner in owners:
                print(f"      {owner}", file=sys.stderr)
        failed = True

    if failed:
        return 1

    total = sum(report.scanned.values())
    summary = ", ".join(f"{s} {n}" for s, n in sorted(report.scanned.items()))
    # Named, not counted. "2 services not importable" tells a reader
    # nothing about whether the one they care about was checked.
    note = f". NOT CHECKED (could not import): {', '.join(sorted(report.unimportable))}" if report.unimportable else ""
    print(
        f"check_route_duplicates: OK — {total} route registration(s) across "
        f"{len(report.scanned)} service(s) ({summary}), no pair registered twice{note}."
    )
    return 0


def self_test() -> int:
    root = repo_root()
    report = inspect(root)
    extra: list[tuple[str, bool]] = [
        ("the real tree has no duplicate pair", not report.duplicates),
        (
            f"it read a real corpus ({sum(report.scanned.values())} registrations across {len(report.scanned)} services)",
            sum(report.scanned.values()) > 200 and len(report.scanned) >= 2,
        ),
        ("no app yielded zero routes, which would be the FastAPI-minor trap", not report.empty),
    ]

    # The detector itself: inject a duplicate into a synthetic table.
    rows = [["GET", "/a", "one", "mod_a"], ["GET", "/a", "two", "mod_b"], ["GET", "/b", "three", "mod_c"]]
    seen: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for method, path, name, module in rows:
        seen[(method, path)].append(f"{module}.{name}")
    dupes = [k for k, v in seen.items() if len(v) > 1]
    extra.append(("two handlers on one method and path are reported", dupes == [("GET", "/a")]))
    extra.append(("a single handler is not", ("GET", "/b") not in dupes))

    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
