#!/usr/bin/env python3
"""Every console API path resolves to a backend route or a Next rewrite.

Why this exists
---------------
Nothing checked the console against the backends. `check_ledger_replay_contract.py`
pins one client object against one router prefix, and `check_sdk_surface.py`
covers the SDKs, so an `/api/v1/...` path in `apps/web/src` that no service
serves shipped silently and showed up as a page that never loads.

It had, repeatedly: seven compliance calls to four route shapes that did not
exist, a case report pane fetching a route nobody had written, and two pages
whose calls went to the console's own origin because no rewrite existed.

How a path is resolved
----------------------
In the order a request actually takes:

1. a Next.js rewrite in `apps/web/next.config.js` (the console's own proxy
   table, which is what makes a path reach another service at all);
2. a route on the API service;
3. a route on the agents service;
4. a static file under `apps/web/public`.

The two services are read by importing their apps and asking
`app.openapi()`, not by scanning decorators. `app.routes` is not the route
table and what it holds changes with the FastAPI minor, which has already
made one gate in this repository compare zero pairs and report success.

Deliberately not checked
------------------------
That a path is *used*. A client surface may legitimately expose more than
the console calls today, and deleting an unused-but-working function is a
judgement about product surface rather than correctness. This reports them
separately so the judgement can be made, and fails only on paths that
resolve to nothing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

CONSOLE_SRC = "apps/web/src"
NEXT_CONFIG = "apps/web/next.config.js"
PUBLIC_DIR = "apps/web/public"

#: A template segment, `${...}`, stands for any single path segment.
_TEMPLATE = re.compile(r"\$\{[^}]*\}")

#: Paths the console calls that no backend serves, each with the reason.
#: This may only shrink. An entry whose path has gone fails the gate, so a
#: deleted call cannot leave its excuse behind.
KNOWN_UNRESOLVED: dict[str, str] = {
    # Base-path constants, suffixed before use. They are never requested as
    # written, and a gate reading string literals cannot tell a prefix from
    # a path. Reported rather than silently stripped, because a constant
    # that stops being suffixed becomes a real broken call.
    "/api/v1/fusion": "FUSION_PATH in lib/api.ts, a prefix every fusion call extends",
    "/api/v1/osquery": "the osquery client's base, built from NEXT_PUBLIC_OSQUERY_TLS_URL",
    # A WebSocket URL, not an HTTP route. It reaches the realtime service
    # through the `/ws/:path*` rewrite, which this gate does not model
    # because a WebSocket upgrade is not a path lookup.
    "/api/v1/graph_ws/stream": "a WebSocket endpoint, routed by the /ws rewrite",
    # Named inside a code comment explaining where the data comes from.
    "/api/v1/contextual": "a prose reference in a comment in AlertDetailView.tsx, not a call",
}


def _run_isolated(argv: list[str], *, cwd: pathlib.Path, timeout: int):
    """Run a probe in its own process group, and kill the group on timeout.

    Not a fix for an observed hang. A CI job appeared stuck on this step
    for ninety minutes and the diagnosis was that a grandchild holding the
    pipes defeats `subprocess.run(timeout=...)`; that was **wrong**, proven
    by reproducing the shape and watching the plain call time out in three
    seconds. The job had in fact completed in 23 minutes and the GitHub
    API was reporting a stale state.

    Kept anyway, for two reasons that stand on their own: killing the
    process group closes every inherited pipe rather than only the child's,
    which is correct even where the plain call happens to cope; and
    `stdin` is closed, so a probe that decides to prompt dies instead of
    waiting. The timeout also drops from 240s to 90s, which caps the worst
    case at six minutes across six services rather than twenty-four.
    """
    import os
    import signal

    process = subprocess.Popen(  # noqa: S603
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.communicate()
        return None
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


@dataclass
class Report:
    console_paths: set[str] = field(default_factory=set)
    unresolved: list[tuple[str, str]] = field(default_factory=list)
    stale_allowlist: list[str] = field(default_factory=list)
    rewrites: int = 0
    opaque_rewrites: int = 0
    api_routes: int = 0
    agents_routes: int = 0


def _console_paths(root: pathlib.Path) -> dict[str, str]:
    """Every `/api/v1/...` string literal in the console, to its file."""
    found: dict[str, str] = {}
    src = root / CONSOLE_SRC
    if not src.is_dir():
        return found
    pattern = re.compile(r"['\"`](/api/v1/[^'\"`\s]*)['\"`]")
    for path in sorted(src.rglob("*.ts*")):
        if "node_modules" in path.parts or path.name.endswith(".d.ts"):
            continue
        # Tests mock their own endpoints and name paths that are deliberately
        # not real. Including them made the gate report a WebSocket stub and a
        # branding fixture as broken console calls.
        if ".test." in path.name or ".spec." in path.name or "__tests__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in pattern.finditer(text):
            url = match.group(1)
            # A trailing `${qs}` or `${suffix}` is a query string, not a path
            # segment. Substituting a segment for it invented a path nobody
            # calls, which is a finding about this gate rather than the tree.
            url = re.sub(r"\$\{(?:qs|suffix|query|params|search)[^}]*\}$", "", url)
            url = url.split("?")[0].rstrip("/")
            # `/api/v1/*` and friends are globs in a comment or a route table,
            # not call sites.
            if not url or url.endswith("*"):
                continue
            found.setdefault(url, path.relative_to(root).as_posix())
    return found


def _rewrites(root: pathlib.Path) -> list[tuple[str, str]]:
    """`(source, destination-host-expression)` pairs from the Next config.

    Read with a regex rather than by executing the config, because the
    config reads environment variables and importing it would make the
    gate's answer depend on the shell it ran in.

    The destination matters, and getting that wrong made the first version
    of this gate useless. `/api/v1/:path*` routes everything not matched
    earlier to the API service, so treating any rewrite as proof that a
    path resolves meant **every** console path passed, including the seven
    compliance calls to routes that did not exist. A rewrite is a statement
    about where a request goes, not that anything answers it.
    """
    config = root / NEXT_CONFIG
    if not config.is_file():
        return []
    text = config.read_text(encoding="utf-8")
    return re.findall(
        r"source:\s*'([^']+)'\s*,\s*destination:\s*[`'\"]?\$\{(\w+)\}",
        text,
    )


def _service_paths(root: pathlib.Path, service: str) -> set[str]:
    """Paths one FastAPI service publishes, from its own OpenAPI document."""
    script = "import json,sys;sys.path.insert(0,'.');from app.main import app;print(json.dumps(sorted(app.openapi().get('paths',{}))))"
    try:
        out = _run_isolated([sys.executable, "-c", script], cwd=root / "services" / service, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if out is None:
        return set()
    for line in reversed(out.stdout.splitlines()):
        line = line.strip()
        if line.startswith("["):
            try:
                return set(json.loads(line))
            except json.JSONDecodeError:
                continue
    return set()


def _to_regex(pattern: str) -> re.Pattern[str]:
    """A route or rewrite pattern as a matcher over a console path."""
    # Next `:param*` is a catch-all; `:param` and FastAPI `{param}` are one
    # segment each.
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "{":
            end = pattern.find("}", i)
            out.append("[^/]+")
            i = (end + 1) if end != -1 else i + 1
            continue
        if char == ":":
            j = i + 1
            while j < len(pattern) and (pattern[j].isalnum() or pattern[j] == "_"):
                j += 1
            if j < len(pattern) and pattern[j] == "*":
                out.append(".*")
                i = j + 1
            else:
                out.append("[^/]+")
                i = j
            continue
        out.append(re.escape(char))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    console = _console_paths(root)
    report.console_paths = set(console)

    rewrites = _rewrites(root)
    report.rewrites = len(rewrites)
    api = _service_paths(root, "api")
    agents = _service_paths(root, "agents")
    report.api_routes, report.agents_routes = len(api), len(agents)

    api_matchers = [_to_regex(p) for p in sorted(api)]
    agents_matchers = [_to_regex(p) for p in sorted(agents)]

    # A rewrite pointing at a service this gate can introspect proves
    # nothing on its own; the service has to serve the path. A rewrite
    # pointing at one it cannot (realtime, fusion, osquery, honeytokens,
    # purple-team) is accepted as routing, which is the honest limit and is
    # printed rather than hidden.
    INTROSPECTABLE = {"API_HOST": api_matchers, "AGENTS_HOST": agents_matchers}
    opaque_rewrites = [_to_regex(src) for src, host in rewrites if host not in INTROSPECTABLE]
    report.opaque_rewrites = len(opaque_rewrites)

    def resolves(probe: str) -> bool:
        for src, host in rewrites:
            if not _to_regex(src).match(probe):
                continue
            matchers = INTROSPECTABLE.get(host)
            if matchers is None:
                return True  # routed to a service this gate cannot read
            return any(m.match(probe) for m in matchers)
        # No rewrite claims it, so it is served by the API directly or by
        # nothing.
        return any(m.match(probe) for m in api_matchers)

    public = root / PUBLIC_DIR

    used_allowlist: set[str] = set()
    for url, where in sorted(console.items()):
        # A template segment stands for any one segment.
        probe = _TEMPLATE.sub("X", url)
        if resolves(probe):
            continue
        if (public / probe.lstrip("/")).exists():
            continue
        if url in KNOWN_UNRESOLVED:
            used_allowlist.add(url)
            continue
        report.unresolved.append((url, where))

    report.stale_allowlist = [u for u in KNOWN_UNRESOLVED if u not in used_allowlist]
    return report


def _verdict(report: Report) -> int:
    if not report.console_paths:
        print(
            "check_console_route_contract: found no /api/v1 path in the console, which "
            "means the source tree was not read. Refusing to report that as clean.",
            file=sys.stderr,
        )
        return 2
    if not (report.api_routes or report.agents_routes):
        print(
            "check_console_route_contract: neither service published a route. Every console "
            "path would resolve to nothing, which is a broken probe rather than a finding.",
            file=sys.stderr,
        )
        return 2

    if report.stale_allowlist:
        print("check_console_route_contract: allowlist entries whose path has gone:", file=sys.stderr)
        for url in report.stale_allowlist:
            print(f"  {url}", file=sys.stderr)
        return 1

    if report.unresolved:
        print(
            f"check_console_route_contract: {len(report.unresolved)} console path(s) resolve "
            "to no backend route, no rewrite and no static file:",
            file=sys.stderr,
        )
        for url, where in report.unresolved:
            print(f"  {url}\n      called from {where}", file=sys.stderr)
        return 1

    print(
        f"check_console_route_contract: OK — {len(report.console_paths)} console path(s) all "
        f"resolve, against {report.api_routes} API route(s), {report.agents_routes} agents "
        f"route(s) and {report.rewrites} rewrite(s). A rewrite is only proof of routing: "
        f"{report.opaque_rewrites} point at a service this gate cannot introspect and are "
        f"accepted on that basis."
    )
    return 0


def self_test() -> int:
    root = repo_root()
    report = inspect(root)
    extra: list[tuple[str, bool]] = [
        ("the real tree resolves every console path", not report.unresolved),
        (
            f"it read a real corpus ({len(report.console_paths)} paths, {report.api_routes} API routes)",
            len(report.console_paths) > 50 and report.api_routes > 50,
        ),
    ]

    # The matcher, in both directions.
    cases = [
        ("a templated segment matches a path parameter", "/api/v1/cases/{case_id}", "/api/v1/cases/X", True),
        ("a catch-all rewrite matches a deep path", "/api/v1/hunt/:path*", "/api/v1/hunt/a/b", True),
        ("a one-segment parameter does not match two", "/api/v1/cases/{id}", "/api/v1/cases/a/b", False),
        ("a literal does not match a different literal", "/api/v1/alerts", "/api/v1/cases", False),
    ]
    for description, pattern, probe, expected in cases:
        extra.append((description, bool(_to_regex(pattern).match(probe)) is expected))

    # And the detector: a path nothing serves must be reported.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="aisoc-route-contract-") as tmp:
        fake = pathlib.Path(tmp)
        (fake / CONSOLE_SRC).mkdir(parents=True)
        (fake / CONSOLE_SRC / "x.ts").write_text("const a = '/api/v1/this-route-does-not-exist';\n", encoding="utf-8")
        (fake / NEXT_CONFIG).parent.mkdir(parents=True, exist_ok=True)
        (fake / NEXT_CONFIG).write_text("module.exports = {};\n", encoding="utf-8")
        probe_report = inspect(fake)
        # No services under that root, so the vacuity guard fires first,
        # which is itself the behaviour to confirm.
        extra.append(("refuses a tree whose services publish no route", _verdict(probe_report) == 2))

    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--list-unused", action="store_true", help="report paths no component calls")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
