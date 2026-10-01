#!/usr/bin/env python3
"""No route module keeps state in a module global, or serves invented data.

Why this exists
---------------
`check_mock_data_gated.py` scans `apps/web/src` and nothing else, so the same
two defects on the Python side had no gate at all:

**Shared mutable state.** A `dict` or `list` at module scope that a handler
writes to is one object for the whole process, shared by every tenant and
lost on restart. `copilot.py` kept conversations in `_CONVERSATIONS` and
listed them with no principal and no tenant filter, so one tenant could read,
append to and delete another's; `hunt_search.py` had the same shape for saved
searches. Neither is a caching bug. A module global has no tenant, so a
handler that writes to one has already lost the ability to scope the read.

**Fabricated data outside demo mode.** `shifts.py` served three invented
shifts with named analysts and a fake ticket id from a module-level list, and
`stix_taxii.py` served invented indicators, bundles and collections. Both were
reachable with demo mode off.

Why a sibling rather than an extension
--------------------------------------
The brief asked for `check_mock_data_gated.py` to be extended. That file is
1,181 lines of rules written against TypeScript syntax — SWR `fallbackData`,
nullish fallbacks reaching a mock, demo factories, catch-block literals.
Python has none of those shapes and has one the console does not: a mutable
module global. Extending would have meant a second rule engine inside a file
whose every existing rule stayed inapplicable. Recorded as a deviation.

This gate parses with `ast` rather than matching text, because the question
is "does a function body assign to a name bound at module scope", and that is
a scope question a regex cannot answer.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys
import tempfile
from dataclasses import dataclass, field

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Where route modules live, per service.
ROUTE_DIRS = ("app/api", "app/routers", "app/routes")

#: Mutable types that hold state. A module-level `frozenset` or tuple is a
#: constant and is fine; these are not.
MUTABLE_TYPES = (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)

#: Calls that produce a mutable container.
MUTABLE_CALLS = frozenset({"dict", "list", "set", "defaultdict", "OrderedDict", "deque", "Counter"})

#: Methods that mutate. A handler calling one of these on a module global is
#: writing process-wide state.
MUTATING_METHODS = frozenset({"append", "extend", "insert", "pop", "remove", "clear", "update", "setdefault", "add", "popitem", "sort"})

#: Names that signal fabricated data rather than configuration.
SAMPLE_PREFIXES = ("MOCK_", "DEMO_", "SAMPLE_", "FAKE_", "FIXTURE_", "_MOCK_", "_DEMO_", "_SAMPLE_")

#: What a demo gate looks like in this tree.
DEMO_GUARDS = ("is_demo", "demo_mode", "DEMO_MODE", "canUseDemoData", "allow_seed", "AISOC_DEMO")


#: Module-level containers that are allowed, each with a reason. This may only
#: shrink: `--check` reports an entry whose name has gone, so a fixed module
#: cannot leave its excuse behind.
ALLOWED_GLOBALS: dict[tuple[str, str], str] = {
    # ── Not tenant state: a log de-duplicator ──────────────────────────────
    (
        "services/api/app/api/v1/dev_auth.py",
        "_REFUSALS_LOGGED",
    ): (
        "Holds the set of refusal reasons already logged, so a hot path emits one line per "
        "reason rather than one per request. It carries no tenant data and losing it on restart "
        "re-emits a log line, which is the correct behaviour for a new process."
    ),
    # ── Caches of a static artefact ────────────────────────────────────────
    (
        "services/api/app/api/v1/endpoints/marketplace.py",
        "_installed",
    ): (
        "Marketplace installs are in-process and lost on restart, which the feature- "
        "completeness audit records as a known gap. Parity plan 5.4 makes install write rows "
        "that fusion reads, which is where this gets a table."
    ),
    (
        "services/api/app/api/v1/endpoints/marketplace.py",
        "_index_cache",
    ): (
        "Caches the parsed marketplace index, which is a file shipped in the image and "
        "identical for every tenant. Not state: a cold replica re-reads the same bytes."
    ),
    (
        "services/actions/app/api/router.py",
        "_chatops_replied",
    ): (
        "Idempotency set for ChatOps replies, so a retried callback does not post twice. Per- "
        "replica, which means a retry that lands on another replica can double-post; that is a "
        "known weakness of the in-process form and belongs with the durable approval pause "
        "(parity plan 5.2)."
    ),
    # ── Real instances of the class, each named with where it closes ───────
    (
        "services/agents/app/api/router.py",
        "_runs",
    ): (
        "One half of the duplicate `GET /api/v1/investigations/{run_id}` registration: two "
        "handlers, two separate in-process stores, and the one registered first answers. Parity "
        "plan 1.3 splits the paths, and this entry goes with the dict that loses."
    ),
    (
        "services/agents/app/api/investigate.py",
        "_runs",
    ): "The other half of the same duplicate pair.",
    (
        "services/agents/app/api/playbooks.py",
        "_runs",
    ): (
        "Playbook run state. Parity plan 5.2 makes an approval a durable pause that survives a "
        "restart, which is the same change that gives this a table."
    ),
    (
        "services/agents/app/api/triage.py",
        "_triage_runs",
    ): (
        "Triage run state, surfaced by the console's polling. The Redis-backed store exists for "
        "investigations and this is the one that did not move with it."
    ),
    (
        "services/api/app/api/v1/endpoints/business_context.py",
        "_rule_store",
    ): (
        "Business-context rules. They persist in Postgres and the agents triage worker reads a "
        "YAML file instead, which is a known gap in the feature-completeness audit; this in- "
        "memory copy is the third store and goes when the two are reconciled."
    ),
    (
        "services/api/app/api/v1/endpoints/community.py",
        "_community_plugins",
    ): (
        "Community content is in-memory and lost on restart, recorded as a known gap. Not "
        "cross-tenant by design: community content is global."
    ),
    (
        "services/api/app/api/v1/endpoints/community.py",
        "_community_detections",
    ): "Same module, same gap.",
    (
        "services/api/app/api/v1/endpoints/community.py",
        "_community_playbooks",
    ): "Same module, same gap.",
    (
        "services/api/app/api/v1/endpoints/detection_loop.py",
        "_SUGGESTIONS",
    ): (
        "Drafted detection suggestions awaiting review. Parity plan 6.2 makes a draft a "
        "governed DRAFT proposal with a row, which is where this gets a table."
    ),
}


@dataclass(frozen=True)
class Finding:
    rel_path: str
    line: int
    name: str
    kind: str
    detail: str

    def render(self) -> str:
        return f"{self.rel_path}:{self.line}  [{self.kind}] {self.name}\n      {self.detail}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    globals_examined: int = 0
    stale_allowlist: list[str] = field(default_factory=list)


def _route_modules(root: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    services = root / "services"
    if not services.is_dir():
        return found
    for service in sorted(p for p in services.iterdir() if p.is_dir()):
        for rel in ROUTE_DIRS:
            directory = service / rel
            if not directory.is_dir():
                continue
            found.extend(p for p in sorted(directory.rglob("*.py")) if p.name != "__init__.py" and "test" not in p.name)
    return found


def _is_mutable_value(node: ast.AST) -> bool:
    if isinstance(node, MUTABLE_TYPES):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)
        return name in MUTABLE_CALLS
    return False


def _module_level_mutables(tree: ast.Module) -> dict[str, tuple[int, ast.AST]]:
    """Every name bound at module scope to a mutable container."""
    found: dict[str, tuple[int, ast.AST]] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None or not _is_mutable_value(value):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                found[target.id] = (node.lineno, value)
    return found


def _handler_writes(tree: ast.Module, names: set[str]) -> dict[str, int]:
    """Which of `names` a function body mutates, and where.

    Both shapes count: rebinding under a `global` statement, and calling a
    mutating method on the object. `_CONVERSATIONS[key] = value` is the one
    that actually occurred, and it is neither of those two in isolation — it
    is a subscript store, so that is checked as well.
    """
    writes: dict[str, int] = {}
    for function in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in MUTATING_METHODS:
                    # `_SEEN.append(...)` and `_SEEN[key].append(...)` both
                    # mutate the module global. The second reaches it through
                    # a subscript load, which a check for `Attribute` over
                    # `Name` alone does not see — and a `defaultdict(list)`
                    # keyed per tenant is exactly that shape.
                    base = func.value
                    while isinstance(base, (ast.Subscript, ast.Attribute)):
                        base = base.value
                    if isinstance(base, ast.Name) and base.id in names:
                        writes.setdefault(base.id, node.lineno)
            elif isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        if target.value.id in names:
                            writes.setdefault(target.value.id, node.lineno)
                    elif isinstance(target, ast.Name) and target.id in names:
                        writes.setdefault(target.id, node.lineno)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        if target.value.id in names:
                            writes.setdefault(target.value.id, node.lineno)
    return writes


def _looks_fabricated(value: ast.AST) -> bool:
    """A container of record-shaped literals.

    Used only to *describe* a finding the name already identified, never to
    raise one on its own. Shape alone was tried and rejected: it fired on
    `compliance.FRAMEWORKS` (the real 24-control mapping), on
    `inbox._TEMPLATE_CATALOG`, on `translation._FIELD_MAP` and on
    `explain._OCSF_BY_SOURCE` — four configuration tables that are dicts of
    dicts with several populated string fields, which is exactly what a
    record set looks like structurally. Four false positives out of four
    detections is not a heuristic, so the name is the signal and this is the
    detail.
    """
    elements: list[ast.AST] = []
    if isinstance(value, ast.List):
        elements = list(value.elts)
    elif isinstance(value, ast.Dict):
        elements = [v for v in value.values if v is not None]
    for element in elements:
        if isinstance(element, ast.Dict) and len(element.keys) >= 3:
            literals = sum(1 for v in element.values if isinstance(v, ast.Constant) and v.value not in (None, "", 0, False))
            if literals >= 3:
                return True
    return False


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    used_allowlist: set[tuple[str, str]] = set()

    for path in _route_modules(root):
        rel = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        report.files_scanned += 1

        mutables = _module_level_mutables(tree)
        if not mutables:
            continue
        report.globals_examined += len(mutables)

        writes = _handler_writes(tree, set(mutables))
        guarded = any(guard in source for guard in DEMO_GUARDS)

        for name, (line, value) in sorted(mutables.items()):
            key = (rel, name)
            allowed = key in ALLOWED_GLOBALS
            # Marked used only when it actually suppresses a finding, never
            # merely because the name still exists. A first draft credited
            # the entry on the name alone, so a container that stopped being
            # written kept its excuse and the "may only shrink" rule bought
            # nothing — which is exactly what happened to the two STIX lists
            # once their handlers stopped appending.
            would_fire = name in writes or (name.startswith(SAMPLE_PREFIXES) and not guarded)
            if allowed and would_fire:
                used_allowlist.add(key)
                continue
            if allowed:
                continue

            if name in writes:
                report.findings.append(
                    Finding(
                        rel,
                        writes[name],
                        name,
                        "written-module-global",
                        "a route handler writes to a module-level container, which is one "
                        "object for the whole process. It has no tenant, so the read cannot "
                        "be scoped and a restart loses it.",
                    )
                )
                continue

            if name.startswith(SAMPLE_PREFIXES) and not guarded:
                shape = " It holds record-shaped literals." if _looks_fabricated(value) else ""
                report.findings.append(
                    Finding(
                        rel,
                        line,
                        name,
                        "ungated-sample-data",
                        f"named as sample data and served from a route module with no demo "
                        f"gate in the file.{shape} Guard it with one of {DEMO_GUARDS[:3]}, "
                        "or serve real rows.",
                    )
                )

    report.stale_allowlist = [f"{path} :: {name}" for (path, name) in ALLOWED_GLOBALS if (path, name) not in used_allowlist]
    return report


def _verdict(report: Report) -> int:
    if report.files_scanned == 0:
        print(
            "check_python_route_state: no route modules found under services/*/app/api — "
            "refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2

    if report.stale_allowlist:
        print("check_python_route_state: allowlist entries whose global has gone:", file=sys.stderr)
        for entry in report.stale_allowlist:
            print(f"  {entry}", file=sys.stderr)
        print("Remove them; the allowlist may only shrink.", file=sys.stderr)
        return 1

    if report.findings:
        print(
            f"check_python_route_state: {len(report.findings)} route module(s) keep state in a module global or serve invented data:",
            file=sys.stderr,
        )
        for finding in report.findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1

    print(
        f"check_python_route_state: OK — {report.globals_examined} module-level container(s) "
        f"across {report.files_scanned} route module(s); none is written by a handler or "
        f"serves ungated sample data ({len(ALLOWED_GLOBALS)} allowlisted with a reason)."
    )
    return 0


# ── Self-test ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Case:
    description: str
    source: str
    expect: str | None


def self_test_cases() -> tuple[Case, ...]:
    return (
        Case(
            "a dict a handler stores into by key — the copilot shape",
            "_CONVERSATIONS: dict = {}\nasync def chat(body):\n    _CONVERSATIONS[body.id] = body\n    return body\n",
            "written-module-global",
        ),
        Case(
            "a list a handler appends to — the STIX shape",
            "DEMO_INDICATORS = []\nasync def add(i):\n    DEMO_INDICATORS.append(i)\n",
            "written-module-global",
        ),
        Case(
            "a list a handler inserts into — the shifts shape",
            "_MOCK_SHIFTS = []\nasync def create(s):\n    _MOCK_SHIFTS.insert(0, s)\n",
            "written-module-global",
        ),
        Case(
            "a dict a handler deletes from",
            "_SAVED_SEARCHES = {}\nasync def drop(i):\n    del _SAVED_SEARCHES[i]\n",
            "written-module-global",
        ),
        Case(
            "a defaultdict, which is still one object per process",
            "from collections import defaultdict\n_SEEN = defaultdict(list)\nasync def note(k):\n    _SEEN[k].append(1)\n",
            "written-module-global",
        ),
        Case(
            "fabricated records read but never written, with no demo gate",
            "_MOCK_SHIFTS = [{'analyst': 'Dana Reyes', 'alerts_handled': 47, 'ticket': 'INFRA-412'}]\n"
            "async def shifts():\n    return _MOCK_SHIFTS\n",
            "ungated-sample-data",
        ),
        # ── and the directions it must not fire in ──────────────────────────
        Case(
            "a frozenset constant, which is not state",
            "ALLOWED = frozenset({'a', 'b'})\nasync def go():\n    return 'a' in ALLOWED\n",
            None,
        ),
        Case(
            "a read-only vocabulary map",
            "BACKEND_LABELS = {'qradar': 'IBM QRadar', 'sentinel': 'Microsoft Sentinel'}\nasync def labels():\n    return BACKEND_LABELS\n",
            None,
        ),
        Case(
            "sample records behind a demo gate",
            "from app.core.demo import is_demo\n"
            "_MOCK_SHIFTS = [{'analyst': 'Dana Reyes', 'alerts_handled': 47, 'ticket': 'INFRA-412'}]\n"
            "async def shifts():\n    return _MOCK_SHIFTS if is_demo() else []\n",
            None,
        ),
        Case(
            "a local dict inside a handler, which is per-request",
            "async def go():\n    cache = {}\n    cache['k'] = 1\n    return cache\n",
            None,
        ),
        Case(
            "a module global read but never written, holding no records",
            "_LIMITS = {'max': 10}\nasync def go():\n    return _LIMITS['max']\n",
            None,
        ),
    )


def _case_results(tmp: pathlib.Path) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for index, case in enumerate(self_test_cases()):
        tree = tmp / f"case{index}" / "services" / "probe" / "app" / "api"
        tree.mkdir(parents=True)
        (tree / "routes.py").write_text(case.source, encoding="utf-8")
        report = inspect(tmp / f"case{index}")
        kinds = {f.kind for f in report.findings}
        if case.expect is None:
            passed = not report.findings
            detail = f"expected nothing, got {sorted(kinds)}" if not passed else ""
        else:
            passed = case.expect in kinds
            detail = f"expected {case.expect}, got {sorted(kinds)}" if not passed else ""
        results.append((f"{case.description}{f' — {detail}' if detail else ''}", passed))
    return results


def _corpus_result(root: pathlib.Path) -> tuple[str, bool]:
    report = inspect(root)
    return (
        f"counts what it scanned ({report.globals_examined} globals in {report.files_scanned} route modules)",
        report.files_scanned > 0,
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="aisoc-route-state-") as tmp:
        extra = _case_results(pathlib.Path(tmp))
    extra.append(_corpus_result(repo_root()))
    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="render a verdict (default)")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
