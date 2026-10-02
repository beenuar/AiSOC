#!/usr/bin/env python3
"""Every service module has a production importer, or a written reason.

Why this exists
---------------
The gates in this repository certify functions, not call paths. A claim row
can pass on a unit test of a module nothing imports, and that is not a
hypothetical failure: the capability review at `v14.0.0` found a large share
of the product built and dark. The hunting agent had no caller outside its
own test. `PostActionVerifier` had none at all. `run_with_tools` was a
working ReAct loop with zero production callers. The console's per-action
closure thresholds were read only by an unused module.

In each case a test passed, a claim row cited it, and the code never ran.

What "reachable" means here
---------------------------
A module is reachable when a path exists from an **entry point** to it
through ordinary imports. Entry points are the things a deployment actually
starts: a service's `main`, a worker, a CLI, a migration runner, a conftest
for the suites CI runs.

Test files are **not** entry points. That is the whole point: a module
imported only by its own test is exactly the shape this gate exists to
find, and counting the test would make the gate agree with the defect.

Dynamic imports
---------------
`importlib.import_module(name)` with a computed name cannot be followed
statically. Where a module is loaded that way, the loader is named in
`DYNAMIC_LOADERS` and the modules it reaches are treated as reachable from
it, so a plugin directory does not read as dead. A loader that stops being
used fails the gate, because the entry would then be excusing nothing.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys
from collections import deque
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Files a deployment starts. Relative to each service directory.
ENTRY_POINT_NAMES = (
    "app/main.py",
    "app/__main__.py",
    "main.py",
    "serve.py",
    "app/worker.py",
    "app/cli.py",
    # Migration runners, started by a command rather than imported. Three
    # services ship one and all three read as dead without this.
    "app/_migrate.py",
    "app/db/env.py",
    "alembic/env.py",
)

#: Any module under one of these, within a service, is an entry point: these
#: are started by a command rather than imported by one.
ENTRY_POINT_DIRS = (
    "app/scripts",
    "app/workers",
    "alembic",
    # Alembic revisions are discovered and executed by the runner, never
    # imported by name.
    "app/db/versions",
    "alembic/versions",
)

#: Loaders that import by computed name. Each maps to the directory whose
#: modules it reaches.
DYNAMIC_LOADERS: dict[str, tuple[str, ...]] = {
    "services/api/app/services/plugin_manager.py": ("services/api/app/plugins",),
    "services/connectors/app/connectors/__init__.py": ("services/connectors/app/connectors",),
}

#: Modules with no production importer, each with the reason. May only
#: shrink: an entry whose module has gone, or which has since become
#: reachable, fails the gate rather than lingering as an excuse.
ALLOWED_UNREACHABLE: dict[str, str] = {
    # ── Named by the parity plan, restored by a later phase ───────────────
    # The pseudonymizer and its package marker were here. Parity 2.4 routed
    # every hosted LLM call through them at the contract layer, so they are
    # reachable now and the entries are gone rather than updated. That is
    # the allowlist shrinking as the plan says it only may.
    "services/agents/app/hunt/agent.py": (
        "The NL hunting agent. Only its own test imports it, which is the "
        "defect the plan records. Wired to the console and MCP by parity 6.1."
    ),
    "services/agents/app/hunt/plan.py": "The hunting agent's plan model, reached only through it. Parity 6.1.",
    "services/agents/app/policy/__init__.py": "Package marker for the guardrails below.",
    "services/agents/app/policy/guardrails.py": (
        "Reads the console's per-action closure thresholds, and nothing reads "
        "it. Parity 2.1 decides whether the new closure-policy table wires "
        "this path or replaces it."
    ),
    "services/actions/app/services/unified_autonomy.py": (
        "Unified autonomy policy: maps a verdict and confidence onto an "
        "action tier. Not on the dispatch path. Parity 2.1 and 2.2 govern "
        "closure and dispatch, and decide whether this is the mechanism."
    ),
    "services/actions/app/services/autonomy_evidence_rules.py": ("Evidence rules for the same unresolved autonomy path as above."),
    # ── Vendor clients reached only through a capability executor ─────────
    # These are constructed by name at dispatch time, not imported. The
    # import graph cannot see that, and inventing a dynamic-loader entry for
    # a factory that takes a string would excuse more than it explains.
    "services/actions/app/clients/aisoc_direct_client.py": "Vendor client, constructed by capability name at dispatch.",
    "services/actions/app/clients/fleetdm_client.py": "Vendor client, constructed by capability name at dispatch.",
    "services/actions/app/clients/osctrl_client.py": "Vendor client, constructed by capability name at dispatch.",
    "services/actions/app/clients/osquery_allowlist.py": "Query allowlist, read by the osquery clients above.",
    # ── Built, never wired, and no plan item claims them ──────────────────
    # Recorded rather than deleted: deleting working code is a product
    # decision, and each of these is a complete implementation with tests.
    # Listing them is what makes the decision visible.
    "services/agents/app/agents/tool_loop.py": (
        "A re-export kept for import compatibility after the loop moved to "
        "app.llm.tool_loop. Nothing imports the old path any more, so this "
        "is a compatibility shim with nothing left to be compatible with."
    ),
    "services/agents/app/routing/cascade.py": "Cost-aware model cascade. Complete, tested, no caller.",
    "services/agents/app/orchestrator/planner.py": "Specialist planner, scored agent selection. Complete, tested, no caller.",
    "services/agents/app/swarm/__init__.py": "Package marker for the swarm modules below.",
    "services/agents/app/swarm/swarm.py": "Parallel competing-hypothesis agents. Complete, tested, no caller.",
    "services/agents/app/swarm/complexity.py": "Complexity scoring for the swarm above.",
    "services/agents/app/swarm/debate.py": "Debate resolution for the swarm above.",
    "services/agents/app/swarm/hypotheses.py": "Hypothesis generation for the swarm above.",
    "services/api/app/models/compliance.py": (
        "ORM model with no importer. The compliance routes use raw SQL "
        "against aisoc_compliance_evidence, so this model describes a table "
        "nothing maps through it."
    ),
    "services/api/app/services/compliance.py": (
        "Not the module the compliance routes use; that is compliance_mapping.py. A second compliance implementation with no caller."
    ),
    "services/api/app/services/detections/__init__.py": "Package marker for the two importers below.",
    "services/api/app/services/detections/ocsf_mapping.py": "OCSF field mapping for detection import. No caller.",
    "services/api/app/services/detections/sigma_import.py": (
        "Sigma importer. The shipped Sigma path is scripts/compile_sigma_ruleset.py, which runs at build time."
    ),
    "services/api/app/db/vector_migrations.py": (
        "Qdrant migration runner. Nothing in any compose path invokes it, which is the same gap recorded for the other migration chains."
    ),
    "services/fusion/app/memory/cli.py": "A CLI with no console-scripts entry and no caller.",
    "services/mesh/app/consensus.py": "Federation consensus. Complete, no caller.",
    "services/slack-bot/app/services/hmac_verify.py": "Signature verification helper with no caller.",
    "services/osquery-tls/app/api/v1/endpoints/extensions.py": (
        "A route module that is mounted by no router, so none of its routes "
        "is served. Reported here rather than silently, because an unmounted "
        "route module is indistinguishable from a working one in review."
    ),
    "services/purple-team/app/adversary/__init__.py": "Package marker for the adversary modules below.",
    "services/purple-team/app/adversary/campaign.py": "Adversary campaign model. No caller.",
    "services/purple-team/app/adversary/canned.py": "Canned adversary scenarios. No caller.",
    "services/purple-team/app/adversary/dac.py": "Detection-as-code evaluation. No caller.",
    "services/purple-team/app/adversary/planner.py": "Adversary planner. No caller.",
    "services/purple-team/app/adversary/scope_guard.py": "Scope guard for adversary emulation. No caller.",
    "services/purple-team/app/adversary/scoreboard.py": "Adversary scoreboard. No caller.",
}


@dataclass
class Report:
    modules: int = 0
    entry_points: int = 0
    reachable: int = 0
    unreachable: list[str] = field(default_factory=list)
    stale_allowlist: list[str] = field(default_factory=list)


def _service_dirs(root: pathlib.Path) -> list[pathlib.Path]:
    services = root / "services"
    if not services.is_dir():
        return []
    return [p for p in sorted(services.iterdir()) if (p / "app").is_dir() or (p / "main.py").is_file()]


def _is_test(path: pathlib.Path) -> bool:
    parts = path.parts
    return (
        "tests" in parts or "test" in parts or path.name.startswith("test_") or path.name.endswith("_test.py") or path.name == "conftest.py"
    )


def _module_name(service: pathlib.Path, path: pathlib.Path) -> str:
    rel = path.relative_to(service).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(path: pathlib.Path, module: str) -> set[str]:
    """Module names this file imports, absolute and relative resolved."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, OSError):
        return set()
    # A package's `__init__` *is* its package, so `from .x import Y` inside
    # `app/live_actions/__init__.py` means `app.live_actions.x`. Computing
    # the parent instead resolved it to `app.x`, which exists nowhere, and
    # every module a package re-exported read as unreachable.
    if path.name == "__init__.py":
        package = module
    else:
        package = module.rsplit(".", 1)[0] if "." in module else ""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative. `from . import x` inside `a.b.c` means `a.b.x`.
                base = package
                for _ in range(node.level - 1):
                    base = base.rsplit(".", 1)[0] if "." in base else ""
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            if target:
                out.add(target)
                for alias in node.names:
                    out.add(f"{target}.{alias.name}")
    return out


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    used_allowlist: set[str] = set()

    for service in _service_dirs(root):
        files = [p for p in sorted(service.rglob("*.py")) if not _is_test(p) and "__pycache__" not in p.parts and "_vendor" not in p.parts]
        if not files:
            continue

        by_name: dict[str, pathlib.Path] = {}
        for path in files:
            by_name[_module_name(service, path)] = path
        report.modules += len(by_name)

        entries: set[str] = set()
        for name, path in by_name.items():
            rel = path.relative_to(service).as_posix()
            if rel in ENTRY_POINT_NAMES or any(rel.startswith(d + "/") for d in ENTRY_POINT_DIRS):
                entries.add(name)
        report.entry_points += len(entries)

        # Dynamic loaders reach whole directories.
        extra_edges: dict[str, set[str]] = {}
        for loader_rel, targets in DYNAMIC_LOADERS.items():
            loader = root / loader_rel
            if not loader.is_file() or service not in loader.parents:
                continue
            loader_name = _module_name(service, loader)
            reached = set()
            for target_rel in targets:
                target = root / target_rel
                if not target.is_dir():
                    continue
                for path in target.rglob("*.py"):
                    if not _is_test(path) and "__pycache__" not in path.parts:
                        reached.add(_module_name(service, path))
            extra_edges[loader_name] = reached

        # Walk from the entry points.
        seen: set[str] = set()
        queue = deque(entries)
        while queue:
            name = queue.popleft()
            if name in seen or name not in by_name:
                continue
            seen.add(name)
            # `imported` rather than `target`: the dynamic-loader block
            # above binds `target` to a Path in the same function scope, and
            # reusing the name made the type checker read a module string as
            # a filesystem path.
            for imported in _imports(by_name[name], name) | extra_edges.get(name, set()):
                # Resolve the longest prefix that names a real module, so
                # `from app.a.b import C` reaches `app.a.b` and not `C`.
                candidate = imported
                while candidate and candidate not in by_name:
                    candidate = candidate.rsplit(".", 1)[0] if "." in candidate else ""
                if not candidate:
                    continue
                queue.append(candidate)
                # Importing `a.b.c` executes `a/__init__.py` and
                # `a/b/__init__.py` as well. Without this, 78 package
                # markers read as dead code purely because nothing names
                # them directly.
                parent = candidate
                while "." in parent:
                    parent = parent.rsplit(".", 1)[0]
                    if parent in by_name:
                        queue.append(parent)

        report.reachable += len(seen)
        for name, path in sorted(by_name.items()):
            if name in seen or not name:
                continue
            rel = path.relative_to(root).as_posix()
            if rel in ALLOWED_UNREACHABLE:
                used_allowlist.add(rel)
                continue
            report.unreachable.append(rel)

    report.stale_allowlist = [r for r in ALLOWED_UNREACHABLE if r not in used_allowlist]
    return report


def _verdict(report: Report) -> int:
    if report.modules == 0 or report.entry_points == 0:
        print(
            "check_module_reachability: found no service modules or no entry points, so every "
            "module would read as unreachable. That is a broken probe, not a finding.",
            file=sys.stderr,
        )
        return 2

    if report.stale_allowlist:
        print(
            "check_module_reachability: allowlist entries that no longer describe an unreachable module:",
            file=sys.stderr,
        )
        for rel in report.stale_allowlist:
            print(f"  {rel}", file=sys.stderr)
        print("Remove them; the allowlist may only shrink.", file=sys.stderr)
        return 1

    if report.unreachable:
        print(
            f"check_module_reachability: {len(report.unreachable)} module(s) have no production "
            "importer. A test that imports one of these proves the code compiles, not that it "
            "runs:",
            file=sys.stderr,
        )
        for rel in report.unreachable:
            print(f"  {rel}", file=sys.stderr)
        return 1

    print(
        f"check_module_reachability: OK — {report.reachable} of {report.modules} module(s) "
        f"reachable from {report.entry_points} entry point(s); "
        f"{len(ALLOWED_UNREACHABLE)} allowlisted with a reason."
    )
    return 0


def self_test() -> int:
    import tempfile

    extra: list[tuple[str, bool]] = []

    with tempfile.TemporaryDirectory(prefix="aisoc-reach-") as tmp:
        base = pathlib.Path(tmp) / "services" / "probe" / "app"
        base.mkdir(parents=True)
        (base / "main.py").write_text("from app import used\n", encoding="utf-8")
        (base / "used.py").write_text("X = 1\n", encoding="utf-8")
        (base / "orphan.py").write_text("Y = 2\n", encoding="utf-8")
        tests = pathlib.Path(tmp) / "services" / "probe" / "tests"
        tests.mkdir(parents=True)
        (tests / "test_orphan.py").write_text("from app import orphan\n", encoding="utf-8")

        report = inspect(pathlib.Path(tmp))
        unreachable = {pathlib.Path(r).name for r in report.unreachable}
        extra.append(("an orphaned module is reported", "orphan.py" in unreachable))
        extra.append(("a module the entry point imports is not", "used.py" not in unreachable))
        extra.append(
            (
                "a test importing the orphan does not rescue it, which is the point",
                "orphan.py" in unreachable,
            )
        )

        # Transitive reach.
        (base / "used.py").write_text("from app import deep\n", encoding="utf-8")
        (base / "deep.py").write_text("Z = 3\n", encoding="utf-8")
        report = inspect(pathlib.Path(tmp))
        unreachable = {pathlib.Path(r).name for r in report.unreachable}
        extra.append(("reach is transitive", "deep.py" not in unreachable))

    report = inspect(repo_root())
    extra.append(
        (
            f"it read a real corpus ({report.modules} modules, {report.entry_points} entry points)",
            report.modules > 200 and report.entry_points > 5,
        )
    )
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
