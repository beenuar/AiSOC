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

#: Repo-root CLIs that are themselves a way the product is run, mapped to
#: the service whose ``app`` package they put on ``sys.path``. Their
#: ``from app.…`` imports are entry points into that service.
#:
#: Deliberately a named map and not "anything under ``scripts/`` counts".
#: Nine repo-root scripts import a service's ``app``, and most are CI
#: analysis tools that import a module precisely to inspect it — counting
#: those would let a checker vouch for dead code, which is weaker evidence
#: than the test imports this gate already refuses. The bar for an entry
#: here is that a user runs it: a documented ``make`` target or a command
#: the docs tell someone to type.
#:
#: A path that no longer exists, or that no longer imports the service,
#: fails the gate rather than lingering — the same discipline as the
#: allowlist below, for the same reason.
CLI_ENTRY_POINTS: dict[str, str] = {
    # `make replay-eval` / `make replay-eval-verify`. Builds and verifies
    # the design-partner evidence bundle on the operator's machine, so the
    # builder, the redactor and the verifier are imported from the API tree
    # rather than reached through a route.
    "scripts/run_replay_eval.py": "services/api",
}

#: Loaders that import by computed name. Each maps to the directory whose
#: modules it reaches.
DYNAMIC_LOADERS: dict[str, tuple[str, ...]] = {
    "services/api/app/services/plugin_manager.py": ("services/api/app/plugins",),
    "services/connectors/app/connectors/__init__.py": ("services/connectors/app/connectors",),
}

#: Modules whose **public symbols** must each have a production caller, not
#: merely a module with a production importer.
#:
#: Module granularity has a blind spot and it cost a safety control. A tenant's
#: response schedule — the change-freeze / out-of-hours / nobody-on-call gate —
#: lives in `approval_rules.py`, which `dispatcher.py` imports, so this gate
#: reported the module reachable and said nothing. But `apply_schedule` had
#: thirteen call sites and every one was in its own test, `ResponseSchedule` was
#: never constructed outside its definition, and the dispatcher imported three
#: other names from that file. The tables migration 142 created for it appeared
#: in exactly one file repo-wide — their own migration. A tenant who declared a
#: change freeze got automatic execution right through it, under a claim-matrix
#: row marked GATED on a test of pure functions.
#:
#: Deliberately a named list rather than every module. Measured over
#: `services/*/app/**`, "public symbol referenced only by tests" reports **634**
#: names, almost all of them FastAPI response models and request bodies that a
#: decorator argument references in their own file. A gate at that noise level
#: is a gate somebody switches off, and the mirror of a floor set too low is a
#: pattern set too broad. These are the modules where "declared and never
#: called" is a *safety* outcome rather than dead code: a verb that should have
#: been held executes, and nothing says so.
SYMBOL_REACHABILITY_MODULES: tuple[str, ...] = (
    "services/actions/app/live_actions/approval_rules.py",
    "services/actions/app/live_actions/capability_contracts.py",
)

#: Public symbols in the modules above with no production caller, each with a
#: reason. Same discipline as `ALLOWED_UNREACHABLE`: may only shrink.
ALLOWED_UNCALLED_SYMBOLS: dict[str, str] = {}

#: Modules with no production importer, each with the reason. May only
#: shrink: an entry whose module has gone, or which has since become
#: reachable, fails the gate rather than lingering as an excuse.
ALLOWED_UNREACHABLE: dict[str, str] = {
    # ── Named by the parity plan, restored by a later phase ───────────────
    # The pseudonymizer and its package marker were here. Parity 2.4 routed
    # every hosted LLM call through them at the contract layer, so they are
    # reachable now and the entries are gone rather than updated. That is
    # the allowlist shrinking as the plan says it only may.
    "services/agents/app/policy/__init__.py": "Package marker for the guardrails below.",
    "services/agents/app/policy/guardrails.py": (
        "Reads the console's per-action closure thresholds, and nothing reads "
        "it. Parity 2.1 decides whether the new closure-policy table wires "
        "this path or replaces it."
    ),
    "services/actions/app/services/unified_autonomy.py": (
        "Unified autonomy policy: maps a verdict and confidence onto an "
        "action tier. Superseded rather than pending — parity 2.1 shipped "
        "the per-tenant closure policy (migration 078) read by the real "
        "`run_auto_triage` path, and `approval_matrix.evaluate_contract` "
        "is what `dispatcher.py` calls. Kept rather than deleted because "
        "a third authority on 'may this execute without a human' is a "
        "safety question, not a tidiness one, and removing one is a "
        "product decision with a wider blast radius than the import graph "
        "shows: deleting its sibling below broke two gates that read it "
        "without importing it."
    ),
    # `services/actions/app/services/autonomy_evidence_rules.py` was here,
    # described as a permanent entry reached only by tooling. Fix pass 3.7
    # gave it a production caller: `tenant_policy` runs its two aggregates
    # and its demotion evaluator before handing a verb to dispatch. The entry
    # went the way an allowlist entry is supposed to go — a module stopped
    # being unreachable and the gate said so.
    # The four osquery entries that used to sit here are gone, and the
    # reason is worth keeping: they were not "constructed by name at
    # dispatch", they were genuinely unreachable. The only caller was a
    # playbook handler in `services/agents` importing `app.clients.*`,
    # a package that image does not contain, so the import raised on every
    # live query. Depth 5.1 made `osquery_live_query` a capability with
    # three arms in this service, and `osquery_arms.py` imports all four
    # at module scope — which is why the gate now reports them as excused
    # entries that no longer describe anything.
    # ── Built, never wired, and no plan item claims them ──────────────────
    # Recorded rather than deleted: deleting working code is a product
    # decision, and each of these is a complete implementation with tests.
    # Listing them is what makes the decision visible.
    "services/agents/app/agents/tool_loop.py": (
        "A re-export kept for import compatibility after the loop moved to "
        "app.llm.tool_loop. Nothing imports the old path any more, so this "
        "is a compatibility shim with nothing left to be compatible with."
    ),
    "services/agents/app/security/vaid_plugin.py": (
        "Optional VAID badge plugin (#1739, PR #1741), off by default and "
        "deliberately not wired: `install_into` is reachable, but nothing in "
        "`app/orchestrator`, `app/investigator` or service startup mints a "
        "`VaidBackedIdentity` for it to verify. Wiring the hook alone would "
        "be worse than leaving it — with no minting call site, turning "
        "`AISOC_VAID_PLUGIN_ENABLED` on would refuse every tool call, which "
        "is fail-closed and also the agent not working. The actions-service "
        "half (`app/security/vaid_verifier.py`) IS reachable from "
        "`live_actions.dispatch()` and is not allowlisted. Remove this entry "
        "in the change that mints an identity on a real agent path; until "
        "then the plugin is a verified shape rather than a running feature, "
        "and this entry is the record of that distinction."
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
    broken_cli_entries: list[str] = field(default_factory=list)
    symbols_checked: int = 0
    uncalled_symbols: list[str] = field(default_factory=list)
    stale_symbol_allowlist: list[str] = field(default_factory=list)
    missing_symbol_modules: list[str] = field(default_factory=list)


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


def _public_symbols(path: pathlib.Path) -> list[tuple[str, int]]:
    """Top-level public functions and classes declared in *path*."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    out: list[tuple[str, int]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and not node.name.startswith("_"):
            out.append((node.name, node.lineno))
    return out


def _referenced_names(path: pathlib.Path) -> set[str]:
    """Every identifier *path* mentions, however it mentions it.

    Attribute access, a bare name, an import alias and a string in ``__all__``
    all count. The question this answers is "does any production file name
    this symbol", and a gate that only understood one of those spellings would
    be the one-directional kind this repository keeps rediscovering.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # `__all__` entries and `getattr(mod, "Name")` both land here.
            names.add(node.value)
    return names


def _symbol_body_references(path: pathlib.Path, symbol: str) -> set[str]:
    """Identifiers mentioned inside *symbol*'s own definition in *path*."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and node.name == symbol:
            names: set[str] = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.Name):
                    names.add(inner.id)
                elif isinstance(inner, ast.Attribute):
                    names.add(inner.attr)
            return names
    return set()


def _inspect_symbols(root: pathlib.Path, report: Report) -> None:
    """The symbol-level arm. See ``SYMBOL_REACHABILITY_MODULES``."""
    declared: dict[str, tuple[str, int]] = {}
    for rel in SYMBOL_REACHABILITY_MODULES:
        path = root / rel
        if not path.is_file():
            # A stale entry roots nothing and silently stops checking the very
            # symbols it was added for, so it fails rather than lingering.
            report.missing_symbol_modules.append(rel)
            continue
        for name, lineno in _public_symbols(path):
            declared[name] = (rel, lineno)
    if not declared:
        return
    report.symbols_checked = len(declared)

    subject_paths = {(root / rel).resolve() for rel in SYMBOL_REACHABILITY_MODULES}
    called: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts or _is_test(path):
            continue
        parts = path.relative_to(root).parts
        if parts and parts[0] == "plans":
            continue
        # A contributor's virtualenv or tool cache inside the tree is not
        # production code, and a dependency that happens to define a name of
        # ours would vouch for it.
        if any(part.startswith(".") for part in parts) or "site-packages" in parts or "node_modules" in parts:
            continue
        resolved = path.resolve()
        if resolved in subject_paths:
            # The defining file does not vouch for its own symbols; nor does
            # the vendored byte-identical copy of it, which is a mirror and
            # not a caller.
            continue
        if "_vendor" in parts and path.name in {pathlib.Path(rel).name for rel in SYMBOL_REACHABILITY_MODULES}:
            continue
        called |= _referenced_names(path) & declared.keys()

    # A symbol a *reachable* sibling calls is reachable too. Without this step
    # `recipient_count_from` reads as uncalled: its only caller is
    # `scaled_impact`, in the same file, which production reaches through the
    # vendored copy. The transitive walk is what separates that from the real
    # shape — `apply_schedule` was referenced by nothing outside its own test
    # anywhere, including by its own module.
    frontier = deque(sorted(called))
    while frontier:
        name = frontier.popleft()
        rel, _lineno = declared[name]
        for reached in _symbol_body_references(root / rel, name) & declared.keys():
            if reached not in called:
                called.add(reached)
                frontier.append(reached)

    for name, (rel, lineno) in sorted(declared.items()):
        if name in called:
            continue
        if name in ALLOWED_UNCALLED_SYMBOLS:
            continue
        report.uncalled_symbols.append(f"{rel}:{lineno}: {name}")

    for name in sorted(ALLOWED_UNCALLED_SYMBOLS):
        if name not in declared or name in called:
            report.stale_symbol_allowlist.append(name)


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

        # A repo-root CLI reaches into exactly one service's `app`, so the
        # modules it names are roots for that service.
        service_rel = service.relative_to(root).as_posix()
        for cli_rel, cli_service in CLI_ENTRY_POINTS.items():
            if cli_service != service_rel:
                continue
            cli = root / cli_rel
            if not cli.is_file():
                report.broken_cli_entries.append(f"{cli_rel} (no such file)")
                continue
            named = {i for i in _imports(cli, "") if i == "app" or i.startswith("app.")}
            resolved = set()
            for imported in named:
                candidate = imported
                while candidate and candidate not in by_name:
                    candidate = candidate.rsplit(".", 1)[0] if "." in candidate else ""
                if candidate:
                    resolved.add(candidate)
            if not resolved:
                report.broken_cli_entries.append(f"{cli_rel} (imports no module of {cli_service})")
                continue
            entries |= resolved

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
    _inspect_symbols(root, report)
    return report


def _verdict(report: Report) -> int:
    if report.modules == 0 or report.entry_points == 0:
        print(
            "check_module_reachability: found no service modules or no entry points, so every "
            "module would read as unreachable. That is a broken probe, not a finding.",
            file=sys.stderr,
        )
        return 2

    # Ahead of the findings below: a CLI entry that no longer resolves
    # silently stops rooting the walk, which *adds* unreachable modules. The
    # gate would then report those as dead code and send someone to delete
    # working code, when the real fault is one stale path here.
    if report.broken_cli_entries:
        print(
            "check_module_reachability: CLI entry points that no longer reach their service:",
            file=sys.stderr,
        )
        for rel in report.broken_cli_entries:
            print(f"  {rel}", file=sys.stderr)
        print(
            "Fix the path or drop the entry. Left stale it roots nothing, and the modules it reached are then reported as dead code.",
            file=sys.stderr,
        )
        return 1

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

    if report.missing_symbol_modules:
        print(
            "check_module_reachability: SYMBOL_REACHABILITY_MODULES names files that do not exist, "
            "so their symbols are checked by nothing:",
            file=sys.stderr,
        )
        for rel in report.missing_symbol_modules:
            print(f"  {rel}", file=sys.stderr)
        return 1

    if report.stale_symbol_allowlist:
        print(
            "check_module_reachability: ALLOWED_UNCALLED_SYMBOLS entries that no longer describe an uncalled symbol:",
            file=sys.stderr,
        )
        for name in report.stale_symbol_allowlist:
            print(f"  {name}", file=sys.stderr)
        print("Remove them; the allowlist may only shrink.", file=sys.stderr)
        return 1

    if report.uncalled_symbols:
        print(
            f"check_module_reachability: {len(report.uncalled_symbols)} public symbol(s) in the "
            "governance layer have no production caller. A module with a production importer is not "
            "the same claim: `apply_schedule` lived in a module `dispatcher.py` imports and had "
            "thirteen call sites, all in its own test, so a tenant's declared change freeze was "
            "enforced by nobody:",
            file=sys.stderr,
        )
        for entry in report.uncalled_symbols:
            print(f"  {entry}", file=sys.stderr)
        return 1

    print(
        f"check_module_reachability: OK — {report.reachable} of {report.modules} module(s) "
        f"reachable from {report.entry_points} entry point(s); "
        f"{len(ALLOWED_UNREACHABLE)} allowlisted with a reason. "
        f"{report.symbols_checked} governance symbol(s) each have a production caller."
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

        # A repo-root CLI roots the walk — and only when it is mapped, so
        # the map cannot be bypassed by dropping a file into `scripts/`.
        cli_dir = pathlib.Path(tmp) / "scripts"
        cli_dir.mkdir(parents=True)
        (cli_dir / "run_probe.py").write_text("from app import orphan\n", encoding="utf-8")
        report = inspect(pathlib.Path(tmp))
        extra.append(
            (
                "an unmapped script under scripts/ does not rescue a module",
                "orphan.py" in {pathlib.Path(r).name for r in report.unreachable},
            )
        )

        CLI_ENTRY_POINTS["scripts/run_probe.py"] = "services/probe"
        try:
            report = inspect(pathlib.Path(tmp))
            extra.append(
                (
                    "a mapped CLI makes what it imports reachable",
                    "orphan.py" not in {pathlib.Path(r).name for r in report.unreachable},
                )
            )

            # The stale-entry arm, which is what keeps the map honest.
            (cli_dir / "run_probe.py").unlink()
            report = inspect(pathlib.Path(tmp))
            extra.append(("a mapped CLI that has gone is reported", bool(report.broken_cli_entries)))
            extra.append(("and that is a failure, not a pass", _verdict(report) == 1))

            # Present but no longer importing the service: the quieter half.
            (cli_dir / "run_probe.py").write_text("X = 1\n", encoding="utf-8")
            report = inspect(pathlib.Path(tmp))
            extra.append(
                (
                    "a mapped CLI that stopped importing the service is reported",
                    any("imports no module" in e for e in report.broken_cli_entries),
                )
            )
        finally:
            CLI_ENTRY_POINTS.pop("scripts/run_probe.py", None)

    # ── The symbol arm ───────────────────────────────────────────────────
    # Probed against a tree of its own, because the real corpus is clean by
    # construction once the fix lands and a gate proven only on a clean tree
    # is a gate nobody has watched fail.
    with tempfile.TemporaryDirectory(prefix="aisoc-symbol-") as tmp:
        base = pathlib.Path(tmp) / "services" / "probe" / "app"
        base.mkdir(parents=True)
        rules = base / "rules.py"
        rules.write_text(
            "def called_by_a_door():\n    return 1\n\n\n"
            "def helper():\n    return 2\n\n\n"
            "def uses_helper():\n    return helper()\n\n\n"
            "def apply_schedule():\n    return 3\n",
            encoding="utf-8",
        )
        (base / "main.py").write_text(
            "from app.rules import called_by_a_door, uses_helper\n\ncalled_by_a_door()\nuses_helper()\n",
            encoding="utf-8",
        )
        tests = pathlib.Path(tmp) / "services" / "probe" / "tests"
        tests.mkdir(parents=True)
        (tests / "test_rules.py").write_text("from app.rules import apply_schedule\n\napply_schedule()\n", encoding="utf-8")

        original = tuple(SYMBOL_REACHABILITY_MODULES)
        globals()["SYMBOL_REACHABILITY_MODULES"] = ("services/probe/app/rules.py",)
        try:
            report = inspect(pathlib.Path(tmp))
            uncalled = {entry.rsplit(": ", 1)[-1] for entry in report.uncalled_symbols}
            extra += [
                ("a governance symbol only its own test calls is reported", "apply_schedule" in uncalled),
                ("and that is a failure, not a pass", _verdict(report) == 1),
                ("a symbol a door calls is not reported", "called_by_a_door" not in uncalled),
                ("a symbol a reachable sibling calls is not reported", "helper" not in uncalled),
            ]

            globals()["SYMBOL_REACHABILITY_MODULES"] = ("services/probe/app/gone.py",)
            report = inspect(pathlib.Path(tmp))
            extra.append(("a listed module that does not exist is reported", bool(report.missing_symbol_modules)))

            globals()["SYMBOL_REACHABILITY_MODULES"] = ("services/probe/app/rules.py",)
            ALLOWED_UNCALLED_SYMBOLS["called_by_a_door"] = "probe"
            try:
                report = inspect(pathlib.Path(tmp))
                extra.append(("an allowlist entry for a symbol that IS called is reported", bool(report.stale_symbol_allowlist)))
            finally:
                ALLOWED_UNCALLED_SYMBOLS.pop("called_by_a_door", None)
        finally:
            globals()["SYMBOL_REACHABILITY_MODULES"] = original

    report = inspect(repo_root())
    extra.append(
        (
            f"it read a real corpus ({report.modules} modules, {report.entry_points} entry points, "
            f"{report.symbols_checked} governance symbols)",
            report.modules > 200 and report.entry_points > 5 and report.symbols_checked > 5,
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
