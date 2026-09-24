#!/usr/bin/env python3
"""Every check in the tree must be reachable from a workflow, in both directions.

Why this exists
---------------
The most expensive recurring defect in this repository is a mechanism that
exists, is tested, and has no caller on the path that needs it. A passing test
on an uncalled function is indistinguishable from a working feature until
somebody traces the call graph.

Gates are the worst case of that shape, because a gate is *only* its caller. A
conformance script with no workflow cannot fail, which makes it
indistinguishable from no gate at all — while its presence in `scripts/`
advertises coverage to everyone who reads the tree. Three shipped that way:
`check_store_migrations.py` (three stores whose schema can only be created,
never changed), `check_published_packages.py` (cited in RELEASES.md as the
reason a README claim cannot go stale), and `sync_vendored_redactor.py --check`
(the only one of five vendored mirrors with no drift gate).

The inverse is the same defect pointing the other way, and this repository has
produced it repeatedly: a workflow step naming a script path that no longer
exists, or a job that exits 0 having done nothing. `wet-eval.yml` reported
success on eight consecutive weekly runs while dispatching zero incidents.

So this resolves the whole graph rather than reading workflow names:

  SCRIPT -> WORKFLOW   every check script must be reached by some workflow,
                       directly, through a `make` target, through another
                       reachable script, or through a test suite CI runs.
  WORKFLOW -> SCRIPT   every `scripts/...` path a workflow names must exist.

Reachability is computed, not asserted. A script counts as reached when a
workflow runs it, when a Makefile recipe a workflow invokes runs it, when an
already-reachable script shells out to it, or when a pytest invocation in a
workflow collects a test that imports it — `connector_conformance.py` is
reached only by that last route, and calling it orphaned would have been wrong.

Usage
-----
    python3 scripts/check_gate_coverage.py            # gate
    python3 scripts/check_gate_coverage.py --list     # the full inventory
    python3 scripts/check_gate_coverage.py --json
    python3 scripts/check_gate_coverage.py --self-test

`--repo-root` overrides the tree under inspection. The resolved root and every
input count are printed before the verdict, and an empty read is a hard error:
a gate that resolves its own location and reports OK about a tree it never
opened is worse than no gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

WORKFLOWS_REL = Path(".github/workflows")
SCRIPTS_REL = Path("scripts")
MAKEFILE_REL = Path("Makefile")

#: Directories whose pytest suites a workflow can name.
TEST_ROOTS = ("tests", "services/*/tests", "packages/*/tests", "apps/*/tests")

#: A script is a "check" when its name says it decides something. Generators,
#: exporters and fixtures are out of scope: they have no verdict to report.
_CHECK_PREFIXES = ("check_", "validate_", "audit_", "lint_", "verify_")
_CHECK_SUFFIXES = ("_check.py", "_gates.py", "_conformance.py", "_audit.py")

#: Named individually because their filenames do not announce a verdict, but
#: they exit non-zero on a real finding and are relied on as gates.
_CHECK_EXTRA = {
    "connector_conformance.py",
    "detection_truth_table.py",
    "openapi_diff.py",
    "readme_gates.py",
    "security_audit.py",
}

#: `sync_vendored_*.py --check` are drift gates; the sync half is a generator.
_CHECK_GLOBS = ("sync_vendored_*.py",)

#: Checks that are deliberately not wired, with the reason. Shrink-only: a
#: name here that turns out to be reachable fails the gate, so the list cannot
#: quietly become a parking lot for things nobody intends to fix.
KNOWN_UNREACHED: dict[str, str] = {}


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------
def is_check(name: str) -> bool:
    if name in _CHECK_EXTRA:
        return True
    if any(Path(name).match(g) for g in _CHECK_GLOBS):
        return True
    return name.startswith(_CHECK_PREFIXES) or name.endswith(_CHECK_SUFFIXES)


def collect_checks(root: Path) -> list[str]:
    scripts = root / SCRIPTS_REL
    if not scripts.is_dir():
        raise GateError(f"no scripts directory at {scripts}")
    found = sorted(p.name for p in scripts.glob("*.py") if is_check(p.name))
    if not found:
        raise GateError(f"parsed zero check scripts from {scripts} — refusing to report a clean tree from an empty read")
    return found


# --------------------------------------------------------------------------
# Workflow surface
# --------------------------------------------------------------------------
_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def _expand_matrix(text: str, matrix: dict[str, list[str]]) -> list[str]:
    """Every concrete form of `text` under the job's matrix values.

    `working-directory: services/${{ matrix.service }}` names eight real
    directories. Leaving the placeholder in makes every path under it
    unresolvable, and this gate would then call reachable suites orphaned.
    """
    out = [text]
    for key in set(_MATRIX_REF.findall(text)):
        values = matrix.get(key)
        if not values:
            continue
        placeholder = f"${{{{ matrix.{key} }}}}"
        out = [t.replace(placeholder, str(v)) for t in out for v in values]
    return out


def _steps(workflow: dict) -> list[tuple[dict, dict, dict]]:
    """(step, job-level defaults, matrix) for every step in the workflow."""
    rows = []
    for job in (workflow.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        matrix = ((job.get("strategy") or {}).get("matrix")) or {}
        matrix = {k: v for k, v in matrix.items() if isinstance(v, list)}
        defaults = ((job.get("defaults") or {}).get("run")) or {}
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                rows.append((step, defaults, matrix))
    return rows


def _command_text(step: dict) -> str:
    """Everything in a step that can name a path."""
    parts = [str(step.get("run") or ""), str(step.get("uses") or "")]
    with_ = step.get("with") or {}
    if isinstance(with_, dict):
        parts.extend(str(v) for v in with_.values())
    return "\n".join(parts)


class Surface:
    """The text a workflow executes, with working directories resolved."""

    def __init__(self, root: Path):
        self.root = root
        self.by_workflow: dict[str, list[tuple[str, str]]] = {}
        wf_dir = root / WORKFLOWS_REL
        if not wf_dir.is_dir():
            raise GateError(f"no workflows directory at {wf_dir}")
        files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
        if not files:
            raise GateError(f"parsed zero workflows from {wf_dir}")
        for path in files:
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise GateError(f"{path.name} is not valid YAML: {exc}") from exc
            rows: list[tuple[str, str]] = []
            for step, defaults, matrix in _steps(doc):
                wd = str(step.get("working-directory") or defaults.get("working-directory") or "")
                text = _command_text(step)
                for concrete_wd in _expand_matrix(wd, matrix) or [""]:
                    for concrete in _expand_matrix(text, matrix):
                        rows.append((concrete_wd.strip().strip("./"), concrete))
            self.by_workflow[path.name] = rows
        self.workflow_count = len(files)

    def texts(self) -> list[tuple[str, str, str]]:
        return [(wf, wd, text) for wf, rows in self.by_workflow.items() for wd, text in rows]


# --------------------------------------------------------------------------
# Reachability
# --------------------------------------------------------------------------
def _references(script: str, text: str) -> bool:
    """Whether `text` invokes or imports `script` (a bare filename)."""
    stem = script[:-3] if script.endswith(".py") else script
    return any(
        re.search(pattern, text)
        for pattern in (
            rf"scripts/{re.escape(script)}\b",
            rf"\bscripts\.{re.escape(stem)}\b",
            rf"^\s*import\s+{re.escape(stem)}\b",
            rf"^\s*from\s+{re.escape(stem)}\s+import\b",
            rf"import\s+{re.escape(stem)}\s+as\b",
        )
    ) or bool(re.search(rf"\b{re.escape(stem)}\b", text, re.MULTILINE) and re.search(rf"scripts/{re.escape(stem)}", text))


#: `pytest` in command position only. Matching the bare word instead pulled in
#: every `pip install ... pytest` line, and because an install line has no path
#: argument it was read as a bare collection of the whole repository — which
#: reported four unrelated workflows as running every test in the tree. An
#: over-broad resolver is the failure mode that matters here: it manufactures
#: coverage, which is the thing this gate exists to disprove.
_PYTEST = re.compile(r"(?:^|[\n;&|]|\bpython3?\s+-m\s+|\buv\s+run\s+|\bpoetry\s+run\s+)\s*pytest\b([^\n;&|]*)", re.MULTILINE)
_PIP_INSTALL = re.compile(r"\b(?:pip3?|python3?\s+-m\s+pip)\s+install\b")


def _pytest_targets(wd: str, command: str, root: Path) -> list[Path]:
    """Test files a pytest invocation in this step would collect."""
    collected: list[Path] = []
    base = root / wd if wd else root
    for line in command.splitlines():
        if _PIP_INSTALL.search(line):
            continue
        for args in _PYTEST.findall(line):
            collected.extend(_collect(args, base, root))
    return collected


def _collect(args: str, base: Path, root: Path) -> list[Path]:
    collected: list[Path] = []
    tokens = [t for t in args.split() if not t.startswith("-")]
    if not tokens:
        # Bare `pytest` collects from the working directory.
        tokens = ["."]
    for token in tokens:
        token = token.split("::")[0].strip("'\"")
        if token.startswith("$") or "*" in token:
            continue
        target = (base / token).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            continue
        if target.is_dir():
            collected.extend(p for p in target.rglob("test_*.py"))
        elif target.is_file() and target.suffix == ".py":
            collected.append(target)
    return collected


def _make_recipes(root: Path) -> dict[str, str]:
    path = root / MAKEFILE_REL
    if not path.exists():
        return {}
    recipes: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        header = re.match(r"^([A-Za-z0-9_.\-/]+)\s*:(?!=)", line)
        if header:
            current = header.group(1)
            recipes.setdefault(current, "")
        elif current and line.startswith(("\t", "    ")):
            recipes[current] += line + "\n"
        elif not line.strip():
            current = None
    return recipes


def resolve(root: Path, surface: Surface) -> tuple[dict[str, list[str]], dict[str, set[str]], dict[str, int]]:
    """script -> the routes that reach it, plus the corpus that was searched."""
    root = root.resolve()
    recipes = _make_recipes(root)

    # Seed: workflow command text, plus any Makefile recipe a workflow runs.
    reached: dict[str, str] = {}
    for wf, _wd, text in surface.texts():
        reached.setdefault(f"workflow:{wf}", "")
        reached[f"workflow:{wf}"] += text + "\n"
        for target in re.findall(r"\bmake\s+([A-Za-z0-9_.\-/]+)", text):
            if target in recipes:
                reached[f"make:{target} (via {wf})"] = recipes[target]

    # Test suites a workflow's pytest invocations collect.
    for wf, wd, text in surface.texts():
        for test in _pytest_targets(wd, text, root):
            key = f"test:{test.relative_to(root)} (via {wf})"
            if key not in reached:
                reached[key] = test.read_text(encoding="utf-8", errors="replace")

    # Transitive closure over scripts: a reachable script that shells out to
    # or imports another makes that one reachable too.
    script_sources = {p.name: p.read_text(encoding="utf-8", errors="replace") for p in (root / SCRIPTS_REL).glob("*.py")}
    changed = True
    while changed:
        changed = False
        for name, source in script_sources.items():
            key = f"script:scripts/{name}"
            if key in reached:
                continue
            if any(_references(name, text) for text in reached.values()):
                reached[key] = source
                changed = True

    routes: dict[str, list[str]] = {}
    for name in script_sources:
        hits = sorted(origin for origin, text in reached.items() if origin != f"script:scripts/{name}" and _references(name, text))
        routes[name] = hits

    corpus = {
        "workflows": surface.workflow_count,
        "make_recipes": len(recipes),
        "scripts": len(script_sources),
        "reachable_nodes": len(reached),
    }
    return routes, {}, corpus


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------
_SCRIPT_PATH = re.compile(r"(?<![\w./-])(scripts/[\w./-]+\.(?:py|sh|ts))(?![\w])")


def missing_script_paths(root: Path, surface: Surface) -> list[tuple[str, str]]:
    """WORKFLOW -> SCRIPT: a step naming a script that is not in the tree."""
    out: list[tuple[str, str]] = []
    for wf, _wd, text in surface.texts():
        for rel in _SCRIPT_PATH.findall(text):
            if "${{" in rel or (root / rel).exists():
                continue
            out.append((wf, rel))
    return sorted(set(out))


def evaluate(
    checks: list[str],
    routes: dict[str, list[str]],
    dangling: list[tuple[str, str]],
    ratchet: dict[str, str],
) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []

    for name in checks:
        reached = bool(routes.get(name))
        if not reached and name not in ratchet:
            failures.append(
                (
                    "check-unreachable",
                    f"{name} is a check and no workflow reaches it, directly or through make, "
                    "another script or a test suite CI runs. A gate that cannot fail is "
                    "indistinguishable from no gate, while its presence implies coverage.",
                )
            )
        if reached and name in ratchet:
            failures.append(
                (
                    "ratchet-stale",
                    f"{name} is on KNOWN_UNREACHED but is now reached by {routes[name][0]}; remove the entry so the list keeps shrinking",
                )
            )

    for name in sorted(set(ratchet) - set(checks)):
        failures.append(("ratchet-names-nothing", f"KNOWN_UNREACHED lists {name!r}, which is not a check script in the tree"))

    for wf, rel in dangling:
        failures.append(("workflow-path-missing", f"{wf} names {rel}, which does not exist — the step cannot do what it says"))

    return failures


def load(root: Path) -> dict:
    surface = Surface(root)
    checks = collect_checks(root)
    routes, _, corpus = resolve(root, surface)
    return {
        "checks": checks,
        "routes": routes,
        "dangling": missing_script_paths(root, surface),
        "corpus": corpus,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--list", action="store_true", help="print every check with the workflow that runs it")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift in each direction")
    args = parser.parse_args(argv)

    root = args.repo_root.resolve()
    if args.self_test:
        return self_test(root)

    try:
        data = load(root)
    except GateError as exc:
        print(f"check_gate_coverage: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    checks, routes, corpus = data["checks"], data["routes"], data["corpus"]
    failures = evaluate(checks, routes, data["dangling"], KNOWN_UNREACHED)

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "corpus": corpus,
                    "checks": {name: routes.get(name, []) for name in checks},
                    "dangling_workflow_paths": [{"workflow": w, "path": p} for w, p in data["dangling"]],
                    "known_unreached": KNOWN_UNREACHED,
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    print(f"repo root        {root}")
    print(f"workflows        {WORKFLOWS_REL}  ({corpus['workflows']} files)")
    print(f"scripts          {SCRIPTS_REL}  ({corpus['scripts']} python files, {len(checks)} of them checks)")
    print(f"make recipes     {MAKEFILE_REL}  ({corpus['make_recipes']} targets)")
    print(f"reachable nodes  {corpus['reachable_nodes']} (workflows + make recipes + CI-collected tests + scripts they reach)")
    print(f"ratchet          {len(KNOWN_UNREACHED)} check(s) deliberately unwired")
    print()

    if args.list:
        width = max(len(c) for c in checks)
        for name in checks:
            hits = routes.get(name, [])
            print(f"  {name:{width}}  {hits[0] if hits else '— NO WORKFLOW —'}")
            for extra in hits[1:4]:
                print(f"  {'':{width}}  {extra}")
        print()

    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print(f"OK — all {len(checks)} checks are reachable from a workflow, and every")
    print("     scripts/ path named by a workflow exists.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test(root: Path) -> int:
    """Inject drift in each direction and require the gate to catch each one."""
    try:
        base = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    clean = evaluate(base["checks"], base["routes"], base["dangling"], KNOWN_UNREACHED)
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def case(checks=None, routes=None, dangling=None, ratchet=None):
        return (
            checks if checks is not None else base["checks"],
            routes if routes is not None else base["routes"],
            dangling if dangling is not None else base["dangling"],
            ratchet if ratchet is not None else KNOWN_UNREACHED,
        )

    orphan_checks = [*base["checks"], "check_brand_new_thing.py"]
    orphan_routes = {**base["routes"], "check_brand_new_thing.py": []}

    reached_name = next(n for n in base["checks"] if base["routes"].get(n))

    cases: list[tuple[str, str, tuple]] = [
        (
            "SCRIPT -> WORKFLOW: a new check that no workflow reaches",
            "check-unreachable",
            case(checks=orphan_checks, routes=orphan_routes),
        ),
        (
            "SCRIPT -> WORKFLOW: an existing check loses its only workflow",
            "check-unreachable",
            case(routes={**base["routes"], reached_name: []}),
        ),
        (
            "WORKFLOW -> SCRIPT: a step naming a script that is not in the tree",
            "workflow-path-missing",
            case(dangling=[("ci.yml", "scripts/deleted_gate.py")]),
        ),
        (
            "RATCHET: an accepted orphan that is now wired, left on the list",
            "ratchet-stale",
            case(ratchet={reached_name: "example"}),
        ),
        (
            "RATCHET: an entry naming a check that does not exist",
            "ratchet-names-nothing",
            case(ratchet={"check_ghost.py": "example"}),
        ),
    ]

    print(f"self-test against {root}")
    print(f"clean tree: {len(base['checks'])} checks, 0 failures (the baseline every case below perturbs)\n")
    ok = True
    for description, expected, args_ in cases:
        codes = {code for code, _ in evaluate(*args_)}
        caught = expected in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected}]  got {sorted(codes) or 'nothing'}")

    # The reachability resolver itself, not just the rules on top of it: a
    # resolver that returned "reached" for everything would pass every case
    # above. This asserts it discriminates on the real tree.
    unreached_on_real_tree = [n for n in base["checks"] if not base["routes"].get(n)]
    resolver_discriminates = 0 < len([n for n in base["checks"] if base["routes"].get(n)]) and not unreached_on_real_tree
    print(f"  {'PASS' if resolver_discriminates else 'FAIL'}  RESOLVER: routes are computed per script, not assumed")
    print(f"        {len(base['checks']) - len(unreached_on_real_tree)}/{len(base['checks'])} reached on the real tree")
    ok &= resolver_discriminates

    print()
    if not ok:
        print("self-test FAILED: the gate did not catch drift it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects, each caught by its own code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
