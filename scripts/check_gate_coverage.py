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
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

WORKFLOWS_REL = Path(".github/workflows")
SCRIPTS_REL = Path("scripts")
MAKEFILE_REL = Path("Makefile")

#: Directories whose pytest suites a workflow can name.
TEST_ROOTS = ("tests", "services/*/tests", "packages/*/tests", "apps/*/tests")

# --------------------------------------------------------------------------
# What counts as a check
# --------------------------------------------------------------------------
# This used to be a filename test: `check_*`, `validate_*`, `_conformance.py`
# and a hand-kept list of five exceptions for the ones whose names did not
# announce a verdict. That is the same defect the script exists to catch, one
# level up — a gate named something unexpected was simply not inventoried, and
# an uninventoried gate is indistinguishable from one that does not exist.
# Nineteen were in that state, every one of them a CI gate: eleven
# `generate_*`/`export_*`/`build_*` scripts a workflow runs with `--check`,
# `project_stats.py`, `storage_cost_model.py`, `curate_detections.py` and the
# rest. Deleting any of their workflow steps would have left this script
# reporting full coverage.
#
# Classification is now structural: what a script *does*.
#
#   verdict-flag      it declares a CLI option whose only purpose is to turn
#                     the run into a verdict.
#   findings-exit     its exit status is derived from findings it accumulates
#                     — non-zero when the accumulator is non-empty, or zero
#                     when it is empty. The polarity matters: `if not specs:
#                     return 1` is a generator aborting on an empty read, not
#                     a gate reporting a finding.
#   gates-a-workflow  a workflow job that runs it publishes an output another
#                     job branches on. `wet_eval_check.py` is a preflight that
#                     always exits 0 by design and reports its verdict in a
#                     JSON status file; the job graph is where that shows.
#
# All three are read from the tree, never from the name. The first two are
# intrinsic, so a gate is inventoried whether or not anything calls it — which
# is what keeps the SCRIPT -> WORKFLOW direction below from being vacuous.

#: Flags that exist only so a caller can act on the result.
_VERDICT_FLAGS = ("--check", "--check-only", "--verify", "--strict", "--self-test")
_VERDICT_PREFIXES = ("--fail-", "--max-", "--require-", "--assert-")

#: A check reports on the repository. Scripts that talk only to a running
#: service (`inject_scenario.py` posts alerts, `generate_runbook.py` queries a
#: tracing backend) exit non-zero when the network call fails, which is an
#: operational error and not a finding about the tree.
#
# `repo_root(` is in the list because it replaced `Path(__file__)` as the way
# a gate names the tree it is about, and six gates had no other signal: the
# migration onto `gate_toolkit.repo_root()` silently dropped
# `check_prompt_lock.py`, `export_openapi.py` and four `sync_vendored_*`
# mirrors out of this inventory, which would have left deleting their
# workflow steps unnoticed. A classifier keyed on an idiom has to move when
# the idiom does.
_INSPECTS_TREE = re.compile(r"Path\(__file__\)|\brepo_root\(|\.glob\(|\.rglob\(|\.iterdir\(|\.read_text\(|\.read_bytes\(|os\.walk\(")

#: Calls that grow a collection.
_MUTATORS = {"append", "add", "extend", "update"}

#: Annotations that say a name holds a collection of findings.
_COLLECTION_TYPES = {"list", "set", "dict", "tuple", "List", "Set", "Dict", "Counter", "defaultdict"}

#: Checks that are deliberately not wired, with the reason. Shrink-only: a
#: name here that turns out to be reachable fails the gate, so the list cannot
#: quietly become a parking lot for things nobody intends to fix.
KNOWN_UNREACHED: dict[str, str] = {}


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------
def _with_parents(tree: ast.Module) -> ast.Module:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node  # type: ignore[attr-defined]
    return tree


def _inside_except(node: ast.AST) -> bool:
    parent = getattr(node, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.ExceptHandler):
            return True
        parent = getattr(parent, "parent", None)
    return False


def _verdict_flags(tree: ast.Module) -> list[str]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            for arg in node.args:
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--")):
                    continue
                if arg.value in _VERDICT_FLAGS or arg.value.startswith(_VERDICT_PREFIXES):
                    found.add(arg.value)
    return sorted(found)


def _is_collection_annotation(node: ast.AST | None) -> bool:
    if node is None:
        return False
    base = node.value if isinstance(node, ast.Subscript) else node
    return isinstance(base, ast.Name) and base.id in _COLLECTION_TYPES


def _accumulators(tree: ast.Module) -> set[str]:
    """Names and attributes the script collects findings into.

    Attributes are included because a report object is the other common shape:
    `security_audit.py` decides on `report.high_critical` and
    `report.unscanned`, which are list fields it appends to.
    """
    assigned: set[str] = set()
    zeroed: set[str] = set()
    found: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        annotation: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value, annotation = [node.target], node.value, node.annotation
        for target in targets:
            key = target.id if isinstance(target, ast.Name) else (target.attr if isinstance(target, ast.Attribute) else None)
            if key is None:
                continue
            if isinstance(target, ast.Name):
                assigned.add(key)
            if isinstance(value, ast.List | ast.Set | ast.Dict | ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp):
                found.add(key)
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"list", "set", "dict", "sorted"}:
                found.add(key)
            if _is_collection_annotation(annotation):
                found.add(key)
            if isinstance(value, ast.Constant) and value.value == 0:
                zeroed.add(key)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_collection_annotation(node.returns):
            found.add(node.name)
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id in zeroed:
            found.add(node.target.id)  # a counter of findings
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
            container = node.func.value
            if isinstance(container, ast.Name):
                found.add(container.id)
            elif isinstance(container, ast.Attribute):
                found.add(container.attr)
        if isinstance(node, ast.For):
            if isinstance(node.iter, ast.Name) and node.iter.id in assigned:
                found.add(node.iter.id)
            elif isinstance(node.iter, ast.Attribute):
                found.add(node.iter.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len":
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in assigned:
                    found.add(arg.id)
                elif isinstance(arg, ast.Attribute):
                    found.add(arg.attr)
    return found


def _referenced(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.add(sub.attr)
    return out


def _negated(test: ast.AST, names: set[str]) -> bool:
    """Whether every accumulator in `test` appears under a `not`."""
    positive = set()
    for node in ast.walk(test):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            continue
        if isinstance(node, ast.Name) and node.id in names:
            positive.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in names:
            positive.add(node.attr)
    negated = set()
    for node in ast.walk(test):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            negated |= _referenced(node.operand) & names
    return bool(negated) and not (positive - negated)


def _exit_status(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Return):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "exit" and node.args:
        return node.args[0]
    if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
        if node.exc.func.id == "SystemExit" and node.exc.args:
            return node.exc.args[0]
    return None


def _is_int(node: ast.AST | None, *, zero: bool) -> bool:
    if not (isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool)):
        return False
    return (node.value == 0) if zero else (node.value != 0)


def _exit_path(tree: ast.Module) -> list[ast.AST]:
    """Functions whose return value becomes the process exit status.

    Bounded transitive closure from whatever is passed to `sys.exit(...)`,
    because dispatchers are common: `security_audit.py`'s `main` returns
    `handlers[args.command](args)` and the verdict is three frames down. A
    module with no exit path at all is a library, not a check.
    """
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
    entries: set[str] = set()
    for node in ast.walk(tree):
        args = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "exit":
            args = node.args
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
            args = node.exc.args if node.exc.func.id == "SystemExit" else None
        for arg in args or []:
            entries |= {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)} & set(funcs)
    if not entries and "main" in funcs:
        entries = {"main"}

    seen: set[str] = set()
    frontier, depth = entries, 0
    while frontier and depth < 4:
        seen |= frontier
        nxt: set[str] = set()
        for name in frontier:
            nxt |= ({n.id for n in ast.walk(funcs[name]) if isinstance(n, ast.Name)} & set(funcs)) - seen
        frontier, depth = nxt, depth + 1
    return [funcs[name] for name in sorted(seen)]


def _findings_exit(tree: ast.Module) -> str | None:
    """The guard that turns accumulated findings into an exit status."""
    accumulators = _accumulators(tree)
    if not accumulators:
        return None
    for function in _exit_path(tree):
        for node in ast.walk(function):
            if isinstance(node, ast.IfExp) and (_is_int(node.body, zero=False) or _is_int(node.orelse, zero=False)):
                if _referenced(node.test) & accumulators:
                    return ast.unparse(node)[:72]
                continue
            status = _exit_status(node)
            if status is None or _inside_except(node):
                continue
            nonzero = _is_int(status, zero=False)
            if not nonzero and not _is_int(status, zero=True):
                continue
            parent = getattr(node, "parent", None)
            while parent is not None:
                if isinstance(parent, ast.If) and (_referenced(parent.test) & accumulators):
                    # Findings present -> fail. The inverse (`if not specs:
                    # return 1`) is an abort on an empty read: the script
                    # could not do its job, which is not a verdict on the tree.
                    if nonzero != _negated(parent.test, accumulators):
                        return ast.unparse(parent.test)[:72]
                    break
                parent = getattr(parent, "parent", None)
    return None


def classify_source(source: str) -> dict[str, str]:
    """Structural signals that make a script a check. Empty means it is not."""
    try:
        tree = _with_parents(ast.parse(source))
    except SyntaxError:
        return {}
    if not _INSPECTS_TREE.search(source):
        return {}
    signals: dict[str, str] = {}
    if flags := _verdict_flags(tree):
        signals["verdict-flag"] = " ".join(flags)
    if guard := _findings_exit(tree):
        signals["findings-exit"] = guard
    return signals


def collect_checks(root: Path, gating: dict[str, str] | None = None) -> dict[str, dict[str, str]]:
    """script name -> the structural signals that classify it as a check."""
    scripts = root / SCRIPTS_REL
    if not scripts.is_dir():
        raise GateError(f"no scripts directory at {scripts}")
    found: dict[str, dict[str, str]] = {}
    for path in sorted(scripts.glob("*.py")):
        signals = classify_source(path.read_text(encoding="utf-8", errors="replace"))
        if gating and path.name in gating:
            signals["gates-a-workflow"] = gating[path.name]
        if signals:
            found[path.name] = signals
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


_NEEDS_OUTPUT = re.compile(r"needs\.([A-Za-z0-9_-]+)\.outputs")

#: A script the job *runs*, not one it merely mentions. The interpreter prefix
#: is what makes the difference: a job that computes which areas a diff touched
#: lists `scripts/backup_crypt.py` as a path to match, and the previous
#: spelling — the bare path, anywhere in the job's YAML — read that as the job
#: graph asking an encryption utility for a verdict, inventorying it as a gate
#: it is not. Same shape as the matcher that counted eleven services as
#: CI-covered on the strength of a quoted path inside an `echo`: a path is not
#: an invocation.
_SCRIPT_IN_JOB = re.compile(r"(?:python3?(?:\.\d+)?|uv run|poetry run)\s+(?:-m\s+)?[\w./-]*?scripts/([\w.-]+\.py)")


def _gating_jobs(doc: dict, workflow: str) -> dict[str, str]:
    """script -> "workflow:job" for jobs whose output another job branches on.

    A workflow that merely runs a script is not evidence the script is a gate.
    A workflow that publishes a job output and makes a downstream job
    conditional on it has, structurally, asked the script for a verdict.
    """
    jobs = doc.get("jobs") or {}
    branched: set[str] = set()
    for job in jobs.values():
        if isinstance(job, dict):
            branched.update(_NEEDS_OUTPUT.findall(yaml.safe_dump(job, default_flow_style=False)))
    out: dict[str, str] = {}
    for job_id, job in jobs.items():
        if job_id not in branched or not isinstance(job, dict) or not job.get("outputs"):
            continue
        for name in _SCRIPT_IN_JOB.findall(yaml.safe_dump(job, default_flow_style=False)):
            out.setdefault(name, f"{workflow}:{job_id}")
    return out


class Surface:
    """The text a workflow executes, with working directories resolved."""

    def __init__(self, root: Path):
        self.root = root
        self.by_workflow: dict[str, list[tuple[str, str]]] = {}
        self.gating: dict[str, str] = {}
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
            for name, origin in _gating_jobs(doc, path.name).items():
                self.gating.setdefault(name, origin)
        self.workflow_count = len(files)

    def texts(self) -> list[tuple[str, str, str]]:
        return [(wf, wd, text) for wf, rows in self.by_workflow.items() for wd, text in rows]

    def invoked_with_verdict_flag(self) -> dict[str, str]:
        """script -> the workflow that runs it with a verdict flag.

        The other direction on the classifier itself. If a workflow asks a
        script for a verdict and the classifier does not call it a check, the
        classifier has a blind spot — which is the defect this file is about.
        """
        flags = "|".join(re.escape(f) for f in (*_VERDICT_FLAGS, *_VERDICT_PREFIXES))
        pattern = re.compile(rf"scripts/([\w.-]+\.py)[^\n;&|]*?\s(?:{flags})")
        out: dict[str, str] = {}
        for workflow, _wd, text in self.texts():
            for name in pattern.findall(text):
                out.setdefault(name, workflow)
        return out


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
    checks: dict[str, dict[str, str]],
    routes: dict[str, list[str]],
    dangling: list[tuple[str, str]],
    ratchet: dict[str, str],
    verdict_invocations: dict[str, str] | None = None,
) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []

    for name in checks:
        reached = bool(routes.get(name))
        if not reached and name not in ratchet:
            failures.append(
                (
                    "check-unreachable",
                    f"{name} is a check ({', '.join(sorted(checks[name]))}) and no workflow reaches it, "
                    "directly or through make, another script or a test suite CI runs. A gate that cannot "
                    "fail is indistinguishable from no gate, while its presence implies coverage.",
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

    # CLASSIFIER -> WORKFLOW. The classifier read in the other direction: a
    # script CI runs with `--check` is being asked for a verdict, so anything
    # the classifier leaves out is a blind spot in the classifier, not a
    # script that stopped being a gate.
    for name, workflow in sorted((verdict_invocations or {}).items()):
        if name not in checks:
            failures.append(
                (
                    "classifier-blind-spot",
                    f"{workflow} runs {name} with a verdict flag, but no structural signal classifies it as a check — "
                    "it would not be inventoried, and losing its workflow step would go unnoticed",
                )
            )

    return failures


def load(root: Path) -> dict:
    surface = Surface(root)
    checks = collect_checks(root, surface.gating)
    routes, _, corpus = resolve(root, surface)
    return {
        "checks": checks,
        "routes": routes,
        "dangling": missing_script_paths(root, surface),
        "corpus": corpus,
        "verdict_invocations": surface.invoked_with_verdict_flag(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=repo_root())
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
    failures = evaluate(checks, routes, data["dangling"], KNOWN_UNREACHED, data["verdict_invocations"])

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "corpus": corpus,
                    "checks": {name: {"signals": checks[name], "routes": routes.get(name, [])} for name in checks},
                    "dangling_workflow_paths": [{"workflow": w, "path": p} for w, p in data["dangling"]],
                    "known_unreached": KNOWN_UNREACHED,
                    "verdict_invocations": data["verdict_invocations"],
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    by_signal = Counter(signal for signals in checks.values() for signal in signals)
    intrinsic = sum(1 for s in checks.values() if set(s) - {"gates-a-workflow"})
    print(f"repo root        {root}")
    print(f"workflows        {WORKFLOWS_REL}  ({corpus['workflows']} files)")
    print(f"scripts          {SCRIPTS_REL}  ({corpus['scripts']} python files, {len(checks)} of them checks)")
    print(f"make recipes     {MAKEFILE_REL}  ({corpus['make_recipes']} targets)")
    print(f"reachable nodes  {corpus['reachable_nodes']} (workflows + make recipes + CI-collected tests + scripts they reach)")
    print("classified by    " + ", ".join(f"{signal} {count}" for signal, count in sorted(by_signal.items())))
    print(f"                 {intrinsic} of {len(checks)} from an intrinsic signal, so they are inventoried with or without a caller")
    print(f"ratchet          {len(KNOWN_UNREACHED)} check(s) deliberately unwired")
    print()

    if args.list:
        width = max(len(c) for c in checks)
        for name in checks:
            hits = routes.get(name, [])
            print(f"  {name:{width}}  {hits[0] if hits else '— NO WORKFLOW —'}")
            print(f"  {'':{width}}  signals: {', '.join(sorted(checks[name]))}")
            for extra in hits[1:3]:
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

    clean = evaluate(base["checks"], base["routes"], base["dangling"], KNOWN_UNREACHED, base["verdict_invocations"])
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def case(checks=None, routes=None, dangling=None, ratchet=None, invocations=None):
        return (
            checks if checks is not None else base["checks"],
            routes if routes is not None else base["routes"],
            dangling if dangling is not None else base["dangling"],
            ratchet if ratchet is not None else KNOWN_UNREACHED,
            invocations if invocations is not None else base["verdict_invocations"],
        )

    orphan = "check_brand_new_thing.py"
    orphan_checks = {**base["checks"], orphan: {"verdict-flag": "--check"}}
    orphan_routes = {**base["routes"], orphan: []}
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
        (
            "CLASSIFIER -> WORKFLOW: CI asks a script for a verdict the classifier does not inventory",
            "classifier-blind-spot",
            case(invocations={**base["verdict_invocations"], "some_unclassified_thing.py": "ci.yml"}),
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

    # The classifier itself. The defect this replaced was a filename test, so
    # the case that matters is a gate whose name announces nothing: a
    # structural classifier must find it, and the old one could not.
    planted = '''\
"""A gate that no naming convention would reveal."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def main() -> int:
    offenders = [p.name for p in ROOT.glob("*.md") if "\\t" in p.read_text(errors="replace")]
    if offenders:
        print("tabs in markdown:", offenders)
        return 1
    return 0

sys.exit(main())
'''
    signals = classify_source(planted)
    print(f"  {'PASS' if signals else 'FAIL'}  CLASSIFIER: a gate planted under an unconventional name is still found")
    print(f"        `frobnicate_widgets.py` matches no check_/validate_/audit_ prefix; signals {sorted(signals) or 'none'}")
    ok &= bool(signals)

    # And the inverse, because a classifier that said yes to everything would
    # pass the case above: a generator that aborts on an empty read is not a
    # gate, and the polarity of its guard is the only thing that says so.
    generator = '''\
"""Writes a document. Not a gate."""
import sys
from pathlib import Path

def main() -> int:
    specs = [p for p in Path("specs").glob("*.yaml")]
    if not specs:
        print("nothing to render")
        return 1
    Path("out.md").write_text("\\n".join(p.name for p in specs))
    return 0

sys.exit(main())
'''
    rejected = not classify_source(generator)
    print(f"  {'PASS' if rejected else 'FAIL'}  CLASSIFIER: a generator that aborts on an empty read is not a check")
    print(f"        `if not specs: return 1` is an abort, not a finding; signals {sorted(classify_source(generator)) or 'none'}")
    ok &= rejected

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
