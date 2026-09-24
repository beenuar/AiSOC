#!/usr/bin/env python3
"""No gate in this tree may report OK over a repository containing nothing.

Why this exists
---------------
The cheapest diagnostic anyone has run on this repository was to copy
``scripts/`` into an empty git repository and run every wired check there.
Five reported OK over a tree with no content:

* ``validate_detections.py`` — the validator behind the rule count the front
  page quotes — printed a warning and exited 0, certifying zero rules valid.
* ``check_grafana_dashboards.py`` had both branches and had them backwards:
  it failed on an *empty* dashboards directory and passed on a *missing* one,
  forgiving the larger loss.
* ``check_go_module_paths.py`` reported ``OK: 0 published Go module path(s)``.
* ``check_repo_self_links.py`` called every self-link healthy over zero files
  — and it exists to replace a lychee run that accepted HTTP 403 as healthy,
  so it had inherited the same inability in a different costume.
* ``audit_health_probes.py --check`` printed a table header and exited 0.

All five are fixed. The probe that found them was a one-off, so the next gate
written could reintroduce the defect freely. This makes it permanent.

The question it asks
--------------------
Not "does the gate flag the right things" but **"what does it credit as
clean, and could it credit something it never opened?"** A gate that walks
zero files finds zero violations; unless it refuses an empty read, a clean
result is indistinguishable from a broken glob, a wrong root, or a tree that
is not there. *Found nothing* and *scanned nothing* print the same word.

What it checks
--------------
Three properties of every check in the tree, each with a shrink-only list of
recorded exceptions, each list verified in both directions so an entry that
stops being needed fails the build rather than sitting there:

``empty-tree``
    Run the gate the way CI runs it, inside a git repository holding only
    ``scripts/``. It must not exit 0.

``root-from-git``
    A gate that derives a repository root from ``__file__`` must also consult
    ``git rev-parse``. ``Path(__file__).parent.parent`` is whatever sits two
    levels above the script; a copy run from elsewhere scans that other tree
    and prints a confident OK about a checkout nobody asked about. One gate
    was in exactly that state and only a deliberate probe from another
    directory caught it.

``self-test``
    The gate declares ``--self-test``, so a contributor can prove it still
    detects what it claims to before CI does.

The inventory is not written here
---------------------------------
It comes from ``check_gate_coverage.py``, which already resolves the
workflow-to-check graph mechanically and classifies a script by what it does
rather than what it is called. Two scanners drift the first time either one
learns something the other has not — that gate went from 42 to 59 inventoried
checks the day its filename test was deleted, and a second inventory here
would have kept the old answer.

How an invocation is chosen
---------------------------
From the workflow surface, not from a list kept here. Every way a workflow
runs the script is a candidate, in CI's own spelling; ``--self-test`` is
excluded because it renders a verdict on the gate rather than on the tree,
and so are invocations naming an unexpanded shell variable or a path outside
the repository, because replaying those tests the argument list rather than
the tree. If nothing is replayable, the script's own declared verdict flag is
used.

A run that fails for a reason other than the empty tree — an argparse usage
error, or an import of a third-party module the environment lacks — proves
nothing, so it is reported as INCONCLUSIVE and fails this gate. Crediting a
refusal the probe never actually caused would be the same defect one level
up.

Usage
-----
    python3 scripts/check_gate_contract.py              # gate
    python3 scripts/check_gate_contract.py --list       # per-check detail
    python3 scripts/check_gate_contract.py --json
    python3 scripts/check_gate_contract.py --self-test  # prove it detects drift

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. Its siblings sit beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_gate_coverage as coverage  # noqa: E402
from gate_toolkit import (  # noqa: E402
    BARE,
    SELF_TEST_FLAG,
    SKELETON,
    TREE_SHAPES,
    VERDICT_FLAG_PREFERENCE,
    repo_root,
    run_in_scratch_tree,
    scratch_tree,
)

# --------------------------------------------------------------------------
# Recorded exceptions. Every one of these is shrink-only and checked in both
# directions: an entry naming a check that does not exist fails the build, and
# so does an entry whose reason has stopped being true.
# --------------------------------------------------------------------------

#: Every shape, when a script behaves the same against all of them.
ANY_SHAPE = "*"

#: Checks the empty-tree question cannot be put to, each recorded with the
#: disposition it is expected to produce. Recording the disposition and not
#: just the name is what makes the entry falsifiable: an exception written
#: because argparse refused the arguments does not quietly go on covering the
#: gate on the day it starts exiting 0 instead.
#:
#: Keyed ``script -> shape -> (disposition, reason)``. ``ANY_SHAPE`` covers
#: every shape and is what most entries use; a named shape overrides it. The
#: indirection earns its keep exactly once — ``check_logger_kwargs.py``
#: refuses the bare tree and legitimately passes the skeleton — and writing
#: both shapes out for the other four would have duplicated four paragraphs
#: to express "no change".
EMPTY_TREE_EXCEPTIONS: dict[str, dict[str, tuple[str, str]]] = {
    "wet_eval_check.py": {
        ANY_SHAPE: (
            "passed",
            "Reads two environment variables and no repository content at all. Its exit status is 0 by "
            "design so a fork with no secrets does not look like a broken build; the verdict is the JSON "
            "status file that wet-eval.yml branches on, which is why check_gate_coverage classifies it "
            "from the job graph rather than from anything intrinsic. There is no tree for it to credit, "
            "so its --self-test checks the verdict it does render: should_run across present, absent, "
            "partial and dry-run secrets.",
        )
    },
    "security_audit.py": {
        ANY_SHAPE: (
            "passed",
            "Three of its four arms — pnpm, python, go — now refuse a tree with no manifests in it. The "
            "fourth, validate-ignores, has scripts/security_audit_ignores.txt as its entire subject, and "
            "scripts/ is the one directory the scratch tree has to keep for the gate to be runnable at "
            "all. So the probe cannot pose the question for that arm; the missing-policy-file case is "
            "covered instead by test_validate_ignores_refuses_a_missing_policy_file.",
        )
    },
    "openapi_diff.py": {
        ANY_SHAPE: (
            "inconclusive",
            "Both specifications are named on the command line and one of them is a checkout of main that "
            "openapi-breaking.yml writes outside the repository, so it discovers nothing from the tree and "
            "there is no empty-tree verdict to render. Run with no arguments it refuses at argparse, before "
            "any file is opened.",
        )
    },
    "wet_eval_update_benchmark.py": {
        ANY_SHAPE: (
            "inconclusive",
            "Same shape: --wet-block names a report the weekly workflow produces outside the checkout, so "
            "the only replayable invocation would be testing the argument list rather than the tree. "
            "Required arguments mean argparse refuses a bare run before it reads anything.",
        )
    },
    "check_logger_kwargs.py": {
        BARE: (
            "refused",
            "No services/ directory at all, which it refuses outright before scanning. Recorded rather "
            "than left implicit because the skeleton entry below only makes sense next to it.",
        ),
        SKELETON: (
            "passed",
            "Its corpus is every Python file in the repository, not one directory — scripts/ is in scope "
            "and the scratch tree keeps it, so against a skeleton it classifies real stdlib loggers in "
            "real files and correctly finds none misused. That is a pass over a corpus it genuinely has, "
            "not a credit for a tree it never opened, and its own floor proves the difference: it exits 1 "
            "when it classifies zero stdlib calls. Measured, not assumed — 64 of the 71 checks refuse the "
            "skeleton and this is the only one whose disposition differs between the two shapes.",
        ),
    },
}

#: Checks that derive a root from ``__file__`` and do not consult git. Empty:
#: every check in the tree resolves through git today. The list stays so that
#: a future exception has to be written down and justified rather than
#: appearing as a quietly relaxed rule.
NO_GIT_ROOT: dict[str, str] = {}

#: Checks that do not declare ``--self-test``. Also empty, same reason.
NO_SELF_TEST: dict[str, str] = {}


class ProbeError(RuntimeError):
    """The probe could not be set up. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Choosing how to run each gate
# --------------------------------------------------------------------------
#: Command words that mean "the next path is a Python program". Requiring one
#: is what keeps a quoted path inside an `echo` out of the answer: shlex hands
#: back `['echo', 'scripts/foo.py']`, whose command word is `echo`. A matcher
#: that looked for the substring counted eleven services as CI-covered on the
#: strength of a quoted path in a shell array.
_INTERPRETERS = frozenset({"python", "python3", *(f"python3.{minor}" for minor in range(8, 20))})

#: `uv run python x.py` and `poetry run python x.py` reach the same place.
_RUNNERS = frozenset({"uv", "poetry"})


def _segments(text: str) -> list[str]:
    """Individual commands inside a workflow `run:` block."""
    joined = text.replace("\\\n", " ")
    parts: list[str] = []
    for line in joined.splitlines():
        for piece in re.split(r"&&|\|\||[;|]", line):
            stripped = piece.strip()
            if stripped:
                parts.append(stripped)
    return parts


def _argv_after(tokens: list[str], script: str) -> list[str] | None:
    """The arguments a command passes to ``scripts/<script>``, or None."""
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index < len(tokens) and tokens[index] == "env":
        index += 1
        while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
            index += 1
    if index >= len(tokens):
        return None
    if tokens[index] in _RUNNERS:
        if index + 1 >= len(tokens) or tokens[index + 1] != "run":
            return None
        index += 2
        if index < len(tokens) and tokens[index] in _INTERPRETERS:
            index += 1
    elif tokens[index] in _INTERPRETERS:
        index += 1
    else:
        return None
    # `python -m pytest ...` runs a module, not this script.
    if index < len(tokens) and tokens[index].startswith("-"):
        return None
    if index >= len(tokens) or Path(tokens[index]).name != script:
        return None
    return tokens[index + 1 :]


def _replayable(args: Sequence[str]) -> bool:
    """Whether replaying these arguments would test the tree rather than the argument list.

    An unexpanded `$VAR` becomes a literal path that cannot exist, and an
    absolute path is an artefact CI builds outside the checkout. Either way
    the gate would fail for a reason the empty tree did not cause, which is
    not evidence of anything.
    """
    return not any("$" in arg or arg.startswith("/") for arg in args)


def ci_invocations(surface: coverage.Surface, script: str, signals: dict[str, str] | None = None) -> list[list[str]]:
    """Every replayable way a workflow asks ``script`` for a verdict.

    Asks for a verdict, not merely runs: several scripts here are a generator
    and a gate in one file, and CI runs both halves. ``build_marketplace.py``
    with no arguments *writes* ``marketplace/index.json``; only
    ``--check`` compares it. Probing the generator would report that writing
    an empty index over an empty tree is a gate crediting nothing, which is
    true of every generator and says nothing about the gate. So when a script
    declares verdict flags, only the invocations carrying one are probed —
    the same structural signal ``check_gate_coverage`` classifies it by.
    """
    verdict_flags = {f for f in (signals or {}).get("verdict-flag", "").split() if f != SELF_TEST_FLAG}
    found: list[list[str]] = []
    for _workflow, _wd, text in surface.texts():
        if f"/{script}" not in text and not text.strip().startswith(script):
            continue
        for segment in _segments(text):
            try:
                tokens = shlex.split(segment)
            except ValueError:
                continue
            args = _argv_after(tokens, script)
            if args is None or args == [SELF_TEST_FLAG] or not _replayable(args):
                continue
            if verdict_flags and not verdict_flags & set(args):
                continue
            if args not in found:
                found.append(args)
    # Longest first: a step that passes flags is asking a sharper question
    # than a bare run, and is the one whose behaviour matters most.
    found.sort(key=len, reverse=True)
    return found


def declared_invocations(signals: dict[str, str]) -> list[list[str]]:
    """Fallbacks from the gate's own declared verdict flags."""
    flags = [f for f in signals.get("verdict-flag", "").split() if f != SELF_TEST_FLAG]
    ordered = [f for f in VERDICT_FLAG_PREFERENCE if f in flags]
    ordered += [f for f in flags if f not in ordered]
    return [[flag] for flag in ordered] + [[]]


# --------------------------------------------------------------------------
# Reading the result
# --------------------------------------------------------------------------
_ARGPARSE_USAGE = re.compile(r"^usage: ", re.MULTILINE)
_ARGPARSE_ERROR = re.compile(r"^\S+: error: ", re.MULTILINE)
_MISSING_MODULE = re.compile(r"ModuleNotFoundError: No module named '([\w.]+)'")

REFUSED = "refused"
PASSED = "passed"
INCONCLUSIVE = "inconclusive"


def importable_names(root: Path) -> frozenset[str]:
    """Top-level module names the repository itself supplies.

    A gate that dies on ``No module named 'app'`` inside the scratch tree died
    *because* the tree is empty — ``app`` is the package under ``services/``.
    One that dies on ``No module named 'structlog'`` died because the probe
    environment is short a dependency, which is evidence about the probe and
    not about the gate.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        raise ProbeError(f"cannot list tracked files under {root}: {out.stderr.strip()}")
    names: set[str] = set()
    for line in out.stdout.splitlines():
        path = Path(line)
        if path.name == "__init__.py":
            names.add(path.parent.name)
        elif path.suffix == ".py":
            names.add(path.stem)
    if not names:
        raise ProbeError(f"git ls-files returned no Python under {root}")
    return frozenset(names)


def classify(status: int | None, output: str, supplied: frozenset[str]) -> tuple[str, str]:
    """(disposition, why) for one run of a gate in the scratch tree."""
    if status is None:
        return INCONCLUSIVE, "timed out"
    if status == 0:
        return PASSED, "exited 0"
    if _ARGPARSE_USAGE.search(output) and _ARGPARSE_ERROR.search(output):
        return INCONCLUSIVE, "argparse rejected the arguments, so the tree was never read"
    missing = _MISSING_MODULE.search(output)
    if missing and missing.group(1).split(".")[0] not in supplied:
        return INCONCLUSIVE, f"the probe environment has no {missing.group(1)!r}, which this repository does not supply"
    return REFUSED, f"exited {status}"


@dataclass
class Run:
    """One invocation of one gate inside one scratch tree."""

    args: list[str]
    source: str
    shape: str
    disposition: str
    why: str
    evidence: str = ""


@dataclass
class Probe:
    """Everything the probe learned about one gate."""

    script: str
    runs: list[Run] = field(default_factory=list)

    def disposition_for(self, shape: str) -> str:
        """The worst thing any invocation did against ``shape``.

        Worst, not first: a script CI runs four ways is four gates wearing one
        name, and excusing the set because the first one refused is how a
        subcommand that credits an empty tree stays hidden behind a sibling
        that does not.
        """
        seen = {run.disposition for run in self.runs if run.shape == shape}
        if PASSED in seen:
            return PASSED
        if REFUSED in seen:
            return REFUSED
        return INCONCLUSIVE

    def why_for(self, shape: str) -> str:
        worst = self.disposition_for(shape)
        return next(
            (run.why for run in self.runs if run.shape == shape and run.disposition == worst),
            "no invocation was attempted",
        )

    @property
    def shapes(self) -> list[str]:
        return [shape for shape in TREE_SHAPES if any(run.shape == shape for run in self.runs)]


def probe(surface: coverage.Surface, checks: dict[str, dict[str, str]], root: Path, *, only: str | None = None) -> list[Probe]:
    """Run every check inside a repository with no content and read the result.

    Every way CI runs a script is probed, because each is a verdict somebody
    relies on. Its own declared flags are the fallback, used only when nothing
    CI does can be replayed — a step whose arguments name an artefact built
    outside the checkout tests the argument list rather than the tree.

    Two tree shapes, because they are two questions. ``BARE`` asks what a gate
    does when the thing it judges is not there; ``SKELETON`` asks what it does
    when the directory is there and holds nothing. The second is the one that
    happens — a renamed package, a changed glob — and a gate opening with
    ``if not X.is_dir(): return 2`` answers the first for a reason that says
    nothing about its corpus.
    """
    supplied = importable_names(root)
    results: dict[str, Probe] = {script: Probe(script=script) for script in sorted(checks) if not only or script == only}
    for shape in TREE_SHAPES:
        with scratch_tree(root / "scripts", shape=shape) as tree:
            for script, result in results.items():
                for args in ci_invocations(surface, script, checks[script]):
                    result.runs.append(_run_one(script, args, tree, supplied, "the workflow that runs it", shape))
                if result.disposition_for(shape) == INCONCLUSIVE:
                    for args in declared_invocations(checks[script]):
                        run = _run_one(script, args, tree, supplied, "its own declared verdict flag", shape)
                        result.runs.append(run)
                        if run.disposition != INCONCLUSIVE:
                            break
    return list(results.values())


def _run_one(script: str, args: Sequence[str], tree: Path, supplied: frozenset[str], source: str, shape: str) -> Run:
    status, output = run_in_scratch_tree(script, args, tree=tree)
    _reset(tree)
    disposition, why = classify(status, output, supplied)
    return Run(args=list(args), source=source, shape=shape, disposition=disposition, why=why, evidence=_tail(output))


def _reset(tree: Path) -> None:
    """Undo anything the gate just wrote, so the next one sees the same tree."""
    for argv in (["reset", "--hard", "-q"], ["clean", "-qxfd"]):
        subprocess.run(["git", *argv], cwd=tree, check=False, capture_output=True)  # noqa: S603


def _tail(output: str, limit: int = 220) -> str:
    lines = [line for line in output.strip().splitlines() if line.strip()]
    return lines[-1][-limit:] if lines else ""


# --------------------------------------------------------------------------
# The two static properties
# --------------------------------------------------------------------------
#: Read from the syntax tree, never from the text. The first spelling of this
#: matched `\brepo_root\b` anywhere in the file, and `check_gate_coverage.py`
#: emits `"repo_root"` as a JSON key — so a gate that resolved its root from
#: `__file__` and never asked git read as compliant on the strength of a
#: dictionary key in its own output. A gate crediting something it never
#: opened, one level up from the gates it inspects.
_GIT_TOPLEVEL = "--show-toplevel"
_ROOT_HELPER = "repo_root"


def static_properties(source: str) -> dict[str, bool]:
    """What the syntax tree says about root resolution and self-testing."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"derives_root_from_file": False, "consults_git_for_root": False, "declares_self_test": False}
    return {
        "derives_root_from_file": any(_is_file_relative_root(n) for n in ast.walk(tree)),
        "consults_git_for_root": _consults_git(tree),
        "declares_self_test": _declares_self_test(tree),
    }


def _is_file_relative_root(node: ast.AST) -> bool:
    """``Path(__file__)…parent.parent`` or ``…parents[n]`` — a root from a file path."""
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        inner = node.value
        return isinstance(inner, ast.Attribute) and inner.attr == "parent" and _reaches_dunder_file(inner)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
        index = node.slice
        return isinstance(index, ast.Constant) and index.value != 0 and _reaches_dunder_file(node.value)
    return False


def _reaches_dunder_file(node: ast.AST) -> bool:
    return any(isinstance(sub, ast.Name) and sub.id == "__file__" for sub in ast.walk(node))


def _consults_git(tree: ast.Module) -> bool:
    """Either it shells out to git itself, or it calls the shared resolver."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == _GIT_TOPLEVEL:
            return True
        if isinstance(node, ast.Call):
            called = node.func
            name = called.id if isinstance(called, ast.Name) else (called.attr if isinstance(called, ast.Attribute) else None)
            if name == _ROOT_HELPER:
                return True
    return False


def _declares_self_test(tree: ast.Module) -> bool:
    """The flag reaches code, or the shared hook is installed.

    A docstring promising ``--self-test`` while nothing parses it is the
    documentation equivalent of a gate with no caller, and this repository has
    shipped that shape more than once — so the flag has to appear as a value
    the program uses, not as prose about the program.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == SELF_TEST_FLAG:
            return True
        if isinstance(node, ast.Name) and node.id == "SELF_TEST_FLAG":
            return True
        if isinstance(node, ast.Call):
            called = node.func
            name = called.id if isinstance(called, ast.Name) else (called.attr if isinstance(called, ast.Attribute) else None)
            if name == "self_test_if_requested":
                return True
    return False


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
def _expected(accepted: dict[str, dict[str, tuple[str, str]]], script: str, shape: str) -> tuple[str, str] | None:
    """The recorded exception for this script and shape, if there is one."""
    per_shape = accepted.get(script)
    if per_shape is None:
        return None
    return per_shape.get(shape) or per_shape.get(ANY_SHAPE)


def evaluate(
    checks: dict[str, dict[str, str]],
    probes: dict[str, Probe],
    properties: dict[str, dict[str, bool]],
    *,
    accepted: dict[str, dict[str, tuple[str, str]]],
    no_git_root: dict[str, str],
    no_self_test: dict[str, str],
) -> list[tuple[str, str]]:
    """Every finding, as (code, detail). Pure, so the self-test can drive it."""
    failures: list[tuple[str, str]] = []

    for script in sorted(checks):
        result = probes.get(script)
        if result is None:
            failures.append(("not-probed", f"{script} is a check and the probe produced no result for it"))
            continue
        for shape in result.shapes:
            exception = _expected(accepted, script, shape)
            disposition, why = result.disposition_for(shape), result.why_for(shape)
            if exception is not None and disposition != exception[0]:
                failures.append(
                    (
                        "exception-stale",
                        f"{script} is excused against the {shape} tree on the strength of a "
                        f"{exception[0]!r} disposition and now reports {disposition!r} ({why}). Either the "
                        "reason has stopped being true and the entry should go, or it is covering "
                        "something it was never written for.",
                    )
                )
            elif exception is None and disposition == INCONCLUSIVE:
                failures.append(
                    (
                        "inconclusive",
                        f"{script} against the {shape} tree: {why}. The probe did not exercise the gate, so "
                        "a non-zero exit is not evidence it refuses an empty tree — install the dependency "
                        "in the job, or record an exception saying why the question cannot be asked.",
                    )
                )
            elif exception is None and disposition == PASSED:
                offending = [" ".join(r.args) or "(no arguments)" for r in result.runs if r.shape == shape and r.disposition == PASSED]
                failures.append(
                    (
                        "passes-over-empty-tree",
                        f"{script} {', '.join(offending)} exited 0 inside a {shape} repository holding no "
                        "content. Found nothing and scanned nothing print the same word: this gate credits "
                        "a tree it never opened. Make it fail closed on an empty read, or record why the "
                        "exit status is not its verdict.",
                    )
                )

        static = properties.get(script, {})
        needs_git = static.get("derives_root_from_file") and not static.get("consults_git_for_root")
        if needs_git and script not in no_git_root:
            failures.append(
                (
                    "root-from-file",
                    f"{script} resolves a repository root from __file__ and never asks git. Two levels above "
                    "the script is whatever happens to be there; use gate_toolkit.repo_root().",
                )
            )
        if not needs_git and script in no_git_root:
            failures.append(("ratchet-stale", f"{script} is on NO_GIT_ROOT but now resolves its root from git; remove the entry"))

        if not static.get("declares_self_test") and script not in no_self_test:
            failures.append(
                (
                    "no-self-test",
                    f"{script} declares no {SELF_TEST_FLAG}, so nothing proves it still detects what it "
                    f"claims to. gate_toolkit.self_test_main() is the shared body.",
                )
            )
        if static.get("declares_self_test") and script in no_self_test:
            failures.append(("ratchet-stale", f"{script} is on NO_SELF_TEST but now declares {SELF_TEST_FLAG}; remove the entry"))

    flattened = {name: " ".join(reason for _disposition, reason in per_shape.values()) for name, per_shape in accepted.items()}
    reasons: dict[str, dict[str, str]] = {
        "EMPTY_TREE_EXCEPTIONS": flattened,
        "NO_GIT_ROOT": no_git_root,
        "NO_SELF_TEST": no_self_test,
    }
    for name, label in reasons.items():
        for script in sorted(set(label) - set(checks)):
            failures.append(("ratchet-names-nothing", f"{name} lists {script!r}, which is not a check in the tree"))
        for script, reason in sorted(label.items()):
            if script in checks and not reason.strip():
                failures.append(("ratchet-unexplained", f"{name}[{script!r}] carries no reason"))

    return failures


def _exception_summary() -> str:
    counts: dict[str, int] = {}
    for per_shape in EMPTY_TREE_EXCEPTIONS.values():
        for disposition, _reason in per_shape.values():
            counts[disposition] = counts.get(disposition, 0) + 1
    return ", ".join(f"{count} {name}" for name, count in sorted(counts.items())) or "none"


def load(root: Path, *, only: str | None = None) -> dict:
    surface = coverage.Surface(root)
    checks = coverage.collect_checks(root, surface.gating)
    results = probe(surface, checks, root, only=only)
    properties = {script: static_properties((root / "scripts" / script).read_text(encoding="utf-8", errors="replace")) for script in checks}
    return {"checks": checks, "probes": {p.script: p for p in results}, "properties": properties}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect (default: git rev-parse)")
    parser.add_argument("--list", action="store_true", help="print every check with its disposition")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only", help="probe a single check, by file name")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", help="prove this gate detects the drift it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    try:
        data = load(root, only=args.only)
    except (ProbeError, coverage.GateError, FileNotFoundError) as exc:
        print(f"check_gate_contract: FAILED to run the probe: {exc}", file=sys.stderr)
        return 2

    checks, probes, properties = data["checks"], data["probes"], data["properties"]
    failures = evaluate(
        checks,
        probes,
        properties,
        accepted=EMPTY_TREE_EXCEPTIONS,
        no_git_root=NO_GIT_ROOT,
        no_self_test=NO_SELF_TEST,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "checks": sorted(checks),
                    "probes": {name: asdict(p) for name, p in probes.items()},
                    "properties": properties,
                    "empty_tree_exceptions": EMPTY_TREE_EXCEPTIONS,
                    "no_git_root": NO_GIT_ROOT,
                    "no_self_test": NO_SELF_TEST,
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    runs = sum(len(p.runs) for p in probes.values())
    print(f"repo root        {root}")
    print(f"inventory        check_gate_coverage.py  ({len(checks)} checks, {len(probes)} probed over {runs} invocations)")
    print("scratch trees    bare      — a git repository holding only scripts/: services, detections, apps, docs, workflows absent")
    print("                 skeleton  — the same, with those directories present and empty")
    for shape in TREE_SHAPES:
        counts = {name: sum(1 for p in probes.values() if p.disposition_for(shape) == name) for name in (REFUSED, PASSED, INCONCLUSIVE)}
        print(f"  {shape:<14} {counts[REFUSED]} refused, {counts[PASSED]} exited 0, {counts[INCONCLUSIVE]} inconclusive")
    print(
        f"exceptions       {len(EMPTY_TREE_EXCEPTIONS)} scripts recorded ({_exception_summary()}), "
        f"{len(NO_GIT_ROOT)} without a git root, {len(NO_SELF_TEST)} without a self-test"
    )
    print()

    if args.list:
        width = max((len(s) for s in probes), default=10)
        for name in sorted(probes):
            for run in probes[name].runs:
                mark = {REFUSED: "refused ", PASSED: "EXITED 0", INCONCLUSIVE: "UNKNOWN "}[run.disposition]
                print(f"  {mark} {run.shape:<9} {name:{width}}  {' '.join(run.args) or '(no arguments)'}  [{run.source}]")
                if run.evidence:
                    print(f"           {'':9} {'':{width}}  {run.evidence}")
        print()

    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print(f"OK — {len(checks) - len(EMPTY_TREE_EXCEPTIONS)} of {len(checks)} checks refuse both a repository with no content")
    print("     and one whose directories are present and empty;")
    print(f"     the other {len(EMPTY_TREE_EXCEPTIONS)} are recorded exceptions, each with the disposition it is excused for per shape.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test() -> int:
    """Inject each defect this gate exists to catch and require it to be caught."""
    checks = {"check_real.py": {"verdict-flag": "--check"}}

    def result(*dispositions: str, shape: str = BARE, also: dict[str, str] | None = None) -> dict[str, Probe]:
        runs = [Run(args=["--check"], source="test", shape=shape, disposition=d, why=f"exited on {d}") for d in dispositions]
        for other_shape, disposition in (also or {}).items():
            runs.append(Run(args=["--check"], source="test", shape=other_shape, disposition=disposition, why="exited"))
        return {"check_real.py": Probe(script="check_real.py", runs=runs)}

    good = result(REFUSED)
    clean_props = {"check_real.py": {"derives_root_from_file": False, "consults_git_for_root": True, "declares_self_test": True}}

    def run(probes, props=None, *, accepted=None, no_git=None, no_self=None):
        return {
            code
            for code, _ in evaluate(
                checks,
                probes,
                props or clean_props,
                accepted=accepted or {},
                no_git_root=no_git or {},
                no_self_test=no_self or {},
            )
        }

    cases: list[tuple[str, str, set[str]]] = [
        (
            "a gate that exits 0 over a repository with no content",
            "passes-over-empty-tree",
            run(result(PASSED)),
        ),
        (
            "one invocation of a gate exits 0 while a sibling invocation refuses",
            "passes-over-empty-tree",
            run(result(REFUSED, PASSED)),
        ),
        (
            "a run that failed for a reason the empty tree did not cause",
            "inconclusive",
            run(result(INCONCLUSIVE)),
        ),
        (
            "a check the probe never reached at all",
            "not-probed",
            run({}),
        ),
        (
            "an accepted empty-tree pass that has started refusing — a stale exception",
            "exception-stale",
            run(good, accepted={"check_real.py": {ANY_SHAPE: (PASSED, "recorded reason")}}),
        ),
        (
            "an exception written for an inconclusive probe now covering an outright pass",
            "exception-stale",
            run(result(PASSED), accepted={"check_real.py": {ANY_SHAPE: (INCONCLUSIVE, "recorded reason")}}),
        ),
        (
            "an exception naming a check that is not in the tree",
            "ratchet-names-nothing",
            run(good, accepted={"check_ghost.py": {ANY_SHAPE: (PASSED, "recorded reason")}}),
        ),
        (
            "an exception with no reason given",
            "ratchet-unexplained",
            run(good, accepted={"check_real.py": {ANY_SHAPE: (REFUSED, "   ")}}),
        ),
        (
            "a gate that refuses the bare tree and credits the skeleton — the shape the second tree exists for",
            "passes-over-empty-tree",
            run(result(REFUSED, also={SKELETON: PASSED})),
        ),
        (
            "an ANY_SHAPE exemption cannot quietly cover a shape it was not written for",
            "exception-stale",
            run(
                result(REFUSED, also={SKELETON: PASSED}),
                accepted={"check_real.py": {ANY_SHAPE: (REFUSED, "recorded reason")}},
            ),
        ),
        (
            "a per-shape exemption covers only the shape it names",
            "passes-over-empty-tree",
            run(
                result(PASSED, also={SKELETON: PASSED}),
                accepted={"check_real.py": {SKELETON: (PASSED, "recorded reason")}},
            ),
        ),
        (
            "a gate rooting itself at __file__ with no git resolution",
            "root-from-file",
            run(
                good,
                {"check_real.py": {"derives_root_from_file": True, "consults_git_for_root": False, "declares_self_test": True}},
            ),
        ),
        (
            "a gate that has moved onto git but is still listed as if it had not",
            "ratchet-stale",
            run(good, no_git={"check_real.py": "recorded reason"}),
        ),
        (
            "a gate with no self-test",
            "no-self-test",
            run(
                good,
                {"check_real.py": {"derives_root_from_file": False, "consults_git_for_root": True, "declares_self_test": False}},
            ),
        ),
    ]

    print("check_gate_contract self-test")
    print("baseline: one clean check, 0 findings (every case below perturbs exactly that)\n")
    ok = not run(good)
    print(f"  {'PASS' if ok else 'FAIL'}  the unperturbed baseline reports nothing")

    for description, expected, codes in cases:
        caught = expected in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected}]  got {sorted(codes) or 'nothing'}")

    # The reader of the result, not just the rules on top of it. A classifier
    # that called everything a refusal would pass every case above.
    supplied = frozenset({"app"})
    reader: list[tuple[str, tuple[str, str], str]] = [
        ("exit 0 is a pass", classify(0, "OK: 0 things checked", supplied), PASSED),
        ("exit 1 with a refusal is a refusal", classify(1, "no detections/ directory", supplied), REFUSED),
        ("an argparse usage error proves nothing", classify(2, "usage: x [-h]\nx: error: unrecognized arguments", supplied), INCONCLUSIVE),
        (
            "a missing third-party module proves nothing",
            classify(1, "ModuleNotFoundError: No module named 'structlog'", supplied),
            INCONCLUSIVE,
        ),
        (
            "a missing repo package is the empty tree doing its job",
            classify(1, "ModuleNotFoundError: No module named 'app'", supplied),
            REFUSED,
        ),
        ("a timeout is neither", classify(None, "", supplied), INCONCLUSIVE),
    ]
    for read_label, (read, _why), read_want in reader:
        correct = read == read_want
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  READER: {read_label}")
        print(f"        expected {read_want}  got {read}")

    # The invocation chooser. A quoted path inside an `echo` is the shape that
    # manufactured CI coverage for eleven services in another gate.
    chooser: list[tuple[str, list[str] | None, list[str] | None]] = [
        ("a plain invocation yields its arguments", _argv_after(shlex.split("python3 scripts/x.py --check"), "x.py"), ["--check"]),
        ("a quoted path in an echo is not an invocation", _argv_after(shlex.split('echo "scripts/x.py --check"'), "x.py"), None),
        ("an env prefix is stepped over", _argv_after(shlex.split("FOO=1 python scripts/x.py --check"), "x.py"), ["--check"]),
        ("uv run reaches the same place", _argv_after(shlex.split("uv run python scripts/x.py"), "x.py"), []),
        ("python -m runs a module, not this script", _argv_after(shlex.split("python3 -m pytest scripts/x.py"), "x.py"), None),
    ]
    for chosen_label, chosen, chosen_want in chooser:
        correct = chosen == chosen_want
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  CHOOSER: {chosen_label}")
        print(f"        expected {chosen_want}  got {chosen}")

    replay: list[tuple[str, bool, bool]] = [
        ("an unexpanded shell variable is not replayable", _replayable(["--root", "$GITHUB_WORKSPACE"]), False),
        ("a path CI builds outside the checkout is not replayable", _replayable(["--old", "/tmp/base.yaml"]), False),
        ("a repository-relative path is", _replayable(["--new", "docs/openapi.yaml"]), True),
    ]
    for replay_label, replayed, replay_want in replay:
        correct = replayed == replay_want
        ok &= correct
        print(f"  {'PASS' if correct else 'FAIL'}  REPLAY: {replay_label}")
        print(f"        expected {replay_want}  got {replayed}")

    # And the scratch trees themselves, because every result above is only as
    # good as the claim that each tree really is the shape it says it is.
    with scratch_tree() as tree:
        present = sorted(p.name for p in tree.iterdir() if p.name != ".git")
        toplevel = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--show-toplevel"], cwd=tree, capture_output=True, text=True, check=False
        )
        isolated = Path(toplevel.stdout.strip() or "/nowhere").resolve() == tree.resolve()
        bare = present == ["scripts"]
    ok &= bare and isolated
    print(f"  {'PASS' if bare else 'FAIL'}  TREE(bare): the scratch repository holds scripts/ and nothing else")
    print(f"        contents {present}")
    print(f"  {'PASS' if isolated else 'FAIL'}  TREE(bare): git inside it resolves to itself, not to the real checkout")

    # The skeleton has to differ from the bare tree in exactly one way: the
    # directories exist and hold nothing. A skeleton that accidentally copied
    # content would turn every probe into a scan of real files, and one whose
    # directories vanished under `git clean` between probes would silently be
    # the bare tree wearing a second name.
    with scratch_tree(shape=SKELETON) as tree:
        _reset(tree)
        dirs = sorted(p.name for p in tree.iterdir() if p.is_dir() and p.name != ".git")
        services = tree / "services"
        empty = services.is_dir() and [p.name for p in services.iterdir()] == [".gitkeep"]
        has_dirs = "services" in dirs and "detections" in dirs
    ok &= empty and has_dirs
    print(f"  {'PASS' if has_dirs else 'FAIL'}  TREE(skeleton): the directories a gate judges are present")
    print(f"        contents {dirs}")
    print(f"  {'PASS' if empty else 'FAIL'}  TREE(skeleton): and still empty after a reset between probes")

    print()
    if not ok:
        print("self-test FAILED: this gate did not catch drift it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects and {len(reader) + len(chooser) + len(replay) + 4} component assertions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
