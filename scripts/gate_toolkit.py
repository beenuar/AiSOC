#!/usr/bin/env python3
"""The two things every gate in this tree has to get right, implemented once.

Why this exists
---------------
A gate is only worth the tree it opened. Copying ``scripts/`` into an empty
git repository and running every wired check there found five that reported
OK over a repository containing nothing: the detection validator certified
zero rules as valid, the dashboard check forgave a *missing* directory while
failing an empty one, the Go module check reported ``OK: 0 published module
path(s)``, the self-link check called every link healthy over zero files, and
the health-probe audit printed a table header and exited 0.

Two root causes ran through all five, and neither is specific to those five:

``__file__`` as the repository root
    ``Path(__file__).resolve().parent.parent`` is whatever happens to sit two
    levels above the script. A copy of the script run from somewhere else
    scans that other tree and prints a confident OK about a checkout the
    caller never meant. Asking git instead makes the answer describe a real
    repository or fail loudly.

"found nothing" and "scanned nothing" print the same word
    A gate that walks zero files finds zero violations. Unless it counts what
    it opened and refuses an empty read, the clean result is indistinguishable
    from a broken glob, a wrong root, or a tree that is not there at all.

So both live here rather than in each gate. Five near-identical copies of the
git resolution had already accumulated across ``scripts/``, which is how the
sixth gets written subtly differently.

Nothing here imports anything outside the standard library: several gates run
on a bare interpreter before any ``pip install``, and a toolkit that drags in
a dependency would take that away from them.
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

__all__ = [
    "BARE",
    "SELF_TEST_FLAG",
    "SKELETON",
    "TREE_SHAPES",
    "VERDICT_FLAG_PREFERENCE",
    "verdict_args",
    "repo_root",
    "scratch_tree",
    "run_in_scratch_tree",
    "refuses_an_empty_tree",
    "self_test_main",
    "self_test_if_requested",
]

#: The flag every gate answers to. Named once so the meta-gate that looks for
#: it and the gates that declare it cannot disagree about the spelling.
SELF_TEST_FLAG = "--self-test"

#: The flags that turn a run into a verdict, most specific first. Several
#: scripts here are a generator and a gate in one file — ``build_marketplace``
#: with no arguments *writes* the index and only ``--check`` compares it — so
#: "run it with no arguments" is not the same question as "ask it for a
#: verdict", and probing the wrong half reports that writing an empty index
#: over an empty tree credits nothing. True of every generator, and nothing to
#: do with the gate. Defined here and imported by ``check_gate_contract`` so
#: the self-test and the meta-gate cannot pick different halves.
VERDICT_FLAG_PREFERENCE = ("--check", "--check-only", "--strict", "--verify")

#: Environment that would redirect a gate away from the tree under test.
#: ``security_audit.py`` prefers ``GITHUB_WORKSPACE`` over anything it can
#: work out for itself, so a scratch run under Actions would otherwise read
#: the real checkout and report on the wrong tree entirely.
_ROOT_OVERRIDES = ("AISOC_REPO_ROOT", "GITHUB_WORKSPACE")


def repo_root(start: Path | None = None) -> Path:
    """The repository, per git — not per this file's location.

    ``start`` is the directory the question is asked from, and defaults to
    ``scripts/``: every gate lives there, so the answer is "the tree these
    gates belong to" rather than "wherever the caller happened to be".

    ``AISOC_REPO_ROOT`` overrides, which is how a caller points a gate at a
    tree deliberately. Falling back to the ``__file__`` walk is fine when
    there is no git — a release tarball, a container build context — but
    falling back *silently* is not, because the caller would never learn
    which tree was read.
    """
    override = os.environ.get("AISOC_REPO_ROOT")
    if override:
        return Path(override).resolve()

    here = Path(__file__).resolve().parent
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        cwd=start or here,
    )
    if out.returncode == 0 and out.stdout.strip():
        return Path(out.stdout.strip()).resolve()

    fallback = here.parent
    print(
        f"{Path(sys.argv[0]).name}: not a git checkout — falling back to {fallback}",
        file=sys.stderr,
    )
    return fallback


#: The two shapes a gate can be pointed at when it has nothing to judge.
#:
#: ``BARE``      the directories a gate renders a verdict about are *absent*.
#: ``SKELETON``  they are *present and empty*.
#:
#: They are different questions and a gate can answer them differently. The
#: shape that actually recurs here is the second: ``check_grafana_dashboards``
#: failed on an empty dashboards directory and passed on a missing one, and
#: ``check_route_tenant_scope`` printed ``scanned 0 routes across 0 files``
#: followed by a clean verdict against a ``services/`` directory that existed
#: and held nothing. A gate whose first act is ``if not X.is_dir(): return 2``
#: refuses BARE for a reason that says nothing about its corpus.
BARE = "bare"
SKELETON = "skeleton"
TREE_SHAPES = (BARE, SKELETON)

#: Directories the skeleton creates empty. Every top-level directory any gate
#: in this tree renders a verdict about; a gate whose subject is missing from
#: this list sees BARE twice and the second shape buys nothing for it.
_SKELETON_DIRS = (
    "services",
    "detections",
    "apps",
    "packages",
    "plugins",
    "docs",
    "infra",
    "marketplace",
    ".github/workflows",
)


@contextmanager
def scratch_tree(source: Path | None = None, *, shape: str = BARE) -> Iterator[Path]:
    """A git repository holding this repository's ``scripts/`` and nothing else.

    Not an empty directory: the gate under test has to be *runnable*, which
    means its own file and the siblings it imports have to be present. What
    is absent is everything a gate renders a verdict about — ``services/``,
    ``detections/``, ``apps/``, ``packages/``, ``docs/``, ``.github/``. A gate
    pointed here has nothing to inspect, so anything other than a refusal is
    a result it invented.

    ``shape=SKELETON`` creates those directories instead of omitting them,
    each empty. That distinguishes "the tree is not there" from "the corpus
    is gone", which is the failure that actually happens: a renamed package,
    a changed decorator spelling, a glob that stopped matching. None of them
    removes ``services/``.

    It is a real git repository with a commit, because a gate that resolves
    its root through ``git rev-parse`` must land *here* and not walk out into
    the checkout the scratch directory happens to sit inside.
    """
    if shape not in TREE_SHAPES:
        raise ValueError(f"unknown scratch tree shape {shape!r}; expected one of {TREE_SHAPES}")
    scripts = (source or Path(__file__).resolve().parent).resolve()
    if not scripts.is_dir():
        raise FileNotFoundError(f"no scripts directory to copy from: {scripts}")

    tmp = Path(tempfile.mkdtemp(prefix=f"aisoc-{shape}-tree-"))
    try:
        shutil.copytree(scripts, tmp / "scripts")
        if shape == SKELETON:
            for rel in _SKELETON_DIRS:
                (tmp / rel).mkdir(parents=True, exist_ok=True)
                # git does not track a directory, only files in it, and a gate
                # resolving its root through git must still find the directory
                # after `git clean -qxfd` between probes.
                (tmp / rel / ".gitkeep").write_text("", encoding="utf-8")
        git = ["git", "-c", "user.name=gate", "-c", "user.email=gate@invalid", "-c", "commit.gpgsign=false"]
        for argv in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-qm", "scratch"]):
            subprocess.run(git + argv, cwd=tmp, check=True, capture_output=True)  # noqa: S603
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_in_scratch_tree(
    script: str,
    args: Sequence[str] = (),
    *,
    tree: Path,
    timeout: int = 180,
) -> tuple[int | None, str]:
    """Run ``scripts/<script>`` inside ``tree``. Returns (exit status, output).

    ``None`` for the status means the run timed out, which is neither a pass
    nor a refusal and is reported as such rather than rounded to either.
    """
    env = {k: v for k, v in os.environ.items() if k not in _ROOT_OVERRIDES}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        done = subprocess.run(  # noqa: S603
            [sys.executable, str(Path("scripts") / script), *args],
            cwd=tree,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def refuses_an_empty_tree(script: str, args: Sequence[str] = (), *, shape: str = BARE) -> tuple[bool, str]:
    """Whether ``script`` declines to render a verdict about a tree with no content."""
    with scratch_tree(shape=shape) as tree:
        status, output = run_in_scratch_tree(script, args, tree=tree)
    if status is None:
        return False, output
    tail = "\n".join(line for line in output.strip().splitlines() if line.strip())[-400:]
    return status != 0, f"exit {status}\n{tail}" if tail else f"exit {status}"


def self_test_main(script: str, args: Sequence[str] = (), extra: Sequence[tuple[str, bool]] = ()) -> int:
    """The shared ``--self-test`` body: prove the gate fails closed on nothing.

    ``extra`` carries results a gate has already computed for cases only it
    can express — an injected violation of the specific rule it enforces.
    Those are printed alongside so one command answers "does this gate still
    work", which is the point of running a self-test before the gate itself.
    """
    ok = True
    for description, passed in extra:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")

    refused, detail = refuses_an_empty_tree(script, args)
    ok &= refused
    print(f"  {'PASS' if refused else 'FAIL'}  refuses a tree with no content rather than reporting it clean")
    for line in detail.splitlines():
        print(f"        {line}")

    print()
    if not ok:
        print(f"{script}: self-test FAILED")
        return 1
    print(f"{script}: self-test OK")
    return 0


def verdict_args(script: Path) -> list[str]:
    """The arguments that ask ``script`` for a verdict, read from its own source.

    Read rather than passed, so a gate that grows a ``--check`` mode does not
    have to remember to tell its self-test about it.
    """
    try:
        source = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    declared = {
        node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant) and node.value in VERDICT_FLAG_PREFERENCE
    }
    return next(([flag] for flag in VERDICT_FLAG_PREFERENCE if flag in declared), [])


def self_test_if_requested(script_path: str, args: Sequence[str] | None = None) -> None:
    """Answer ``--self-test`` and exit, for gates with nothing bespoke to add.

    Installed as one statement just below a gate's imports, so it runs before
    the gate touches anything — which is the point of a self-test. Two things
    keep it from firing when it should not:

    * it only acts when the flag is on the command line, so an ordinary run is
      untouched;
    * it only acts when the process was launched as *this* script. Gates in
      this tree import one another (``check_route_auth`` imports
      ``check_route_tenant_scope``), and without that guard the imported
      module would answer a flag meant for its importer.
    """
    if SELF_TEST_FLAG not in sys.argv[1:]:
        return
    if Path(sys.argv[0]).name != Path(script_path).name:
        return
    script = Path(script_path)
    sys.exit(self_test_main(script.name, verdict_args(script) if args is None else args))
