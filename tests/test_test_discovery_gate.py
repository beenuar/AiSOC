"""A suite is only worth the files its invocation reaches.

``scripts/check_test_discovery.py`` compares the test files git tracks against
the files the workflows actually collect. Before it existed, 63 were reached
by nothing — 56 of them under ``services/agents``, whose invocation was a
hand-maintained list of 26 file paths.

These tests pin the parts a reviewer cannot see by reading the gate's output:
what it *credits*. Every defect this gate has had came from crediting
something — the first version resolved ``tests/`` against the repository root
for a step that had ``cd``'d into a service, which simultaneously reported the
whole agents suite unreached and credited the root tree with a package's
invocation; the second skipped ``-m`` as "a filter, not a collection rule",
which would have credited a file in full under ``-m "not integration"`` while
nothing in it ran.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_test_discovery as ctd  # noqa: E402


# ── Reading an invocation ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("pytest tests/", ["tests/"]),
        ("python -m pytest tests/ -q", ["tests/", "-q"]),
        ("python3 -m pytest tests/ --tb=short", ["tests/", "--tb=short"]),
        ("python3.11 -m pytest tests/", ["tests/"]),
        ("PYTHONPATH=. python -m pytest tests/", ["tests/"]),
        ("PYTHONPATH=src FOO=1 python3 -m pytest tests/", ["tests/"]),
        ("poetry run pytest tests/", ["tests/"]),
        ("uv run pytest tests/", ["tests/"]),
    ],
)
def test_an_invocation_is_recognised_however_it_is_spelled(command, expected):
    assert ctd._args_after_pytest(shlex.split(command)) == expected


@pytest.mark.parametrize(
    "command",
    [
        "pip install pytest pytest-asyncio",
        "python3 -m pip install --quiet pytest",
        "ruff check services/",
        "echo pytest tests/",
        "npm test",
    ],
)
def test_something_that_is_not_a_pytest_run_is_not_credited(command):
    """A ``pip install ... pytest`` line has no path argument.

    Read as an invocation it looks like a bare collection of the whole
    repository, which would credit every test file in the tree to a step that
    installs a package. An over-broad resolver manufactures exactly the
    coverage this gate exists to disprove.
    """
    assert ctd._args_after_pytest(shlex.split(command)) is None


@pytest.mark.parametrize(
    ("args", "paths", "ignores", "markers"),
    [
        (["tests/"], ["tests/"], [], ""),
        (["tests/", "--ignore=tests/isolation"], ["tests/"], ["tests/isolation"], ""),
        (["tests/", "--ignore", "tests/isolation"], ["tests/"], ["tests/isolation"], ""),
        (["tests/", "-k", "not_slow"], ["tests/"], [], ""),
        (["tests/", "-m", "not integration"], ["tests/"], [], "not integration"),
        (["tests/", "--cov=app", "--cov-config=pyproject.toml"], ["tests/"], [], ""),
        (["tests/a.py", "tests/b.py", "-v"], ["tests/a.py", "tests/b.py"], [], ""),
    ],
)
def test_arguments_are_split_into_paths_ignores_and_markers(args, paths, ignores, markers):
    assert ctd._split_args(args) == (paths, ignores, markers)


# ── Following `cd` ───────────────────────────────────────────────────────────
def test_a_cd_inside_a_run_block_moves_the_resolver():
    """The agents invocation ``cd``s into the service, then names ``tests/``.

    Resolving that against the repository root reported all 82 agents files
    unreached and credited the root ``tests/`` tree with the package's
    invocation — the same defect in both directions at once.
    """
    assert ctd._cd_target("cd services/agents", "") == "services/agents"
    assert ctd._cd_target("cd packages/aisoc-benchmark", "") == "packages/aisoc-benchmark"


def test_cd_composes_and_unwinds():
    assert ctd._cd_target("cd tests", "services/agents") == "services/agents/tests"
    assert ctd._cd_target("cd ..", "services/agents") == "services"


def test_a_cd_to_an_unexpanded_variable_does_not_move_the_resolver():
    """Guessing would send every path after it somewhere arbitrary.

    They would then all read as missing, which is a finding the tree did not
    cause.
    """
    assert ctd._cd_target("cd $GITHUB_WORKSPACE", "services/agents") == "services/agents"


@pytest.mark.parametrize("command", ["pytest tests/", "cd", "cdrom --help", "echo cd services"])
def test_something_that_is_not_a_cd_is_not_read_as_one(command):
    assert ctd._cd_target(command, "") is None


# ── Marker deselection ───────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("expression", "markers", "deselected"),
    [
        ("not integration", {"integration"}, True),
        ("not integration", set(), False),
        ("integration", {"integration"}, False),
        ("integration", set(), True),
        ("not a and not b", {"b"}, True),
        ("not a and not b", {"c"}, False),
        ("", {"integration"}, False),
    ],
)
def test_a_marker_expression_is_evaluated_not_matched_as_text(expression, markers, deselected):
    """``not integration`` and ``integration`` differ by three characters.

    They invert the answer, so a gate matching the marker name as a substring
    would credit precisely the files nothing runs.
    """
    assert ctd.deselects_module(expression, frozenset(markers)) is deselected


def test_an_expression_that_cannot_be_evaluated_credits_the_file():
    """The reading that can only miss a finding, never invent one."""
    assert ctd.deselects_module("not and or", frozenset({"integration"})) is False


def test_a_module_level_pytestmark_is_read_off_the_syntax_tree(tmp_path):
    module = tmp_path / "test_x.py"
    module.write_text("import pytest\npytestmark = pytest.mark.integration\n")

    assert ctd.module_markers(module) == frozenset({"integration"})


def test_a_marker_on_a_single_test_does_not_mark_the_module(tmp_path):
    """One deselected test is not a file nothing runs, and this gate is about files."""
    module = tmp_path / "test_x.py"
    module.write_text("import pytest\n\n\n@pytest.mark.integration\ndef test_one():\n    pass\n")

    assert ctd.module_markers(module) == frozenset()


def test_a_list_of_pytestmarks_is_read(tmp_path):
    module = tmp_path / "test_x.py"
    module.write_text("import pytest\npytestmark = [pytest.mark.integration, pytest.mark.slow]\n")

    assert ctd.module_markers(module) == frozenset({"integration", "slow"})


# ── The corpus ───────────────────────────────────────────────────────────────
def test_the_corpus_is_what_git_tracks(tmp_path):
    """An untracked install directory is not this repository's tests.

    Deriving the corpus from git removes the exclusion list a filesystem walk
    needs — and a list of ephemeral directory names cannot be checked in both
    directions, because on a clean checkout none of them exist. The first
    version of this gate carried one and failed on its own repository.
    """
    for rel in ("services/x/tests/test_a.py", "services/x/tests/helper.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")
    (tmp_path / "node_modules/p/tests").mkdir(parents=True)
    (tmp_path / "node_modules/p/tests/test_vendor.py").write_text("")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@invalid", "-c", "commit.gpgsign=false"]
    for argv in (["init", "-q", "-b", "main"], ["add", "services"], ["commit", "-qm", "t"]):
        subprocess.run(git + argv, cwd=tmp_path, check=True, capture_output=True)  # noqa: S603

    files = [f for tree in ctd.discover_trees(tmp_path) for f in tree.files]

    assert files == ["services/x/tests/test_a.py"]


def test_a_test_shaped_file_in_no_tests_directory_is_still_in_the_corpus(tmp_path):
    """``scripts/integration/spine_test.py`` is one.

    Scoping the scan to ``tests/`` directories would make it invisible, which
    is the defect this gate removes, one level up. It gets its own pseudo-tree
    and is reached by a workflow executing it directly.
    """
    (tmp_path / "scripts/integration").mkdir(parents=True)
    (tmp_path / "scripts/integration/spine_test.py").write_text("")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@invalid", "-c", "commit.gpgsign=false"]
    for argv in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-qm", "t"]):
        subprocess.run(git + argv, cwd=tmp_path, check=True, capture_output=True)  # noqa: S603

    trees = ctd.discover_trees(tmp_path)

    assert [t.name for t in trees] == [ctd.LOOSE]
    assert trees[0].files == ["scripts/integration/spine_test.py"]


def test_conftest_collect_ignore_removes_a_file_from_reach(tmp_path):
    """A file pytest is told not to collect is not reached, however it is named."""
    tests = tmp_path / "services/x/tests"
    tests.mkdir(parents=True)
    (tests / "test_a.py").write_text("")
    (tests / "conftest.py").write_text('collect_ignore = ["test_a.py"]\n')

    assert ctd.collect_ignored(tests, tmp_path) == {"services/x/tests/test_a.py"}


def test_a_tree_that_renames_python_files_is_scanned_for_its_own_pattern(tmp_path):
    """Scanning for the default in a tree that renamed it finds nothing, and
    a tree with nothing to find reads as fully covered."""
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\npython_files = ["check_*.py"]\n')

    assert ctd.python_files_patterns(tmp_path) == ("check_*.py",)
    assert ctd.python_files_patterns(tmp_path / "nothing-here") == ctd.DEFAULT_PYTHON_FILES


# ── The verdict ──────────────────────────────────────────────────────────────
def _tree(files, reached, name="services/x"):
    tree = ctd.Tree(name=name, tests_dir=f"{name}/tests", files=list(files))
    tree.reached = set(reached)
    return tree


def _codes(trees, missing=(), *, quarantine=None):
    return {code for code, _detail in ctd.evaluate(trees, missing, quarantine=quarantine or {})}


def test_a_file_no_invocation_reaches_is_a_finding():
    one = ["services/x/tests/test_a.py"]

    assert "unreached" in _codes([_tree([*one, "services/x/tests/test_b.py"], one)])


def test_an_invocation_naming_a_file_that_is_gone_is_a_finding():
    """The other direction. A step listing a deleted path no longer does what
    it reads as doing, and this repository has shipped that shape repeatedly."""
    one = ["services/x/tests/test_a.py"]
    missing = [("ci.yml", "pytest tests/test_gone.py", "services/x/tests/test_gone.py")]

    assert "names-nothing" in _codes([_tree(one, one)], missing)


def test_quarantine_excuses_a_file_and_is_checked_in_both_directions():
    files = ["services/x/tests/test_a.py", "services/x/tests/test_b.py"]
    reached = files[:1]

    assert not _codes([_tree(files, reached)], quarantine={files[1]: "needs a live Neo4j and Kafka"})
    assert "quarantine-unexplained" in _codes([_tree(files, reached)], quarantine={files[1]: "  "})
    assert "quarantine-names-nothing" in _codes([_tree(files, reached)], quarantine={"services/x/tests/test_ghost.py": "gone"})
    assert "quarantine-stale" in _codes([_tree(files, reached)], quarantine={files[0]: "but CI runs it now"})


# ── The real tree ────────────────────────────────────────────────────────────
def test_every_quarantine_entry_carries_a_real_justification():
    for path, reason in ctd.QUARANTINE.items():
        assert len(reason.split()) >= 10, f"{path}: a one-line reason is not a justification"


def test_the_scan_finds_the_trees_this_repository_actually_has():
    """A parser that silently stopped resolving anything would report a clean
    tree, so the counts themselves are asserted."""
    trees, invocations, _missing = ctd.scan(REPO_ROOT)

    assert len(invocations) > 20, "the workflow surface runs far more than this"
    names = {t.name for t in trees}
    for expected in ("services/agents", "services/api", "services/connectors", "scripts", "."):
        assert expected in names, f"{expected} ships tests and must appear as a tree"


def test_the_agents_suite_is_reached_as_a_directory_not_as_a_list():
    """The regression this gate was built for. 26 of 82 files, named one per
    line, and adding a 83rd would have been silently free of signal."""
    trees, _invocations, _missing = ctd.scan(REPO_ROOT)
    agents = next(t for t in trees if t.name == "services/agents")

    assert agents.unreached == [], f"unreached agents tests: {agents.unreached}"
    assert len(agents.files) > 80


def test_the_self_test_catches_every_defect_it_claims_to():
    assert ctd.self_test() == 0
