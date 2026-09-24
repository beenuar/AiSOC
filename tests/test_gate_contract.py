"""A gate is only worth the tree it opened.

``scripts/check_gate_contract.py`` runs every wired check inside a git
repository holding nothing but ``scripts/`` and requires each one to refuse.
The one-off version of that probe found five gates reporting OK over a
repository containing no content — among them the detection validator behind
the rule count on the front page, and a self-link checker written to replace
a link run that accepted HTTP 403 as healthy, which had inherited the same
inability in a different costume.

These tests pin the parts of that gate a reviewer cannot see by reading its
output: how it decides what to run, and how it reads the result. Both are
places where a gate quietly hands out credit.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_gate_contract as cgc  # noqa: E402
import gate_toolkit  # noqa: E402

SUPPLIED = frozenset({"app", "detection_specs"})


# ── Reading the result ───────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("status", "output", "expected"),
    [
        (0, "OK: 0 published Go module path(s)", cgc.PASSED),
        (1, "ERROR: detections/ directory not found", cgc.REFUSED),
        (2, "refusing to report a result for a tree I did not open", cgc.REFUSED),
        (None, "", cgc.INCONCLUSIVE),
    ],
)
def test_exit_status_is_read_for_what_it_means(status, output, expected):
    assert cgc.classify(status, output, SUPPLIED)[0] == expected


def test_an_argparse_error_is_not_evidence_of_anything():
    """Exit 2 with a usage block means the tree was never opened.

    Counting it as a refusal would let the probe credit a failure it did not
    cause — the same shape as the gates it exists to find, one level up.
    """
    output = "usage: x [-h] --old OLD\nx: error: the following arguments are required: --old"

    assert cgc.classify(2, output, SUPPLIED)[0] == cgc.INCONCLUSIVE


def test_a_missing_third_party_module_is_the_environment_not_the_tree():
    output = "ModuleNotFoundError: No module named 'structlog'"

    assert cgc.classify(1, output, SUPPLIED)[0] == cgc.INCONCLUSIVE


def test_a_missing_repository_package_is_the_empty_tree_working():
    """``app`` is the package under ``services/``; its absence *is* the point."""
    output = "ModuleNotFoundError: No module named 'app'"

    assert cgc.classify(1, output, SUPPLIED)[0] == cgc.REFUSED


def test_the_supplied_set_is_read_from_the_repository():
    supplied = cgc.importable_names(REPO_ROOT)

    assert "app" in supplied, "services/*/app is a package this repository supplies"
    assert "structlog" not in supplied, "a third-party dependency must not read as repository-supplied"


# ── Choosing what to run ─────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("python3 scripts/x.py --check", ["--check"]),
        ("python scripts/x.py", []),
        ("FOO=1 BAR=2 python3 scripts/x.py --strict", ["--strict"]),
        ("env FOO=1 python3 scripts/x.py --strict", ["--strict"]),
        ("uv run python scripts/x.py --check", ["--check"]),
        ("poetry run python3 scripts/x.py", []),
        ("python3 ../../scripts/x.py --check", ["--check"]),
    ],
)
def test_an_invocation_is_recognised_however_it_is_spelled(command, expected):
    assert cgc._argv_after(shlex.split(command), "x.py") == expected


@pytest.mark.parametrize(
    "command",
    [
        'echo "scripts/x.py --check"',
        "echo scripts/x.py",
        "python3 -m pytest scripts/x.py",
        "cat scripts/x.py",
        "ruff check scripts/x.py",
    ],
)
def test_a_path_that_is_not_being_executed_is_not_an_invocation(command):
    """A quoted path inside an ``echo`` is the shape that manufactures coverage.

    Another gate in this tree matched a path inside a quoted shell string and
    reported eleven services as CI-covered on the strength of it.
    """
    assert cgc._argv_after(shlex.split(command), "x.py") is None


@pytest.mark.parametrize(
    ("args", "replayable"),
    [
        (["--check"], True),
        (["--new", "docs/openapi.yaml"], True),
        (["--root", "$GITHUB_WORKSPACE"], False),
        (["--old", "/tmp/base-openapi.yaml"], False),
    ],
)
def test_only_arguments_that_test_the_tree_are_replayed(args, replayable):
    assert cgc._replayable(args) is replayable


def test_a_generator_run_is_not_probed_when_the_script_also_declares_a_gate():
    """``build_marketplace.py`` writes the index; only ``--check`` compares it.

    Probing the writing half would report that producing an empty index over
    an empty tree is a gate crediting nothing — true of every generator, and
    nothing to do with the gate.
    """

    class _Surface:
        def texts(self):
            return [
                ("sync.yml", "", "python3 scripts/build_marketplace.py"),
                ("sync.yml", "", "python3 scripts/build_marketplace.py --check"),
            ]

    signals = {"verdict-flag": "--check"}

    assert cgc.ci_invocations(_Surface(), "build_marketplace.py", signals) == [["--check"]]
    assert [] in cgc.ci_invocations(_Surface(), "build_marketplace.py", {})


# ── The two static properties ────────────────────────────────────────────────
def test_a_root_taken_from_this_file_is_visible_in_the_syntax_tree():
    properties = cgc.static_properties("from pathlib import Path\nROOT = Path(__file__).resolve().parent.parent\n")

    assert properties["derives_root_from_file"]
    assert not properties["consults_git_for_root"]


def test_a_json_key_spelled_like_the_helper_is_not_a_call_to_it():
    """The first spelling of this matched ``repo_root`` anywhere in the text.

    ``check_gate_coverage.py`` emits ``"repo_root"`` as a JSON key, so a gate
    that rooted itself at ``__file__`` and never asked git read as compliant
    on the strength of a dictionary key in its own output.
    """
    source = 'from pathlib import Path\nROOT = Path(__file__).resolve().parent.parent\nprint({"repo_root": str(ROOT)})\n'

    assert not cgc.static_properties(source)["consults_git_for_root"]


def test_the_shared_resolver_counts_as_consulting_git():
    source = "from gate_toolkit import repo_root\nROOT = repo_root()\n"

    assert cgc.static_properties(source)["consults_git_for_root"]


def test_a_docstring_promising_a_self_test_is_not_a_self_test():
    """A promise nothing parses is the documentation form of a gate with no caller."""
    source = '"""Run with --self-test to prove it works."""\nimport sys\nsys.exit(0)\n'

    assert not cgc.static_properties(source)["declares_self_test"]


@pytest.mark.parametrize(
    "source",
    [
        'parser.add_argument("--self-test", action="store_true")',
        "parser.add_argument(SELF_TEST_FLAG, action='store_true')",
        "self_test_if_requested(__file__)",
    ],
)
def test_a_self_test_that_reaches_code_counts(source):
    assert cgc.static_properties(source)["declares_self_test"]


# ── The scratch tree ─────────────────────────────────────────────────────────
def test_the_scratch_tree_is_a_repository_with_nothing_but_scripts():
    with gate_toolkit.scratch_tree() as tree:
        assert sorted(p.name for p in tree.iterdir() if p.name != ".git") == ["scripts"]
        assert (tree / "scripts" / "check_gate_contract.py").is_file()
        for absent in ("services", "detections", "apps", "packages", "docs", ".github"):
            assert not (tree / absent).exists(), f"{absent} must not be reachable from the scratch tree"


def test_a_shared_self_test_asks_the_gate_for_a_verdict_not_a_bare_run(tmp_path):
    """The generator half of a generator-and-gate script is not the gate.

    ``build_marketplace.py`` with no arguments writes the index; only
    ``--check`` compares it. A self-test that ran the writing half would
    report every such script as crediting an empty tree, and the fix would
    have been to weaken the assertion rather than to ask the right question.
    """
    script = tmp_path / "check_thing.py"
    script.write_text('import argparse\np = argparse.ArgumentParser()\np.add_argument("--check", action="store_true")\n')

    assert gate_toolkit.verdict_args(script) == ["--check"]
    assert gate_toolkit.verdict_args(tmp_path / "nothing_here.py") == []


def test_the_self_test_and_the_meta_gate_agree_on_what_a_verdict_looks_like():
    """One list, imported in both places. Two would drift on the first addition."""
    assert cgc.VERDICT_FLAG_PREFERENCE is gate_toolkit.VERDICT_FLAG_PREFERENCE
    assert cgc.declared_invocations({"verdict-flag": "--verify --check"})[0] == ["--check"]


def test_a_gate_in_the_scratch_tree_resolves_the_scratch_tree():
    """Otherwise the probe would be asking every gate about the real checkout."""
    with gate_toolkit.scratch_tree() as tree:
        status, output = gate_toolkit.run_in_scratch_tree("check_grafana_dashboards.py", tree=tree, timeout=60)

    assert status != 0
    assert str(tree) in output, "the gate must name the tree it actually read"
    assert str(REPO_ROOT) not in output


# ── The verdict ──────────────────────────────────────────────────────────────
def _probe(*dispositions: str, shape: str = gate_toolkit.BARE) -> dict[str, cgc.Probe]:
    runs = [cgc.Run(args=["--check"], source="test", shape=shape, disposition=d, why=d) for d in dispositions]
    return {"check_x.py": cgc.Probe(script="check_x.py", runs=runs)}


_CLEAN_PROPERTIES = {"check_x.py": {"derives_root_from_file": False, "consults_git_for_root": True, "declares_self_test": True}}


def _codes(probes, *, accepted=None, properties=None):
    return {
        code
        for code, _detail in cgc.evaluate(
            {"check_x.py": {"verdict-flag": "--check"}},
            probes,
            properties or _CLEAN_PROPERTIES,
            accepted=accepted or {},
            no_git_root={},
            no_self_test={},
        )
    }


def test_the_worst_invocation_decides_not_the_first():
    """Four subcommands under one name are four gates.

    ``security_audit.py`` runs as ``validate-ignores``, ``pnpm``, ``python``
    and ``go``. Three of them refused an empty tree while the others did not;
    excusing the set because one refused is how the rest stay hidden.
    """
    assert "passes-over-empty-tree" in _codes(_probe(cgc.REFUSED, cgc.PASSED))


def test_an_exception_is_checked_against_the_disposition_it_was_written_for():
    excused = {"check_x.py": {cgc.ANY_SHAPE: (cgc.INCONCLUSIVE, "its inputs are named on the command line")}}

    assert not _codes(_probe(cgc.INCONCLUSIVE), accepted=excused)
    assert "exception-stale" in _codes(_probe(cgc.PASSED), accepted=excused)
    assert "exception-stale" in _codes(_probe(cgc.REFUSED), accepted=excused)


def test_an_exception_naming_nothing_fails():
    assert "ratchet-names-nothing" in _codes(_probe(cgc.REFUSED), accepted={"check_gone.py": {cgc.ANY_SHAPE: (cgc.PASSED, "reason")}})


def test_an_exception_with_no_reason_fails():
    assert "ratchet-unexplained" in _codes(_probe(cgc.REFUSED), accepted={"check_x.py": {cgc.ANY_SHAPE: (cgc.REFUSED, "  ")}})


# ── The real tree ────────────────────────────────────────────────────────────
def test_every_recorded_exception_names_a_check_that_exists():
    """The cheap half of the both-directions check, without running the probe."""
    import check_gate_coverage as coverage  # noqa: PLC0415

    surface = coverage.Surface(REPO_ROOT)
    checks = set(coverage.collect_checks(REPO_ROOT, surface.gating))

    for name in (*cgc.EMPTY_TREE_EXCEPTIONS, *cgc.NO_GIT_ROOT, *cgc.NO_SELF_TEST):
        assert name in checks, f"{name} is excused but is not a check in the tree"


def test_every_recorded_exception_carries_a_disposition_the_gate_understands():
    for name, per_shape in cgc.EMPTY_TREE_EXCEPTIONS.items():
        assert per_shape, f"{name} is listed with no shape at all"
        for shape, (disposition, reason) in per_shape.items():
            assert shape == cgc.ANY_SHAPE or shape in gate_toolkit.TREE_SHAPES, f"{name}: unknown tree shape {shape!r}"
            assert disposition in {cgc.PASSED, cgc.REFUSED, cgc.INCONCLUSIVE}, name
            assert len(reason.split()) >= 10, f"{name}[{shape}]: a one-line reason is not a justification"


def test_a_shape_specific_exemption_does_not_cover_the_other_shape():
    """The reason the second tree shape is worth having, asserted rather than assumed.

    A gate can refuse a missing directory for a reason that says nothing
    about its corpus and then credit the same directory when it exists and is
    empty. An exemption written for one shape must not silently carry over.
    """
    excused = {"check_x.py": {gate_toolkit.SKELETON: (cgc.PASSED, "its corpus is not the directory in question at all")}}
    both = _probe(cgc.PASSED)
    both["check_x.py"].runs.append(
        cgc.Run(args=["--check"], source="test", shape=gate_toolkit.SKELETON, disposition=cgc.PASSED, why="exited 0")
    )
    assert "passes-over-empty-tree" in _codes(both, accepted=excused)


def test_the_skeleton_tree_has_the_directories_the_bare_one_omits():
    with gate_toolkit.scratch_tree(shape=gate_toolkit.SKELETON) as tree:
        assert (tree / "services").is_dir()
        assert (tree / "detections").is_dir()
        assert [p.name for p in (tree / "services").iterdir()] == [".gitkeep"]
    with gate_toolkit.scratch_tree(shape=gate_toolkit.BARE) as tree:
        assert not (tree / "services").exists()


def test_the_self_test_catches_every_defect_it_claims_to():
    assert cgc.self_test() == 0
