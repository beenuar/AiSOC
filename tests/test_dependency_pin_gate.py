"""Tests for `scripts/check_dependency_pins.py`.

A gate is only worth its runtime if it fails when the property it claims to
enforce is broken. Two failure shapes this repository has actually shipped are
guarded against here:

* a **one-directional** gate that compares A to B and never B to A, so drift in
  the direction things change slips past while the gate prints OK;
* a gate that resolves its repository root from its own file location and
  prints a confident OK about a tree it never opened.

So every test below injects drift into a throwaway tree and asserts the gate
both fails *and* names the right direction. The gate carries the same
injections in `--self-test`, which runs in CI; these tests additionally pin the
behaviour of the pieces (`normalise`, `satisfies`, the tokeniser) that decide
whether an injection is seen at all.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "check_dependency_pins.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_dependency_pins", GATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_dependency_pins"] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    gate._fixture(tmp_path)
    return tmp_path


# ── the gate passes on a clean tree, and on this repository ──────────────────


def test_clean_fixture_passes(tree: Path) -> None:
    code, problems = gate.run(tree)
    assert code == 0, problems


def test_this_repository_passes() -> None:
    code, problems = gate.run(REPO_ROOT)
    assert code == 0, problems


def test_the_scan_actually_opens_this_repository() -> None:
    """Guard against a gate that reports OK about nothing.

    The counts are lower bounds rather than exact numbers so adding a service
    does not fail this test, but they are high enough that an empty or
    mis-rooted scan cannot satisfy them.
    """
    scanned = gate.scan(REPO_ROOT)
    manifests = [f for f in scanned.files if f.endswith("pyproject.toml")]
    locks = [f for f in scanned.files if f.endswith("poetry.lock")]
    workflows = [f for f in scanned.files if f.startswith(".github/workflows/")]
    assert len(manifests) >= 13, manifests
    assert len(locks) >= 13, locks
    assert len(workflows) >= 40, len(workflows)
    assert "services/api/pyproject.toml" in scanned.files
    assert "services/api/poetry.lock" in scanned.files


def test_every_python_service_has_a_committed_lock() -> None:
    """No manifest may install by re-resolving at build time."""
    missing = [
        manifest.parent.name
        for manifest in sorted(REPO_ROOT.glob("services/*/pyproject.toml"))
        if not (manifest.parent / "poetry.lock").exists()
    ]
    assert not missing, f"services with no poetry.lock, so their images resolve afresh each build: {missing}"


# ── each direction, injected separately ──────────────────────────────────────


def test_detects_manifest_to_image_drift(tree: Path) -> None:
    dockerfile = tree / "services" / "demo" / "Dockerfile"
    dockerfile.write_text(dockerfile.read_text() + 'RUN pip install "fastapi>=0.111,<0.112"\n')
    code, problems = gate.run(tree)
    assert code == 1
    assert any("manifest -> image" in p for p in problems), problems


def test_detects_image_to_manifest_drift(tree: Path) -> None:
    """The reverse direction: the image installs something nothing declares."""
    dockerfile = tree / "services" / "demo" / "Dockerfile"
    dockerfile.write_text(dockerfile.read_text() + 'RUN pip install "requests>=2,<3"\n')
    code, problems = gate.run(tree)
    assert code == 1
    assert any("image -> manifest" in p for p in problems), problems


def test_detects_a_workflow_installing_a_different_range(tree: Path) -> None:
    workflow = tree / ".github" / "workflows" / "ci.yml"
    workflow.write_text(workflow.read_text().replace('"cryptography>=46,<51"', '"cryptography>=41,<46"'))
    code, problems = gate.run(tree)
    assert code == 1
    assert any("pinned 2 different ways" in p and "cryptography" in p for p in problems), problems


def test_detects_an_unbounded_install(tree: Path) -> None:
    workflow = tree / ".github" / "workflows" / "ci.yml"
    workflow.write_text(workflow.read_text().replace('"fastapi>=0.117,<0.142"', "fastapi"))
    code, problems = gate.run(tree)
    assert code == 1
    assert any("no version bound" in p for p in problems), problems


def test_detects_a_lock_outside_the_agreed_range(tree: Path) -> None:
    """The ranges can agree perfectly while the lock installs something else."""
    lock = tree / "services" / "demo" / "poetry.lock"
    lock.write_text(lock.read_text().replace('version = "0.141.1"', 'version = "0.111.1"'))
    code, problems = gate.run(tree)
    assert code == 1
    assert any("lock -> agreement" in p for p in problems), problems


def test_detects_an_install_path_the_scan_does_not_cover(tree: Path) -> None:
    extra = tree / "extra"
    extra.mkdir()
    (extra / "Dockerfile").write_text('FROM python:3.11-slim\nRUN pip install "fastapi>=0.111,<0.112"\n')
    code, problems = gate.run(tree)
    assert code == 1
    assert any("not an install path this gate scans" in p for p in problems), problems


def test_detects_drift_inside_a_folded_run_block(tree: Path) -> None:
    """`run: >-` is one shell command spread over many lines.

    A line-by-line reader finds `pip install` with nothing after it and
    extracts no packages, while still counting the file as scanned.
    `integration.yml` installs the whole API dependency set this way.
    """
    workflow = tree / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        workflow.read_text()
        + "      - run: >-\n          pip install --quiet\n          \"cryptography>=41,<46\" structlog\n"
    )
    code, problems = gate.run(tree)
    assert code == 1
    assert any("pinned 2 different ways" in p and "cryptography" in p for p in problems), problems


def test_detects_a_declaration_the_parser_cannot_read(tree: Path) -> None:
    """Scanned, counted, and contributing nothing.

    This is the shape of the bug this check found in the gate itself: poetry
    dev-group dependencies were never parsed, so `ruff` was reported as
    agreeing across seven files none of which had been read for it.
    """
    manifest = tree / "services" / "demo" / "pyproject.toml"
    manifest.write_text(manifest.read_text() + '\n[tool.uv]\ndev-dependencies = ["sqlglot>=27,<31"]\n')
    code, problems = gate.run(tree)
    assert code == 1
    assert any("parser extracted nothing" in p for p in problems), problems


def test_dev_group_dependencies_are_parsed() -> None:
    """`ruff` only ever appears in a dev group, and it is a gated package."""
    declarations = gate.scan(REPO_ROOT).by_package("ruff")
    manifests = {d.path for d in declarations if d.kind == "manifest"}
    assert "services/api/pyproject.toml" in manifests, sorted(manifests)
    assert len(manifests) >= 7, sorted(manifests)


def test_detects_a_matrix_leg_that_drifted_off_the_boundary(tree: Path) -> None:
    """An exempt matrix workflow still has to test the range in force."""
    (tree / ".github" / "workflows" / "reproducible-builds.yml").write_text(
        "name: Reproducible builds\njobs:\n  fastapi-range:\n    strategy:\n      matrix:\n"
        "        include:\n          - fastapi: '0.111.0'\n            label: floor\n"
    )
    code, problems = gate.run(tree)
    assert code == 1
    assert any("tests the floor at fastapi" in p for p in problems), problems


def test_refuses_a_directory_that_is_not_the_repository(tmp_path: Path) -> None:
    code, problems = gate.run(tmp_path)
    assert code == 1
    assert any("does not look like the AiSOC repository" in p for p in problems), problems


def test_self_test_subcommand_passes() -> None:
    assert gate.self_test() == 0


# ── the pieces that decide whether an injection is seen ──────────────────────


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (">=46,<51", ">=46.0.0,<51.0.0"),
        ("<51,>=46", ">=46,<51"),
        (">=0.117,<0.142", ">=0.117.0,<0.142.0"),
    ],
)
def test_normalise_treats_equivalent_ranges_as_equal(left: str, right: str) -> None:
    assert gate.normalise(left) == gate.normalise(right)


def test_normalise_keeps_genuinely_different_ranges_apart() -> None:
    assert gate.normalise(">=0.117,<0.142") != gate.normalise(">=0.111,<0.112")
    assert gate.normalise(">=46,<51") != gate.normalise(">=41,<46")


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("0.141.1", ">=0.117,<0.142", True),
        ("0.116.2", ">=0.117,<0.142", False),
        ("0.117.0", ">=0.117,<0.142", True),
        ("0.142.0", ">=0.117,<0.142", False),
        ("26.33.0", ">=23,<27", True),
        ("27.0.0", ">=23,<27", False),
        ("50.0.1", ">=46,<51", True),
    ],
)
def test_satisfies(version: str, spec: str, expected: bool) -> None:
    assert gate.satisfies(version, spec) is expected


def test_satisfies_refuses_an_operator_it_cannot_reason_about() -> None:
    """An unparseable bound must not read as a pass."""
    assert gate.satisfies("2.0.0", "^2.0") is False


def test_tokeniser_ignores_prose_and_stops_at_shell_operators() -> None:
    """Comments discussing `pip install`, and `&&`-chained commands.

    The first version of the tokeniser folded continuations before dropping
    comments and reported that a Dockerfile installed packages named `that`,
    `was` and `a`; it also read `poetry config virtualenvs.create false` as
    three more.
    """
    text = (
        "# The hand-written `pip install` list it replaces existed at all\n"
        "# because that list was a second copy of the manifest.\n"
        "RUN pip install --no-cache-dir poetry==2.4.1 \\\n"
        "    && poetry config virtualenvs.create false\n"
        'RUN pip install "fastapi>=0.117,<0.142"\n'
    )
    tokens = [gate._requirement(token) for token, _raw in gate._pip_install_tokens(text)]
    found = {name for name, _spec in tokens if name}
    assert found == {"poetry", "fastapi"}, found
