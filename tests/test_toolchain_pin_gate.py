"""Unit tests for `scripts/check_toolchain_pins.py`.

`--self-test` proves the gate detects drift end to end by building throwaway
repositories. These tests cover the parts a fixture exercises only
incidentally: the normalisers, and the parser behaviours that were each a
real bug in this gate or its predecessor before they were a test.

The parser cases matter most. Every one of them is a shape that was present
in the tree and invisible: a Node version behind an ARG, a Go module selected
by a matrix expression, an install command inside a shell error message, a
`--frozen-lockfile=false` that a substring test reads as enabled.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "check_toolchain_pins", Path(__file__).resolve().parent.parent / "scripts" / "check_toolchain_pins.py"
)
assert _SPEC and _SPEC.loader
gate = importlib.util.module_from_spec(_SPEC)
sys.modules["check_toolchain_pins"] = gate
_SPEC.loader.exec_module(gate)


# ── Version normalisation ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("22", "22"),
        ("'22'", "22"),
        ("22-alpine", "22"),
        ("1.26", "1.26"),
        ("1.26-alpine", "1.26"),
        ("3.11-slim", "3.11"),
        ("8.15.1", "8.15"),
    ],
)
def test_normalise_version_reduces_to_the_precision_that_is_pinned(raw, expected):
    assert gate.normalise_version(raw) == expected


@pytest.mark.parametrize(
    ("floor", "toolchain", "ok"),
    [
        ("1.26", "1.26", True),
        ("1.26", "1.27", True),
        ("1.28", "1.26", False),
        ("20.0.0", "22", True),
        ("22.0.0", "20", False),
        ("3.11", "3.12", True),
    ],
)
def test_at_most_compares_a_floor_against_an_installed_toolchain(floor, toolchain, ok):
    assert gate.at_most(floor, toolchain) is ok


def test_normalise_version_pads_unequal_precision():
    """`22` and `22.0.0` are one version; a floor must not fail on the shape."""
    assert gate.at_most("22.0.0", "22")
    assert gate.at_most("22", "22.0.0")


# ── Install-command parsing ──────────────────────────────────────────────────


def test_frozen_lockfile_equals_false_is_not_locked():
    """The devcontainer's real spelling.

    `"--frozen-lockfile" in command` reads `--frozen-lockfile=false` as
    enabling the flag it disables, so the one install path that opted out
    counted as locked.
    """
    (install,) = gate._install_commands("RUN pnpm install --frozen-lockfile=false", "Dockerfile", "")
    assert install.locked is False


def test_no_frozen_lockfile_is_not_locked():
    (install,) = gate._install_commands("RUN pnpm install --no-frozen-lockfile", "Dockerfile", "")
    assert install.locked is False


def test_frozen_lockfile_is_locked():
    (install,) = gate._install_commands("RUN pnpm install --frozen-lockfile", "Dockerfile", "")
    assert install.locked is True


def test_pnpm_install_is_not_read_as_an_npm_install():
    """`pnpm` ends in `npm`.

    Without a left word boundary the npm pattern matches inside every pnpm
    command, so each one was reported twice — once correctly and once as an
    unlocked npm install that does not exist anywhere in the repository.
    """
    installs = gate._install_commands("RUN pnpm install --frozen-lockfile", "Dockerfile", "")
    assert [i.tool for i in installs] == ["pnpm"]


def test_npm_ci_is_locked_and_npm_install_is_not():
    locked = gate._install_commands("RUN npm ci --omit=dev", "Dockerfile", "")
    unlocked = gate._install_commands("RUN npm install", "Dockerfile", "")
    assert [(i.tool, i.locked) for i in locked] == [("npm", True)]
    assert [(i.tool, i.locked) for i in unlocked] == [("npm", False)]


def test_global_tool_installs_are_not_project_installs():
    assert gate._install_commands("RUN npm install -g pnpm@8.15.1", "Dockerfile", "") == []
    assert gate._install_commands("RUN npm install --global corepack", "Dockerfile", "") == []


def test_install_commands_inside_shell_messages_are_not_install_paths():
    """`install.sh` says `die "pnpm install failed."`.

    Read literally that is an install path, and so are the two other messages
    around it. Quoted text in a shell source is an argument.
    """
    text = 'info "Installing deps (pnpm install)..."\npnpm install --frozen-lockfile\ndie "pnpm install failed."\n'
    installs = gate._install_commands(text, "install.sh", "", shell_source=True)
    assert [i.raw for i in installs] == ["pnpm install --frozen-lockfile"]


def test_a_multi_line_shell_message_is_still_a_message():
    text = 'pnpm install --frozen-lockfile\ndie "pnpm install failed.\nTry again."\n'
    installs = gate._install_commands(text, "install.sh", "", shell_source=True)
    assert len(installs) == 1


def test_json_command_values_are_not_stripped_as_quotes():
    """The devcontainer declares its install *as* a quoted JSON value.

    Stripping quotes there would delete the install path being searched for,
    which is the blind spot the quote-stripping exists to avoid creating.
    """
    text = '{"onCreateCommand": "pnpm install --frozen-lockfile"}'
    assert len(gate._install_commands(text, ".devcontainer/devcontainer.json", "")) == 1


def test_a_folded_run_scalar_is_one_command():
    """The syntax that hid a whole dependency set from the dependency gate."""
    text = "jobs:\n  a:\n    steps:\n      - run: >-\n          pnpm install\n          --prefer-offline\n"
    installs = gate._install_commands(text, ".github/workflows/x.yml", "")
    assert len(installs) == 1
    assert installs[0].locked is False


def test_comment_lines_are_not_commands():
    text = "# RUN pnpm install --no-frozen-lockfile is what this used to do\nRUN pnpm install --frozen-lockfile\n"
    installs = gate._install_commands(text, "Dockerfile", "")
    assert [i.locked for i in installs] == [True]


# ── Matrix expansion ─────────────────────────────────────────────────────────


def test_matrix_expression_resolves_to_every_leg():
    """`cd services/${{ matrix.service }}` is three modules, not zero.

    A reader that skipped the expression reported five of six Go modules as
    compiled by nothing; one that matched every `cd services/<x>` reported
    five Python services as Go modules.
    """
    text = "    strategy:\n      matrix:\n        service: [enrichment, ingest, demo-producer]\n"
    matrix = gate._matrix_values(text)
    assert gate._expand("services/${{ matrix.service }}", matrix) == [
        "services/enrichment",
        "services/ingest",
        "services/demo-producer",
    ]


def test_an_unresolvable_expression_expands_to_nothing_rather_than_a_literal():
    assert gate._expand("services/${{ matrix.absent }}", {}) == []


def test_a_literal_path_needs_no_matrix():
    assert gate._expand("services/ingest", {}) == ["services/ingest"]


# ── Checks ───────────────────────────────────────────────────────────────────


def _scan_with(**kwargs) -> gate.Scan:
    scan = gate.Scan()
    for key, value in kwargs.items():
        setattr(scan, key, value)
    return scan


def test_engines_floor_is_not_treated_as_a_toolchain():
    """A published package's `engines` states what a consumer needs.

    `packages/aisoc-lite` supports Node 20 on purpose. Reading that as "this
    repository builds on 20" would force every published floor up to the
    build toolchain for no reason.
    """
    scan = _scan_with(
        pins=[
            gate.Pin("node", "22", ".github/workflows/ci.yml", "test", ""),
            gate.Pin("node", "22", "apps/web/Dockerfile", "ship", ""),
            gate.Pin("node", "18.17", "services/mcp/package.json", "floor", ""),
        ]
    )
    assert gate.check_runtime_agreement(scan) == []
    assert gate.check_floors(scan) == []


def test_a_floor_above_the_toolchain_fails():
    scan = _scan_with(
        pins=[
            gate.Pin("node", "20", "apps/web/Dockerfile", "ship", ""),
            gate.Pin("node", "22.0.0", "package.json", "floor", ""),
        ]
    )
    assert any("floor <= toolchain" in p for p in gate.check_floors(scan))


def test_ship_and_test_parity_runs_in_both_directions():
    behind = _scan_with(
        pins=[
            gate.Pin("node", "20", "apps/web/Dockerfile", "ship", ""),
            gate.Pin("node", "22", ".github/workflows/ci.yml", "test", ""),
        ]
    )
    problems = gate.check_ship_test_parity(behind)
    assert any("ship -> test" in p for p in problems)
    assert any("test -> ship" in p for p in problems)


def test_python_is_held_to_the_same_standard_as_go_and_node():
    """The exemption that let twenty-four workflows drift is gone.

    Python used to be excused from strict equality because its manifests
    declare a floor that permits both 3.11 and 3.12, so a workflow on 3.12
    violated nothing written down. That is exactly why the split survived:
    the gate agreed with it. A floor is what a *consumer* may use; it is not
    a licence for the project's own paths to disagree about what they run.
    """
    scan = _scan_with(
        pins=[
            gate.Pin("python", "3.11", "services/api/Dockerfile", "ship", ""),
            gate.Pin("python", "3.12", ".github/workflows/brand-new.yml", "test", ""),
        ],
        files=[".github/workflows/brand-new.yml"],
    )
    assert any("test -> ship" in p for p in gate.check_ship_test_parity(scan))
    assert any("`python` is pinned 2 different ways" in p for p in gate.check_runtime_agreement(scan))


def test_no_exemption_list_exists_for_the_python_split():
    """A split that can be recorded is a split that can grow.

    The previous design held a set of twenty-four workflow paths allowed to
    run another interpreter. Re-adding one would make the gate pass while
    the defect returned, so the absence of the escape hatch is asserted
    rather than left to convention.
    """
    assert not hasattr(gate, "PYTHON_INTERPRETER_SPLIT")


def test_two_shipped_python_interpreters_fail_outright():
    scan = _scan_with(
        pins=[
            gate.Pin("python", "3.11", "services/api/Dockerfile", "ship", ""),
            gate.Pin("python", "3.12", "services/fusion/Dockerfile", "ship", ""),
        ]
    )
    assert any("`python` is pinned 2 different ways" in p for p in gate.check_runtime_agreement(scan))


def test_static_tool_targets_are_compared_in_both_directions():
    """ruff's `target-version` and mypy's `python_version` install nothing.

    No other check in the gate reads them, and both decide what the tools
    believe: ruff rejects syntax newer than its target and mypy resolves the
    standard library for the version it is told. Pointed at an interpreter
    nothing ships, they are two more checks reasoning about software nobody
    runs.
    """
    stale_target = _scan_with(
        pins=[
            gate.Pin("python", "3.11", "services/api/Dockerfile", "ship", ""),
            gate.Pin("python", "3.12", "ruff.toml", "target", 'target-version = "py312"'),
        ]
    )
    assert any("target -> ship" in p for p in gate.check_python_tooling_target(stale_target))

    image_moved = _scan_with(
        pins=[
            gate.Pin("python", "3.13", "services/api/Dockerfile", "ship", ""),
            gate.Pin("python", "3.11", "ruff.toml", "target", 'target-version = "py311"'),
        ]
    )
    assert any("ship -> target" in p for p in gate.check_python_tooling_target(image_moved))


def test_pnpm_action_version_is_declared_not_voted_on():
    """A majority vote ratifies the drift it exists to catch.

    Flip enough workflows and the "correct" version becomes the new one.
    """
    scan = _scan_with(
        pnpm_actions=[("a.yml", "v4"), ("b.yml", "v4"), ("c.yml", gate.PNPM_ACTION_VERSION)],
        files=["a.yml", "b.yml", "c.yml"],
    )
    problems = gate.check_pnpm_actions(scan)
    assert len(problems) == 2
    assert all("v4" in p for p in problems)


def test_a_declared_pnpm_exemption_is_honoured():
    path = sorted(gate.PNPM_ACTION_EXEMPT)[0]
    scan = _scan_with(pnpm_actions=[(path, "v4"), ("c.yml", gate.PNPM_ACTION_VERSION)], files=[path, "c.yml"])
    assert gate.check_pnpm_actions(scan) == []


def test_a_pnpm_exemption_for_a_workflow_without_pnpm_has_rotted():
    path = sorted(gate.PNPM_ACTION_EXEMPT)[0]
    scan = _scan_with(pnpm_actions=[("c.yml", gate.PNPM_ACTION_VERSION)], files=[path, "c.yml"])
    assert any("rot" in p for p in gate.check_pnpm_actions(scan))


def test_every_declared_exemption_carries_a_reason():
    """An exemption without a reason is a hole with a comment next to it."""
    for registry in (gate.PNPM_ACTION_EXEMPT, gate.UNLOCKED_INSTALL_EXEMPT, gate.EXPECTED_ESBUILD):
        for key, reason in registry.items():
            assert isinstance(reason, str) and len(reason) > 20, key


def test_every_runtime_records_why_it_matters():
    for runtime, reason in gate.RUNTIMES.items():
        assert len(reason) > 40, runtime


# ── esbuild overrides ────────────────────────────────────────────────────────


def _write_workspace(root: Path, overrides: dict, resolved: list[str]) -> None:
    (root / "package.json").write_text(json.dumps({"pnpm": {"overrides": overrides}}), encoding="utf-8")
    (root / "pnpm-lock.yaml").write_text("\n".join(f"  /esbuild@{v}:" for v in resolved), encoding="utf-8")


def test_a_scoped_esbuild_override_is_allowed(tmp_path):
    _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, list(gate.EXPECTED_ESBUILD))
    assert gate.check_esbuild_overrides(tmp_path) == []


def test_a_workspace_wide_esbuild_override_fails(tmp_path):
    """Next bundles its own esbuild; replacing it broke Turbopack's font map."""
    _write_workspace(tmp_path, {"esbuild": "^0.28.1"}, list(gate.EXPECTED_ESBUILD))
    assert any("override scope" in p for p in gate.check_esbuild_overrides(tmp_path))


def test_a_moved_esbuild_resolution_fails(tmp_path):
    """A vite bump pulls esbuild through the scoped override with no esbuild in the diff."""
    _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, [*gate.EXPECTED_ESBUILD, "0.30.0"])
    assert any("0.30.0" in p for p in gate.check_esbuild_overrides(tmp_path))


def test_a_stale_expectation_fails(tmp_path):
    _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, [sorted(gate.EXPECTED_ESBUILD)[0]])
    assert any("stale" in p for p in gate.check_esbuild_overrides(tmp_path))


# ── The gate against this repository ─────────────────────────────────────────

REPO = Path(__file__).resolve().parent.parent


def test_the_gate_passes_on_this_repository():
    code, problems = gate.run(REPO)
    assert code == 0, problems


def test_the_gate_refuses_a_directory_that_is_not_the_repository(tmp_path):
    """One gate here resolved its root from its own file location and would
    have printed a confident OK about a tree it never opened."""
    code, problems = gate.run(tmp_path)
    assert code == 1
    assert "does not look like the AiSOC repository" in problems[0]


def test_the_scan_names_what_it_read():
    scanned = set(gate.scan(REPO).files)
    for expected in (
        ".github/workflows/ci.yml",
        "apps/web/Dockerfile",
        "services/realtime/Dockerfile",
        "services/ingest/go.mod",
        "package.json",
        "install.sh",
        ".devcontainer/devcontainer.json",
    ):
        assert expected in scanned, expected


def test_every_go_module_in_the_tree_is_scanned():
    found = {Path(f).parent.as_posix() for f in gate.scan(REPO).files if f.endswith("go.mod")}
    on_disk = {p.parent.relative_to(REPO).as_posix() for p in REPO.rglob("go.mod") if "node_modules" not in str(p)}
    assert found == {d for d in on_disk if not d.startswith("plans/")}


def test_self_test_covers_every_check_function():
    """A direction with no injection is a direction nobody has proved detects.

    Counted structurally rather than listed, so adding a `check_*` without a
    self-test case fails here instead of silently shipping untested.
    """
    checks = [n for n in dir(gate) if n.startswith("check_")]
    assert len(checks) >= 10
    source = (REPO / "scripts" / "check_toolchain_pins.py").read_text(encoding="utf-8")
    for name in checks:
        assert f"{name}(" in source.split("def run(")[1], f"{name} is never called by run()"
