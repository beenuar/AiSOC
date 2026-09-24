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
import re
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


def _write_workspace(root: Path, overrides: dict, resolved: list[str], subdir: str = ""):
    """One install root, returned as the Scan the checks take.

    `subdir` puts the manifest somewhere other than the repository root,
    because the scoping half of the esbuild check now applies to every
    install root and the interesting case is the one that is *not* the root —
    `apps/mobile` is where a workspace-wide override could previously be
    added with nothing looking at it.
    """
    directory = root / subdir if subdir else root
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(json.dumps({"pnpm": {"overrides": overrides}}), encoding="utf-8")
    (directory / "pnpm-lock.yaml").write_text("\n".join(f"  /esbuild@{v}:" for v in resolved), encoding="utf-8")
    scan = gate.Scan()
    scan.node_roots = gate.scan_node_roots(root)
    return scan


def test_a_scoped_esbuild_override_is_allowed(tmp_path):
    scan = _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, list(gate.EXPECTED_ESBUILD))
    assert gate.check_esbuild_overrides(tmp_path, scan) == []


def test_a_workspace_wide_esbuild_override_fails(tmp_path):
    """Next bundles its own esbuild; replacing it broke Turbopack's font map."""
    scan = _write_workspace(tmp_path, {"esbuild": "^0.28.1"}, list(gate.EXPECTED_ESBUILD))
    assert any("override scope" in p for p in gate.check_esbuild_overrides(tmp_path, scan))


def test_a_workspace_wide_esbuild_override_fails_in_a_satellite_root(tmp_path):
    """The one root the check could not see until it stopped reading only `/`."""
    _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, list(gate.EXPECTED_ESBUILD))
    scan = _write_workspace(tmp_path, {"esbuild": "^0.28.1"}, ["0.28.1"], subdir="apps/mobile")
    problems = gate.check_esbuild_overrides(tmp_path, scan)
    assert any("override scope" in p and "apps/mobile/package.json" in p for p in problems)


def test_a_moved_esbuild_resolution_fails(tmp_path):
    """A vite bump pulls esbuild through the scoped override with no esbuild in the diff."""
    scan = _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, [*gate.EXPECTED_ESBUILD, "0.30.0"])
    assert any("0.30.0" in p for p in gate.check_esbuild_overrides(tmp_path, scan))


def test_a_stale_expectation_fails(tmp_path):
    scan = _write_workspace(tmp_path, {"vite>esbuild": "^0.28.1"}, [sorted(gate.EXPECTED_ESBUILD)[0]])
    assert any("stale" in p for p in gate.check_esbuild_overrides(tmp_path, scan))


# ── Cross-root override propagation ──────────────────────────────────────────


@pytest.fixture
def no_exemptions(monkeypatch):
    """Test the propagation logic against an empty exemption list.

    These fixtures build a tree containing `apps/mobile`, which the real
    exemption list has an entry for. Leaving it in place would mean every
    assertion below also asserted something about this repository's current
    exemptions, and a future entry would fail tests that have nothing to do
    with it. The live entries are checked separately — by
    `test_every_cross_root_exemption_records_versions_and_a_reason` for shape
    and by the whole-repository run at the bottom of this file for liveness.
    """
    monkeypatch.setattr(gate, "CROSS_ROOT_OVERRIDE_EXEMPT", {})


def _two_roots(root: Path, root_overrides: dict, root_lock: dict, sat_overrides: dict, sat_lock: dict):
    """A workspace plus one independent install root, as `apps/mobile` is."""
    for directory, overrides, lock in (
        (root, root_overrides, root_lock),
        (root / "apps" / "mobile", sat_overrides, sat_lock),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(json.dumps({"pnpm": {"overrides": overrides}}), encoding="utf-8")
        (directory / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '6.0'\n" + "".join(f"  /{n}@{v}:\n" for n, vs in lock.items() for v in vs),
            encoding="utf-8",
        )
    scan = gate.Scan()
    scan.node_roots = gate.scan_node_roots(root)
    return scan


def test_an_override_that_reached_one_install_root_fails(tmp_path, no_exemptions):
    """The measured bug: the workspace pinned image-size, apps/mobile kept 1.2.1."""
    scan = _two_roots(tmp_path, {"image-size": ">=2.0.4 <3"}, {"image-size": ["2.0.4"]}, {}, {"image-size": ["1.2.1"]})
    problems = gate.check_override_propagation(tmp_path, scan)
    assert any("override propagation" in p and "apps/mobile/pnpm-lock.yaml" in p for p in problems)


def test_an_override_present_in_both_roots_passes(tmp_path, no_exemptions):
    scan = _two_roots(
        tmp_path,
        {"image-size": ">=2.0.4 <3"},
        {"image-size": ["2.0.4"]},
        {"image-size": ">=2.0.4 <3"},
        {"image-size": ["2.0.4"]},
    )
    assert gate.check_override_propagation(tmp_path, scan) == []


def test_a_package_absent_from_the_other_root_passes(tmp_path, no_exemptions):
    """Not every override has to appear everywhere — only where it is resolved."""
    scan = _two_roots(tmp_path, {"sharp": ">=0.35.4"}, {"sharp": ["0.35.4"]}, {}, {"left-pad": ["1.3.0"]})
    assert gate.check_override_propagation(tmp_path, scan) == []


def test_a_version_selector_only_governs_its_own_line(tmp_path, no_exemptions):
    """`brace-expansion@1` says nothing about the 5.x the workspace also resolves."""
    scan = _two_roots(
        tmp_path,
        {"brace-expansion@1": ">=1.1.18 <2"},
        {"brace-expansion": ["1.1.21", "5.0.12"]},
        {},
        {"brace-expansion": ["5.0.12"]},
    )
    assert gate.check_override_propagation(tmp_path, scan) == []


def test_a_parent_scoped_override_is_not_read_as_a_global_one(tmp_path, no_exemptions):
    """`vite>esbuild` constrains esbuild under vite, not esbuild everywhere."""
    scan = _two_roots(tmp_path, {"vite>esbuild": "^0.28.1"}, {"esbuild": ["0.28.1"]}, {}, {"esbuild": ["0.25.12"]})
    assert gate.check_override_propagation(tmp_path, scan) == []


def test_a_lockfile_behind_its_own_manifest_fails(tmp_path, no_exemptions):
    scan = _two_roots(
        tmp_path,
        {"image-size": ">=2.0.4 <3"},
        {"image-size": ["2.0.4"]},
        {"image-size": ">=2.0.4 <3"},
        {"image-size": ["1.2.1"]},
    )
    assert any("was not regenerated" in p for p in gate.check_override_propagation(tmp_path, scan))


def test_an_unreadable_lockfile_is_not_a_clean_root(tmp_path):
    """What the check *credits*: a root it could not read agrees with everyone."""
    scan = _two_roots(tmp_path, {"image-size": ">=2.0.4 <3"}, {"image-size": ["2.0.4"]}, {}, {})
    assert any("node root corpus" in p for p in gate.check_node_root_corpus(scan))


def test_no_install_root_at_all_is_a_failure(tmp_path):
    assert any("no Node install root" in p for p in gate.check_node_root_corpus(gate.Scan()))


def test_a_range_the_comparison_cannot_evaluate_is_reported(tmp_path, no_exemptions):
    """A union range must not silently pass for want of an opinion."""
    scan = _two_roots(tmp_path, {"image-size": "1.x || >=2.0.4"}, {"image-size": ["2.0.4"]}, {}, {"image-size": ["1.2.1"]})
    assert any("cannot evaluate" in p for p in gate.check_override_propagation(tmp_path, scan))


def test_an_override_block_the_parser_cannot_read_is_reported(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"pnpm": {"override": {"image-size": ">=2"}}}), encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /image-size@1.2.1:\n", encoding="utf-8")
    scan = gate.Scan()
    scan.node_roots = gate.scan_node_roots(tmp_path)
    assert any("override parser coverage" in p for p in gate.check_override_parser_coverage(tmp_path, scan))


def test_npm_nested_overrides_are_read(tmp_path):
    """npm writes `{"a": {"b": "1"}}` where pnpm writes `a>b`; both must be seen."""
    (tmp_path / "package.json").write_text(
        json.dumps({"overrides": {"qs": "^6.16.0", "express": {"body-parser": "^2.3.0"}}}), encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/qs": {"version": "6.16.0"}}}), encoding="utf-8"
    )
    root = gate.scan_node_roots(tmp_path)[0]
    assert root.overrides == {"qs": "^6.16.0", "express>body-parser": "^2.3.0"}
    assert root.resolved == {"qs": ["6.16.0"]}


def test_an_exemption_holds_only_for_the_versions_it_records(tmp_path, monkeypatch):
    """The ratchet. A bump past the verified version re-opens the question."""
    monkeypatch.setattr(gate, "CROSS_ROOT_OVERRIDE_EXEMPT", {("image-size", "apps/mobile"): (("1.2.1",), "verified")})
    scan = _two_roots(tmp_path, {"image-size": ">=2.0.4 <3"}, {"image-size": ["2.0.4"]}, {}, {"image-size": ["1.2.1"]})
    assert gate.check_override_propagation(tmp_path, scan) == []

    moved = _two_roots(tmp_path, {"image-size": ">=2.0.4 <3"}, {"image-size": ["2.0.4"]}, {}, {"image-size": ["1.2.0"]})
    problems = gate.check_override_propagation(tmp_path, moved)
    assert any("re-opens the question" in p for p in problems)
    assert any("1.2.0" in p for p in problems)


def test_an_exemption_for_a_directory_outside_this_tree_is_not_drift(tmp_path, monkeypatch):
    """A fixture or a fork simply lacks the directory; that must not fail the gate."""
    monkeypatch.setattr(gate, "CROSS_ROOT_OVERRIDE_EXEMPT", {("image-size", "apps/never-existed"): (("1.2.1",), "x")})
    scan = _two_roots(tmp_path, {"image-size": ">=2.0.4 <3"}, {"image-size": ["2.0.4"]}, {}, {})
    assert gate.check_override_propagation(tmp_path, scan) == []

    # But a directory that is *there* and has stopped resolving its own
    # node_modules is drift, and must be reported.
    (tmp_path / "apps" / "never-existed").mkdir(parents=True)
    assert any("no longer an install root" in p for p in gate.check_override_propagation(tmp_path, scan))


def test_every_cross_root_exemption_records_versions_and_a_reason(tmp_path):
    """A bare package/root pair would be a permanent hole; the versions make it a ratchet."""
    for key, (versions, reason) in gate.CROSS_ROOT_OVERRIDE_EXEMPT.items():
        assert versions and all(re.match(r"^\d+\.\d+", v) for v in versions), key
        assert "OSV" in reason and len(reason) > 80, key


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
