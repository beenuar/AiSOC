"""Tests for the competitor-naming gate, `scripts/check_competitor_names.py`.

The property worth asserting is not "does the tree happen to be clean today" but
"would this gate still notice if it stopped being clean". A check that only ever
sees good input cannot distinguish a working regex from a dead one, and reports
OK forever either way — the dominant failure shape in this repository.

So every assertion here is paired. The gate must catch a competitor name *and*
leave an integration reference alone; it must reject a stale allow-list entry
*and* accept a live one; it must fail when a comparison-table marker drifts *and*
pass when the region is found. `Torq` gets its own test because it is the one
name that is simultaneously a competitor in a comparison matrix and a shipped
first-party connector, so getting it wrong in either direction is a real bug:
flag the connector and the build breaks, miss the comparison and the rule is
unenforced.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_competitor_names.py"
_CONFIG = _REPO / "scripts" / "competitor_names.toml"
_FIXTURES = _REPO / "scripts" / "competitor_fixtures.json"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_competitor_names", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: @dataclass resolves `cls.__module__` through
    # sys.modules, and raises AttributeError if the module is not there yet.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()
CONFIG = gate.load_config(_CONFIG)
CORPUS = json.loads(_FIXTURES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def tree_report():
    """One full scan of the real tree, shared by the tests that need it."""
    return gate.scan_tree(_REPO, CONFIG, _CONFIG)


# --------------------------------------------------------------------------
# The gate detects a known-bad sample and passes a known-good one.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", CORPUS["bad"], ids=lambda c: c["competitor"])
def test_known_bad_is_caught(case):
    found = gate.scan_text(case["path"], case["text"], CONFIG.competitors, excused=set())
    assert case["competitor"] in {f.competitor for f in found}, f"the gate missed a competitor reference it must catch: {case['text']!r}"


@pytest.mark.parametrize("case", CORPUS["good"], ids=lambda c: c["path"])
def test_known_good_is_not_flagged(case):
    excused = gate.excused_names(case["path"], CONFIG.allows)
    found = gate.scan_text(case["path"], case["text"], CONFIG.competitors, excused)
    assert not found, (
        f"the gate flagged an integration reference ({case['why']}): " f"{case['text']!r} matched {sorted({f.competitor for f in found})}"
    )


def test_every_declared_competitor_has_a_bad_fixture():
    """A name with no fixture is never exercised, so it can rot into a no-op."""
    declared = {c.name for c in CONFIG.competitors}
    covered = {case["competitor"] for case in CORPUS["bad"]}
    assert declared <= covered, f"declared competitors with no known-bad fixture: {sorted(declared - covered)}"


def test_torq_is_a_competitor_in_prose_and_an_integration_in_its_connector():
    """The dual-role name, asserted in both directions at once."""
    competitive = gate.scan_text(
        "plans/example.md",
        "Torq requires playbook authors; AiSOC requires none.",
        CONFIG.competitors,
        excused=gate.excused_names("plans/example.md", CONFIG.allows),
    )
    assert "Torq" in {f.competitor for f in competitive}

    for integration_path in (
        "services/connectors/app/connectors/torq.py",
        "plugins/torq/plugin.yaml",
        "apps/docs/docs/connectors/torq.md",
        "services/connectors/tests/connectors/test_torq.py",
    ):
        excused = gate.excused_names(integration_path, CONFIG.allows)
        found = gate.scan_text(integration_path, "label: Torq", CONFIG.competitors, excused)
        assert not found, f"the Torq connector surface {integration_path} must not be flagged"


# --------------------------------------------------------------------------
# The allow-list is checked both ways.
# --------------------------------------------------------------------------


def test_allow_entries_are_live(tree_report):
    """An exemption must not outlive the code it excused."""
    assert not tree_report.stale_allows, "stale allow-list entries:\n  " + "\n  ".join(tree_report.stale_allows)


def test_a_stale_allow_entry_fails_the_build(tmp_path):
    config_text = _CONFIG.read_text(encoding="utf-8")
    config_text += '\n[[allow]]\npaths = ["services/realtime/**"]\nnames = ["Torq"]\nreason = "probe"\n'
    probe_config = tmp_path / "competitor_names.toml"
    probe_config.write_text(config_text, encoding="utf-8")

    report = gate.scan_tree(_REPO, gate.load_config(probe_config), probe_config)
    assert any("services/realtime" in entry for entry in report.stale_allows)
    assert not report.ok


def test_allow_entry_names_must_be_declared_competitors(tmp_path):
    """A typo in an allow entry would silently excuse nothing; fail loudly instead."""
    config_text = _CONFIG.read_text(encoding="utf-8")
    config_text += '\n[[allow]]\npaths = ["services/**"]\nnames = ["Torqq"]\nreason = "typo"\n'
    probe_config = tmp_path / "competitor_names.toml"
    probe_config.write_text(config_text, encoding="utf-8")

    with pytest.raises(gate.ConfigError, match="not declared competitors"):
        gate.load_config(probe_config)


# --------------------------------------------------------------------------
# Comparison tables: no vendor name at all, even an integration vendor.
# --------------------------------------------------------------------------


def test_comparison_surfaces_are_located(tree_report):
    assert not tree_report.broken_surfaces, "\n  ".join(tree_report.broken_surfaces)
    assert tree_report.surfaces_checked == len(CONFIG.comparison_surfaces)


def test_a_drifted_comparison_marker_fails_rather_than_skipping(tmp_path):
    """A region the gate cannot find must fail, not scan an empty slice."""
    worktree = tmp_path / "tree"
    (worktree / "apps" / "docs" / "docs").mkdir(parents=True)
    (worktree / "apps" / "docs" / "docs" / "benchmark.md").write_text("# no markers here\n", encoding="utf-8")

    report = gate.ScanReport(root=worktree, config_path=_CONFIG)
    gate.scan_comparison_surfaces(worktree, CONFIG, report)

    assert report.broken_surfaces
    assert report.surfaces_checked == 0
    assert not report.ok


@pytest.mark.parametrize("case", CORPUS["comparison_bad"], ids=lambda c: c["text"][:40])
def test_vendor_in_a_comparison_table_is_caught(case, tmp_path):
    """Even a vendor AiSOC integrates with may not label a comparison column."""
    worktree = tmp_path / "tree"
    target = worktree / "apps" / "docs" / "docs" / "benchmark.md"
    target.parent.mkdir(parents=True)
    surface = next(s for s in CONFIG.comparison_surfaces if s.file.endswith("benchmark.md"))
    target.write_text(f"{surface.start}\n{case['text']}\n{surface.end}\n", encoding="utf-8")

    report = gate.ScanReport(root=worktree, config_path=_CONFIG)
    gate.scan_comparison_surfaces(worktree, CONFIG, report)
    assert report.findings, f"comparison table vendor not caught ({case['why']}): {case['text']!r}"


@pytest.mark.parametrize("case", CORPUS["comparison_good"], ids=lambda c: c["text"][:40])
def test_neutral_comparison_label_is_accepted(case, tmp_path):
    worktree = tmp_path / "tree"
    target = worktree / "apps" / "docs" / "docs" / "benchmark.md"
    target.parent.mkdir(parents=True)
    surface = next(s for s in CONFIG.comparison_surfaces if s.file.endswith("benchmark.md"))
    target.write_text(f"{surface.start}\n{case['text']}\n{surface.end}\n", encoding="utf-8")

    report = gate.ScanReport(root=worktree, config_path=_CONFIG)
    gate.scan_comparison_surfaces(worktree, CONFIG, report)
    assert not report.findings, f"neutral label flagged as a vendor: {case['text']!r}"


# --------------------------------------------------------------------------
# The gate names what it scanned.
# --------------------------------------------------------------------------


def test_root_comes_from_the_caller_not_the_scripts_own_location(tmp_path):
    """A gate that locates its repo from __file__ reports on the wrong tree.

    Pointed at another worktree, this one must scan *that* tree, say so by name,
    and find the violation planted there.
    """
    if shutil.which("git") is None:  # pragma: no cover - git is present in CI
        pytest.skip("git unavailable")

    probe = tmp_path / "probe-tree"
    (probe / "docs").mkdir(parents=True)
    (probe / "docs" / "gap.md").write_text("We lag Dropzone AI on investigation depth.\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(probe)], check=True)
    subprocess.run(["git", "-C", str(probe), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(probe), "-c", "user.email=p@example.com", "-c", "user.name=Probe", "commit", "-qm", "probe"],
        check=True,
    )

    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "--root", str(probe), "--config", str(_CONFIG)],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )
    assert result.returncode == 1
    assert str(probe.resolve()) in result.stdout, "the gate must name the tree it scanned"
    assert "files scanned:     1" in result.stdout
    assert "Dropzone AI" in result.stdout


def test_self_test_subcommand_passes():
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "--self-test"],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_tree_is_clean(tree_report):
    assert not tree_report.findings, "\n".join(
        f"{f.path}:{f.line_no} [{f.kind}] {f.competitor} — {f.excerpt}" for f in tree_report.findings
    )
    assert tree_report.files_scanned > 1000, "the scan covered suspiciously few files"
