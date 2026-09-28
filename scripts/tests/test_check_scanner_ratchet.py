"""The scanner ratchet fails in every direction it claims to.

A ratchet that only catches findings going up is half a ratchet: the count
drifts back down for free on an upstream rule change and the ceiling silently
stops meaning anything. A ratchet that credits a scanner which did not run is
worse than none. Both directions, and the vacuous case, are pinned here.

The strict allow-list reader is checked against ``yaml.safe_load`` on the real
file rather than trusted. It exists because the gate has to run in a job that
installs ruff and mypy and nothing else, and a hand-written reader that
disagrees with the parser everyone else uses would be its own defect.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_scanner_ratchet.py"
ALLOWLIST = REPO_ROOT / ".security" / "allowlist.yml"


def _load():
    spec = importlib.util.spec_from_file_location("check_scanner_ratchet", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


# ── the strict reader ────────────────────────────────────────────────────────


def test_reader_agrees_with_pyyaml_on_the_real_file():
    yaml = pytest.importorskip("yaml", reason="cross-check needs PyYAML; the gate itself never imports it")
    text = ALLOWLIST.read_text(encoding="utf-8")
    assert gate.parse_allowlist(text) == yaml.safe_load(text)


def test_reader_refuses_what_it_cannot_represent():
    with pytest.raises(gate.AllowlistError):
        gate.parse_allowlist("ceilings:\n  semgrep:\n    total: not-a-number\n")
    with pytest.raises(gate.AllowlistError):
        gate.parse_allowlist("ceilings:\n\tsemgrep: 1\n")
    with pytest.raises(gate.AllowlistError):
        gate.parse_allowlist("ceilings\n")


def test_reader_handles_the_entry_shape_the_schema_documents():
    doc = gate.parse_allowlist(
        'entries:\n  - tool: "semgrep"\n    id: "python.lang.security.audit"\n    reason: "accepted"\n    expires: "2030-01-01"\n'
    )
    assert doc["entries"] == [{"tool": "semgrep", "id": "python.lang.security.audit", "reason": "accepted", "expires": "2030-01-01"}]


# ── counting ─────────────────────────────────────────────────────────────────


def test_semgrep_counts_split_error_from_total():
    counts, version = gate.count_findings(
        "semgrep",
        {
            "version": "1.86.0",
            "results": [
                {"extra": {"severity": "ERROR"}},
                {"extra": {"severity": "WARNING"}},
                {"extra": {"severity": "ERROR"}},
            ],
        },
    )
    assert counts == {"total": 3, "error": 2}
    assert version == "1.86.0"


def test_checkov_counts_sum_across_frameworks():
    counts, _ = gate.count_findings(
        "checkov",
        [
            {"check_type": "terraform", "summary": {"failed": 7}},
            {"check_type": "helm", "summary": {"failed": 2}},
        ],
    )
    assert counts == {"failed": 9}


def test_checkov_counts_read_a_single_framework_object():
    counts, _ = gate.count_findings("checkov", {"check_type": "terraform", "summary": {"failed": 4}})
    assert counts == {"failed": 4}


def test_tfsec_counts_split_by_severity():
    counts, _ = gate.count_findings(
        "tfsec",
        {"results": [{"severity": "CRITICAL"}, {"severity": "HIGH"}, {"severity": "LOW"}]},
    )
    assert counts == {"total": 3, "critical": 1, "high": 1}


def test_tfsec_null_results_is_zero_not_a_crash():
    counts, _ = gate.count_findings("tfsec", {"results": None})
    assert counts == {"total": 0, "critical": 0, "high": 0}


# ── the three directions ─────────────────────────────────────────────────────

CEILING = {"total": 10, "error": 3, "measured_with": "1.86.0"}


def test_more_findings_than_the_ceiling_fails():
    problems = gate.check_report("semgrep", CEILING, {"total": 11, "error": 3}, "1.86.0")
    assert any("adds 1" in p for p in problems)


def test_fewer_findings_than_the_ceiling_also_fails_and_names_the_new_value():
    problems = gate.check_report("semgrep", CEILING, {"total": 9, "error": 3}, "1.86.0")
    assert any("Lower it to 9" in p for p in problems)


def test_zero_findings_against_a_real_ceiling_is_a_scanner_that_did_not_run():
    problems = gate.check_report("semgrep", CEILING, {"total": 0, "error": 0}, "1.86.0")
    assert any("did not run" in p for p in problems)


def test_matching_counts_pass():
    assert gate.check_report("semgrep", CEILING, {"total": 10, "error": 3}, "1.86.0") == []


def test_a_different_scanner_version_is_not_a_comparison():
    problems = gate.check_report("semgrep", CEILING, {"total": 10, "error": 3}, "1.99.0")
    assert any("measured with 1.86.0" in p for p in problems)


def test_a_bucket_the_report_does_not_carry_fails_rather_than_being_skipped():
    problems = gate.check_report("semgrep", CEILING, {"total": 10}, "1.86.0")
    assert any("no such count" in p for p in problems)


# ── the version-drift arm, where it used to fall silent ──────────────────────
# tfsec's JSON carries no version field, so its counter returns None. The arm
# read `if version and measured_with and ...`, which made that None a pass —
# the ceiling declared `measured_with: "1.28.13"` and nothing ever compared
# it, so a bump that left the finding count identical went through unseen.


def test_a_version_that_could_not_be_established_is_not_a_version_that_matches():
    problems = gate.check_report("tfsec", CEILING, {"total": 10, "error": 3}, None)
    assert any("could not establish" in p for p in problems), "a missing version must fail, not skip the comparison"


def test_a_ceiling_with_no_measured_with_does_not_demand_a_version():
    """Only a ceiling that claims a version needs one to compare against."""
    unversioned = {"total": 10, "error": 3}
    assert gate.check_report("tfsec", unversioned, {"total": 10, "error": 3}, None) == []


def test_a_banner_is_accepted_and_the_bare_version_extracted():
    assert gate.normalise_version("v1.28.13") == "1.28.13"
    assert gate.normalise_version("tfsec version v1.28.13 (linux/amd64)") == "1.28.13"
    assert gate.normalise_version("1.28.13\n") == "1.28.13"


def test_output_with_no_version_number_in_it_is_not_guessed_at():
    assert gate.normalise_version("could not determine version") is None
    assert gate.normalise_version(None) is None


def test_a_binary_that_disagrees_with_its_own_report_fails(tmp_path):
    """Two sources for one fact must be cross-checked, or they drift apart."""
    report = tmp_path / "semgrep.json"
    report.write_text(json.dumps({"version": "1.86.0", "results": []}), encoding="utf-8")
    assert gate.main(["--tool", "semgrep", "--report", str(report), "--tool-version", "1.99.0"]) == 1


def test_tool_version_with_no_number_in_it_is_a_setup_error_not_a_finding(tmp_path):
    report = tmp_path / "tfsec.json"
    report.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert gate.main(["--tool", "tfsec", "--report", str(report), "--tool-version", "unknown"]) == 2


# ── allow-list hygiene ───────────────────────────────────────────────────────

TODAY = date(2026, 9, 28)


def _entry(**overrides):
    base = {
        "tool": "semgrep",
        "id": "python.lang.security.audit.eval-detected",
        "reason": "the expression is a fixed literal, not user input",
        "expires": (TODAY + timedelta(days=30)).isoformat(),
    }
    base.update(overrides)
    return base


def test_a_well_formed_entry_passes():
    assert gate.check_allowlist_entries([_entry()], TODAY) == []


def test_an_entry_with_no_reason_fails():
    problems = gate.check_allowlist_entries([_entry(reason="")], TODAY)
    assert any("no reason" in p for p in problems)


def test_an_expired_entry_fails():
    problems = gate.check_allowlist_entries([_entry(expires="2020-01-01")], TODAY)
    assert any("expired" in p for p in problems)


def test_an_expiry_further_out_than_the_cap_fails():
    far = (TODAY + timedelta(days=gate.MAX_EXPIRY_DAYS + 1)).isoformat()
    problems = gate.check_allowlist_entries([_entry(expires=far)], TODAY)
    assert any("days out" in p for p in problems)


def test_an_entry_naming_a_tool_nothing_runs_fails():
    problems = gate.check_allowlist_entries([_entry(tool="bandit")], TODAY)
    assert any("not one of" in p for p in problems)


# ── coverage, in both directions ─────────────────────────────────────────────


def test_a_scanner_with_no_ceiling_fails():
    problems = gate.check_coverage({"semgrep": {}}, {"semgrep", "checkov"})
    assert any("runs checkov" in p and "declares no ceiling" in p for p in problems)


def test_a_ceiling_for_a_scanner_nothing_runs_fails():
    problems = gate.check_coverage({"semgrep": {}, "tfsec": {}}, {"semgrep"})
    assert any("guards nothing" in p for p in problems)


def test_coverage_is_clean_when_both_sides_agree():
    assert gate.check_coverage({"semgrep": {}, "checkov": {}}, {"semgrep", "checkov"}) == []


# ── the workflow reader ──────────────────────────────────────────────────────


def test_the_real_workflow_invokes_every_tool_the_allowlist_ceils():
    workflow = (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    invoked = gate.tools_invoked(workflow)
    ceilings = gate.parse_allowlist(ALLOWLIST.read_text(encoding="utf-8"))["ceilings"]
    assert set(ceilings) == invoked


def test_a_tool_only_mentioned_in_a_comment_is_not_an_invocation():
    assert gate.tools_invoked("# we should add semgrep one day\n") == set()


def test_every_ceiling_pins_the_version_the_workflow_installs():
    """A ceiling measured with one version and compared against another is not
    a comparison, so the pin and the ``measured_with`` have to agree."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    pins = gate._versions_pinned(workflow)
    ceilings = gate.parse_allowlist(ALLOWLIST.read_text(encoding="utf-8"))["ceilings"]
    for tool, pinned in pins.items():
        if tool in ceilings:
            assert ceilings[tool].get("measured_with") == pinned, f"{tool} pinned at {pinned}"


# ── end to end, through the command line ─────────────────────────────────────


def test_the_gate_reds_on_a_regressed_report(tmp_path):
    report = tmp_path / "semgrep.json"
    report.write_text(
        json.dumps({"version": "1.86.0", "results": [{"extra": {"severity": "ERROR"}}] * 200}),
        encoding="utf-8",
    )
    assert gate.main(["--tool", "semgrep", "--report", str(report)]) == 1


def test_a_missing_report_is_a_scan_that_did_not_finish(tmp_path):
    assert gate.main(["--tool", "semgrep", "--report", str(tmp_path / "absent.json")]) == 2


def test_a_truncated_report_is_a_scan_that_did_not_finish(tmp_path):
    report = tmp_path / "semgrep.json"
    report.write_text('{"results": [', encoding="utf-8")
    assert gate.main(["--tool", "semgrep", "--report", str(report)]) == 2


def test_the_gate_passes_on_the_real_tree_with_no_report():
    assert gate.main([]) == 0
