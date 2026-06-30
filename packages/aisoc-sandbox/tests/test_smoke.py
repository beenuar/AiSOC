"""Smoke tests — the package's own quick-win on-ramp.

If any of these fail, `pip install aisoc-sandbox && aisoc-sandbox demo`
no longer works on a clean machine — which is the only contract that
matters for this package. The CI gate that runs this suite on a Linux
+ macOS matrix (see `.github/workflows/sandbox-smoke.yml`) is the
authoritative trust signal for the `pip install` path.
"""

from __future__ import annotations

import io
import json
import time

import pytest

from aisoc_sandbox import (
    Ledger,
    available_scenarios,
    load_scenario,
    run_investigation,
)
from aisoc_sandbox.cli import main


# ---------------------------------------------------------------------------
# Scenarios are real, loadable, well-formed.
# ---------------------------------------------------------------------------

def test_bundled_scenarios_are_exactly_the_five_we_advertise() -> None:
    expected = {
        "aws-credential-exfil",
        "github-token-theft",
        "kubernetes-privesc",
        "lateral-movement",
        "phishing-payload",
    }
    assert set(available_scenarios()) == expected


@pytest.mark.parametrize("sid", sorted({
    "aws-credential-exfil",
    "github-token-theft",
    "kubernetes-privesc",
    "lateral-movement",
    "phishing-payload",
}))
def test_each_scenario_loads_and_has_required_fields(sid: str) -> None:
    sc = load_scenario(sid)
    assert sc.id == sid
    assert sc.title  # human-readable headline must be present
    assert sc.severity in {"info", "low", "medium", "high", "critical"}
    assert sc.events, "every scenario must carry at least one event"
    assert sc.mitre_techniques, "every scenario must reference at least one MITRE technique"


def test_unknown_scenario_raises_a_useful_error() -> None:
    with pytest.raises(ValueError, match="Unknown scenario"):
        load_scenario("does-not-exist")


# ---------------------------------------------------------------------------
# Investigation funnel.
# ---------------------------------------------------------------------------

def test_run_emits_a_four_stage_ledger() -> None:
    sc = load_scenario("lateral-movement")
    ledger = run_investigation(sc)
    stages = [step.funnel_stage for step in ledger]
    assert stages == ["detect", "triage", "hunt", "respond"]


def test_each_step_has_evidence_and_a_decision() -> None:
    sc = load_scenario("aws-credential-exfil")
    ledger = run_investigation(sc)
    for step in ledger:
        assert step.action, f"step {step.step} missing action"
        assert step.rationale, f"step {step.step} missing rationale"
        assert step.decision, f"step {step.step} missing decision summary"


def test_offline_run_completes_well_under_the_30s_budget() -> None:
    sc = load_scenario("lateral-movement")
    t0 = time.perf_counter()
    run_investigation(sc)
    elapsed = time.perf_counter() - t0
    # 30 s is the plan budget; the simulator should finish in under 1 s
    # on any modern machine. We assert 5 s to leave plenty of headroom
    # for CI VMs.
    assert elapsed < 5.0, f"run took {elapsed:.3f} s (budget: 5 s, plan ceiling: 30 s)"


def test_ledger_serialises_to_valid_json() -> None:
    sc = load_scenario("phishing-payload")
    ledger = run_investigation(sc)
    payload = ledger.to_json()
    parsed = json.loads(payload)
    assert isinstance(parsed, list) and len(parsed) == 4


def test_ledger_human_render_is_plain_text_when_not_tty() -> None:
    sc = load_scenario("kubernetes-privesc")
    ledger = run_investigation(sc)
    buf = io.StringIO()
    ledger.render_human(out=buf)
    text = buf.getvalue()
    # No ANSI escape codes when output isn't a TTY.
    assert "\x1b[" not in text
    # All four funnel labels must appear.
    for label in ("DETECT", "TRIAGE", "HUNT", "RESPOND"):
        assert label in text


# ---------------------------------------------------------------------------
# CLI surface.
# ---------------------------------------------------------------------------

def test_cli_demo_default_returns_0(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["demo"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Investigation Ledger" in out
    assert "Ready for the real stack?" in out


def test_cli_demo_json_emits_machine_readable_payload(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["demo", "--scenario", "github-token-theft", "--json"])
    assert exit_code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["tool"] == "aisoc-sandbox"
    assert parsed["scenario"]["id"] == "github-token-theft"
    assert len(parsed["ledger"]) == 4
    assert "elapsed_ms" in parsed


def test_cli_scenarios_lists_all_five(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scenarios"])
    assert exit_code == 0
    out = capsys.readouterr().out
    for sid in (
        "aws-credential-exfil",
        "github-token-theft",
        "kubernetes-privesc",
        "lateral-movement",
        "phishing-payload",
    ):
        assert sid in out


def test_cli_demo_with_missing_file_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["demo", "--file", "/does/not/exist.json"])
    assert exit_code == 2
    assert "error:" in capsys.readouterr().err


def test_library_user_can_append_to_an_existing_ledger() -> None:
    # A library user might want to chain multiple scenarios into one
    # ledger — the dataclass contract supports that.
    sc1 = load_scenario("lateral-movement")
    sc2 = load_scenario("phishing-payload")
    ledger = Ledger()
    run_investigation(sc1, ledger=ledger)
    run_investigation(sc2, ledger=ledger)
    assert len(ledger) == 8  # 4 steps per scenario
