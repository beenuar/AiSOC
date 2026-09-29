"""The floor refuses everything that would let it pass without measuring.

The failure this guards against is not "the agent got worse". It is a gate
that reports green on a report the agent never produced — a substrate
fallback, a one-incident sample compared to a twenty-incident floor, or a
different model's numbers held to this model's bar. Each of those would make
the floor a decoration, which is worse than not having one, because the
claim-to-gate matrix would then cite it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_live_agent_floor.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_live_agent_floor", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()

FLOOR = {
    "axis": "groundedness",
    "model": "qwen2.5:0.5b",
    "served_by": "ollama",
    "incidents": 20,
    "floor_mean": 0.45,
    "observations": [{"mean": 0.5364, "incidents": 20, "where": "local"}],
    "derivation": "margin below the lowest observed run",
}


def report(**overrides):
    base = {
        "mode": "live",
        "model": "qwen2.5:0.5b",
        "groundedness": {"measured": True, "mean": 0.5364, "scored_incidents": 20, "llm_calls_placed": 160},
    }
    base.update(overrides)
    return base


# ── the ways a green run could mean nothing ──────────────────────────────────


def test_a_substrate_report_never_clears_a_live_floor():
    problems = gate.check(report(mode="dry_run"), FLOOR, allow_model=False)
    assert any("not 'live'" in p for p in problems)


def test_a_substrate_report_is_refused_before_its_numbers_are_read():
    """Reading on would grade figures whose provenance was just rejected."""
    problems = gate.check(
        {
            "mode": "dry_run",
            "model": "qwen2.5:0.5b",
            "groundedness": {"measured": True, "mean": 0.99, "scored_incidents": 20, "llm_calls_placed": 160},
        },
        FLOOR,
        allow_model=False,
    )
    assert len(problems) == 1


def test_groundedness_that_was_not_measured_is_not_a_pass():
    problems = gate.check(
        report(groundedness={"measured": False, "note": "nothing to score"}),
        FLOOR,
        allow_model=False,
    )
    assert any("not measured" in p for p in problems)


def test_a_run_that_placed_no_llm_call_is_the_fallback_not_the_model():
    """Observed for real: a dead model env var sent every agent at an alias
    the endpoint had never heard of, and the run reported 0.8050 at 0.11s per
    investigation — faster than a network round trip, and flattering."""
    problems = gate.check(
        report(groundedness={"measured": True, "mean": 0.805, "scored_incidents": 20, "llm_calls_placed": 0}),
        FLOOR,
        allow_model=False,
    )
    assert any("zero LLM calls" in p for p in problems)


def test_a_smaller_sample_is_a_different_measurement():
    problems = gate.check(
        report(groundedness={"measured": True, "mean": 0.9, "scored_incidents": 3, "llm_calls_placed": 24}),
        FLOOR,
        allow_model=False,
    )
    assert any("3 incident(s) scored" in p for p in problems)


def test_another_model_is_not_graded_against_this_model_s_floor():
    problems = gate.check(report(model="llama3.2:3b"), FLOOR, allow_model=False)
    assert any("llama3.2:3b" in p for p in problems)


def test_grading_another_model_is_possible_but_deliberate():
    assert gate.check(report(model="llama3.2:3b"), FLOOR, allow_model=True) == []


# ── the thing the gate is actually for ───────────────────────────────────────


def test_a_run_below_the_floor_fails_and_prints_what_it_was_derived_from():
    problems = gate.check(
        report(groundedness={"measured": True, "mean": 0.31, "scored_incidents": 20, "llm_calls_placed": 160}),
        FLOOR,
        allow_model=False,
    )
    assert any("0.3100" in p and "0.4500" in p and "0.5364" in p for p in problems)


def test_a_run_at_the_floor_passes():
    assert (
        gate.check(
            report(groundedness={"measured": True, "mean": 0.45, "scored_incidents": 20, "llm_calls_placed": 160}), FLOOR, allow_model=False
        )
        == []
    )


def test_the_real_report_shape_clears_the_real_floor():
    """The committed floor must pass a report carrying the runs it came from.

    A floor set above its own evidence would red every run from the day it
    landed, and the first person to see it would move the floor rather than
    investigate.
    """
    real = gate.load_floor(REPO_ROOT / gate.FLOOR_REL)
    lowest = min(float(o["mean"]) for o in real["observations"])
    clean = {
        "mode": "live",
        "model": real["model"],
        "groundedness": {"measured": True, "mean": lowest, "scored_incidents": int(real["incidents"]), "llm_calls_placed": 1},
    }
    assert gate.check(clean, real, allow_model=False) == []


# ── the floor declaration has to carry its evidence ──────────────────────────


def test_a_floor_with_no_observations_is_refused(tmp_path):
    path = tmp_path / "floor.json"
    path.write_text(json.dumps({**FLOOR, "observations": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="records no observations"):
        gate.load_floor(path)


def test_a_floor_above_its_own_evidence_is_refused(tmp_path):
    path = tmp_path / "floor.json"
    path.write_text(json.dumps({**FLOOR, "floor_mean": 0.9}), encoding="utf-8")
    with pytest.raises(ValueError, match="above the lowest run"):
        gate.load_floor(path)


def test_a_floor_missing_its_provenance_is_refused(tmp_path):
    path = tmp_path / "floor.json"
    path.write_text(json.dumps({"floor_mean": 0.45}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        gate.load_floor(path)


def test_the_committed_floor_parses_and_declares_its_runs():
    real = gate.load_floor(REPO_ROOT / gate.FLOOR_REL)
    assert real["axis"] == "groundedness"
    assert len(real["observations"]) >= 2, "one run is a sample, not a distribution"
    # The model and where each run happened travel with every number, so a
    # reader never has to ask which model produced the figure.
    for entry in real["observations"]:
        assert str(entry["where"]).strip()


# ── end to end ───────────────────────────────────────────────────────────────


def test_a_missing_report_is_an_eval_that_did_not_finish(tmp_path):
    assert gate.main(["--report", str(tmp_path / "absent.json")]) == 2


def test_show_prints_the_floor_without_asserting():
    assert gate.main(["--show"]) == 0


def test_the_gate_reds_on_a_report_below_the_floor(tmp_path):
    real = gate.load_floor(REPO_ROOT / gate.FLOOR_REL)
    path = tmp_path / "wet.json"
    path.write_text(
        json.dumps(
            {
                "mode": "live",
                "model": real["model"],
                "groundedness": {"measured": True, "mean": 0.0, "scored_incidents": int(real["incidents"]), "llm_calls_placed": 1},
            }
        ),
        encoding="utf-8",
    )
    assert gate.main(["--report", str(path)]) == 1
