"""The live dispatch loop's two measurement properties (#1466).

1. **One event loop for the whole run.** Per-incident ``asyncio.run`` looked
   equivalent and was not: langchain-openai caches its default async httpx
   client across constructions, so incident 2's fresh loop inherited a pooled
   connection bound to incident 1's closed loop, and the first LLM call of
   every subsequent incident — recon, always — died with "Event loop is
   closed" and silently fell back to heuristics. Under the old code the test
   below observes three distinct loop ids; under the fix, one.

2. **A failed incident is scored 0 with its reason recorded, never dropped.**
   Dropping it is survivor bias (the mean over the survivors flatters the
   model) and shrinks the sample below what the floor was derived over, which
   ``check_live_agent_floor.py`` rightly refuses. Scoring it 0 keeps the
   sample size equal to the dispatched prefix and makes the failure legible
   in the report.

The fakes here stand in for ``app.investigator`` / ``app.confidence`` only —
the loop structure and the record bookkeeping under test are entirely
``scripts/wet_eval.py``'s own.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _REPO_ROOT / "scripts"


def _load_wet_eval():
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    spec = importlib.util.spec_from_file_location("wet_eval_under_test", _SCRIPTS / "wet_eval.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Registered before exec: the dataclass machinery resolves the module's
    # annotations through sys.modules, and an unregistered module leaves it
    # holding None.
    sys.modules["wet_eval_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _incidents_file(tmp_path: Path, n: int = 3) -> Path:
    incidents = [
        {
            "id": f"INC-{i}",
            "template_id": "t-1",
            "title": f"incident {i}",
            "description": "a login from 203.0.113.7",
            "severity": "medium",
            "telemetry": [],
            "evidence_keywords": [],
            "expected_techniques": ["T1078"],
        }
        for i in range(1, n + 1)
    ]
    path = tmp_path / "incidents.json"
    path.write_text(json.dumps(incidents))
    return path


def _good_state() -> SimpleNamespace:
    return SimpleNamespace(
        status="completed",
        error=None,
        cost_summary={"call_count": 2, "prompt_tokens": 100, "completion_tokens": 50},
        recon=SimpleNamespace(
            summary="observed 203.0.113.7",
            mitre_techniques=["T1078"],
            threat_actors=[],
            iocs=[{"value": "203.0.113.7"}],
        ),
        forensic=None,
        responder=None,
    )


@pytest.fixture
def fake_agent_stack(monkeypatch: pytest.MonkeyPatch):
    """Install fake ``app.investigator`` / ``app.confidence.groundedness``.

    ``_live_records`` imports both lazily, so placing modules in
    ``sys.modules`` is the whole injection. The fixture yields a dict the
    test mutates to control per-incident behaviour and to record what the
    dispatch did.
    """
    control: dict[str, Any] = {"loops": [], "behaviour": {}}

    async def run_investigation(*, case_id: str, alert_summary: str, raw_alert: dict) -> Any:
        control["loops"].append(id(asyncio.get_running_loop()))
        behaviour = control["behaviour"].get(case_id)
        if behaviour == "raise":
            raise RuntimeError("synthetic dispatch failure")
        state = _good_state()
        if behaviour == "failed":
            state.status = "failed"
            state.error = "synthetic parse failure"
        return state

    def score_groundedness(assertion_text: str, evidence_text: str) -> Any:
        return SimpleNamespace(score=0.8, hallucinated=[])

    app_pkg = types.ModuleType("app")
    investigator = types.ModuleType("app.investigator")
    investigator.run_investigation = run_investigation  # type: ignore[attr-defined]
    confidence = types.ModuleType("app.confidence")
    groundedness = types.ModuleType("app.confidence.groundedness")
    groundedness.score_groundedness = score_groundedness  # type: ignore[attr-defined]
    app_pkg.investigator = investigator  # type: ignore[attr-defined]
    app_pkg.confidence = confidence  # type: ignore[attr-defined]
    confidence.groundedness = groundedness  # type: ignore[attr-defined]

    for name, module in [
        ("app", app_pkg),
        ("app.investigator", investigator),
        ("app.confidence", confidence),
        ("app.confidence.groundedness", groundedness),
    ]:
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setenv("WET_EVAL_OPENAI_KEY", "test-key")
    return control


def test_every_incident_dispatches_on_one_event_loop(tmp_path: Path, fake_agent_stack: dict) -> None:
    """Under per-incident ``asyncio.run`` this set has three members."""
    wet_eval = _load_wet_eval()

    records, warnings, degraded = wet_eval._live_records(_incidents_file(tmp_path, 3), model="fake-model")

    assert not degraded
    assert len(records) == 3
    assert len(fake_agent_stack["loops"]) == 3
    assert len(set(fake_agent_stack["loops"])) == 1, (
        "incidents dispatched on different event loops — the cached async HTTP client in the LLM stack "
        "poisons every loop after the first, and recon's call dies with 'Event loop is closed' (#1466)"
    )


def test_a_raised_investigation_scores_zero_and_stays_in_the_sample(tmp_path: Path, fake_agent_stack: dict) -> None:
    wet_eval = _load_wet_eval()
    fake_agent_stack["behaviour"]["INC-2"] = "raise"

    records, warnings, degraded = wet_eval._live_records(_incidents_file(tmp_path, 3), model="fake-model")

    assert not degraded
    assert [r.incident_id for r in records] == ["INC-1", "INC-2", "INC-3"], (
        "a failed incident was dropped from the sample — the mean over the survivors is survivor bias, "
        "and the shrunken sample fails the floor checker's size requirement"
    )
    failed = records[1]
    assert failed.groundedness == 0.0
    assert failed.zero_scored_reason is not None and "raised" in failed.zero_scored_reason
    assert records[0].groundedness == 0.8 and records[2].groundedness == 0.8

    block = wet_eval._groundedness_block(records)
    assert block["measured"] is True
    assert block["scored_incidents"] == 3
    assert block["zero_scored_incidents"] == 1
    assert block["zero_scored"] == [{"incident": "INC-2", "reason": failed.zero_scored_reason}]
    # 0.8, 0.0, 0.8 — the zero participates in the mean rather than vanishing.
    assert block["mean"] == pytest.approx(0.5333, abs=1e-4)


def test_a_status_failed_investigation_scores_zero_with_the_error_recorded(tmp_path: Path, fake_agent_stack: dict) -> None:
    wet_eval = _load_wet_eval()
    fake_agent_stack["behaviour"]["INC-3"] = "failed"

    records, _warnings, degraded = wet_eval._live_records(_incidents_file(tmp_path, 3), model="fake-model")

    assert not degraded
    assert len(records) == 3
    failed = records[2]
    assert failed.groundedness == 0.0
    assert failed.zero_scored_reason is not None
    assert "status=failed" in failed.zero_scored_reason
    assert "synthetic parse failure" in failed.zero_scored_reason
    # The calls the failed run DID place are still counted — they happened.
    assert failed.llm_calls == 2


def test_a_clean_run_reports_no_zero_scored_block(tmp_path: Path, fake_agent_stack: dict) -> None:
    """The zero-scored keys appear only when there is something to explain."""
    wet_eval = _load_wet_eval()

    records, _warnings, _degraded = wet_eval._live_records(_incidents_file(tmp_path, 3), model="fake-model")

    block = wet_eval._groundedness_block(records)
    assert "zero_scored" not in block
    assert "zero_scored_incidents" not in block
