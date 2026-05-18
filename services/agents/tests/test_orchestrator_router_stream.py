"""
T2.2 — RouterOrchestrator.stream() behavioural tests.

These tests exercise the streaming surface that the WebSocket layer will
ride on once ``/investigate`` is swapped over to the router. They cover:

* Step / done event emission for both topologies.
* Monotonic ``seq`` numbering across the run.
* Deterministic Markdown + HTML report carried on ``done``.
* Best-effort ledger persistence: ``start_run`` → multiple
  ``record_event`` calls → ``record_artifact`` → ``complete_run``.
* Robustness: stream completes even when the ledger is unavailable
  (``start_run`` returns ``None``).
* Auto-triage early exit emits exactly one step + ``done`` with
  ``auto_closed=True``.

Sub-agent runners are monkeypatched to deterministic shims that
``asyncio.sleep`` briefly — matches the pattern in
``test_orchestrator_parallel.py``.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.models.state import AgentStatus, InvestigationState  # noqa: E402
from app.orchestrator import RouterOrchestrator  # noqa: E402

SUBAGENT_SLEEP_MS = 10
AUTO_TRIAGE_SLEEP_MS = 5


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _multi_signal_incident() -> InvestigationState:
    """Phishing → identity → cloud → insider, all four signals triggered."""
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=(
            "INC-PH-LATERAL-STREAM: Spear-phishing with OAuth consent led to "
            "credential theft on aws_iam role; impossible-travel login from "
            "Berlin then bulk download to attacker infra."
        ),
        raw_alert={
            "sender": "compliance@trusted-partner.example",
            "subject": "Action required: contract renewal",
            "urls": ["https://contract-renewal[.]example/login"],
            "username": "alice@corp.example",
            "user_email": "alice@corp.example",
            "source_ip": "203.0.113.42",
            "source_geo": "Berlin, DE",
            "auth_method": "saml",
            "mfa_status": "challenged",
            "cloud_provider": "aws",
            "region": "eu-west-1",
            "account_id": "111122223333",
            "resource_arn": "arn:aws:s3:::corp-backups",
            "principal_arn": "arn:aws:iam::111122223333:role/DataAnalyst",
            "data_volume_mb": 4096,
            "file_count": 871,
            "destination_domain": "attacker[.]example",
            "is_off_hours": True,
        },
        status=AgentStatus.PENDING,
    )


def _patch_runners(monkeypatch: pytest.MonkeyPatch, *, auto_close: bool = False) -> dict[str, list[str]]:
    """Replace the five LLM-backed runners with deterministic shims.

    Mirrors the helper in ``test_orchestrator_parallel.py`` but with the
    shorter sleep budget appropriate to a streaming test (we care about
    correctness, not wall-clock ratios).
    """
    call_log: dict[str, list[str]] = {
        "auto_triage": [],
        "phishing": [],
        "identity": [],
        "cloud": [],
        "insider": [],
    }

    async def fake_auto_triage(state: InvestigationState) -> InvestigationState:
        await asyncio.sleep(AUTO_TRIAGE_SLEEP_MS / 1000.0)
        state.iteration_count += 1
        state.status = AgentStatus.COMPLETED if auto_close else AgentStatus.RUNNING
        state.verdict = "benign" if auto_close else "true_positive"
        state.confidence = 0.95 if auto_close else 0.6
        state.confidence_basis = ["fake auto-triage rationale"]
        state.add_finding(f"Auto-triage (fake): verdict={state.verdict}")
        call_log["auto_triage"].append(str(state.incident_id))
        return state

    def _make_runner(name: str, technique: str):
        async def _runner(state: InvestigationState) -> InvestigationState:
            await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
            state.add_finding(f"{name} (fake): triggered")
            if technique not in state.mitre_mappings:
                state.mitre_mappings.append(technique)
            state.verdict = "true_positive"
            state.confidence = max(state.confidence, 0.7 + 0.05 * len(call_log[name]))
            call_log[name].append(str(state.incident_id))
            return state

        return _runner

    fake_phishing = _make_runner("phishing", "T1566.001")
    fake_identity = _make_runner("identity", "T1078")
    fake_cloud = _make_runner("cloud", "T1078.004")
    fake_insider = _make_runner("insider", "T1567.002")

    targets: list[tuple[str, object]] = [
        ("app.agents.run_auto_triage", fake_auto_triage),
        ("app.agents.auto_triage_agent.run_auto_triage", fake_auto_triage),
        ("app.agents.run_phishing", fake_phishing),
        ("app.agents.phishing_agent.run_phishing", fake_phishing),
        ("app.agents.run_identity", fake_identity),
        ("app.agents.identity_agent.run_identity", fake_identity),
        ("app.agents.run_cloud", fake_cloud),
        ("app.agents.cloud_agent.run_cloud", fake_cloud),
        ("app.agents.run_insider_threat", fake_insider),
        ("app.agents.insider_threat_agent.run_insider_threat", fake_insider),
    ]
    for path, fn in targets:
        monkeypatch.setattr(path, fn, raising=False)

    return call_log


class _LedgerSpy:
    """Records every ledger interaction so the test can assert ordering.

    Each entry is ``(method, kwargs)`` in call order. ``start_run``
    returns a fixed tenant UUID so downstream writes can proceed.
    """

    def __init__(self, *, tenant_id: UUID | None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._tenant_id = tenant_id

    async def start_run(self, **kwargs: Any) -> UUID | None:
        self.calls.append(("start_run", kwargs))
        return self._tenant_id

    async def record_event(self, **kwargs: Any) -> UUID | None:
        self.calls.append(("record_event", kwargs))
        return uuid.uuid4() if self._tenant_id is not None else None

    async def record_artifact(self, **kwargs: Any) -> UUID | None:
        self.calls.append(("record_artifact", kwargs))
        return uuid.uuid4() if self._tenant_id is not None else None

    async def complete_run(self, **kwargs: Any) -> None:
        self.calls.append(("complete_run", kwargs))

    def methods_in_order(self) -> list[str]:
        return [m for m, _ in self.calls]


def _install_ledger_spy(
    monkeypatch: pytest.MonkeyPatch,
    *,
    tenant_id: UUID | None,
) -> _LedgerSpy:
    """Replace the ledger surface that ``RouterOrchestrator.stream`` imports."""
    spy = _LedgerSpy(tenant_id=tenant_id)
    import app.investigator.ledger as ledger_module

    monkeypatch.setattr(ledger_module, "start_run", spy.start_run, raising=True)
    monkeypatch.setattr(ledger_module, "record_event", spy.record_event, raising=True)
    monkeypatch.setattr(ledger_module, "record_artifact", spy.record_artifact, raising=True)
    monkeypatch.setattr(ledger_module, "complete_run", spy.complete_run, raising=True)
    return spy


async def _collect(stream) -> list[dict[str, Any]]:
    """Drain an async iterator into a list."""
    return [event async for event in stream]


# ---------------------------------------------------------------------------
# Step / done event surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_emits_step_events_per_stage_parallel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parallel topology emits: auto_triage, router, 4×sub-agent, join, responder, done."""
    _patch_runners(monkeypatch)
    _install_ledger_spy(monkeypatch, tenant_id=None)  # no ledger writes; just exercise streaming

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    types = [e["type"] for e in events]
    assert types[-1] == "done", f"final event must be 'done', got {types}"
    assert types[:-1] == ["step"] * (len(types) - 1), f"all non-terminal events must be 'step', got {types}"

    step_agents = [e["agent"] for e in events if e["type"] == "step"]
    # The first two stages are deterministically ordered.
    assert step_agents[0] == "auto_triage"
    assert step_agents[1] == "router"
    # Then a permutation of the four sub-agents (order depends on which
    # task ``as_completed`` yields first — sleeps are equal so it's
    # scheduling-dependent).
    subagent_window = step_agents[2:6]
    assert set(subagent_window) == {"phishing", "identity", "cloud", "insider"}, subagent_window
    # Then join and responder.
    assert step_agents[6] == "join"
    assert step_agents[7] == "responder"
    assert len(step_agents) == 8


@pytest.mark.asyncio
async def test_stream_emits_step_events_per_stage_sequential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sequential topology emits sub-agent steps in declared signal order."""
    _patch_runners(monkeypatch)
    _install_ledger_spy(monkeypatch, tenant_id=None)

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="sequential"))

    step_agents = [e["agent"] for e in events if e["type"] == "step"]
    assert step_agents == [
        "auto_triage",
        "router",
        "phishing",
        "identity",
        "cloud",
        "insider",
        "join",
        "responder",
    ]
    assert events[-1]["type"] == "done"


@pytest.mark.asyncio
async def test_stream_seq_is_monotonic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every step carries a strictly-increasing ``seq`` starting from 1."""
    _patch_runners(monkeypatch)
    _install_ledger_spy(monkeypatch, tenant_id=None)

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    step_seqs = [e["seq"] for e in events if e["type"] == "step"]
    assert step_seqs == list(range(1, len(step_seqs) + 1)), step_seqs


# ---------------------------------------------------------------------------
# Done event payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_done_carries_report_and_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """``done`` event must carry both report formats plus the final state."""
    _patch_runners(monkeypatch)
    _install_ledger_spy(monkeypatch, tenant_id=None)

    state = _multi_signal_incident()
    incident_id = state.incident_id
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    done = events[-1]
    assert done["type"] == "done"
    assert done["case_id"] == incident_id
    assert UUID(done["run_id"])  # parses as UUID

    # State payload — covers the fields the WebSocket layer surfaces.
    inner = done["state"]
    assert inner["status"] == "completed"
    assert inner["verdict"] == "true_positive"
    assert inner["confidence"] > 0.0
    assert inner["report_md"], "report_md must be non-empty"
    assert inner["report_html"], "report_html must be non-empty"
    # Report should mention the case id so analysts can cross-ref.
    assert str(incident_id) in inner["report_md"]
    assert "<html" in inner["report_html"].lower()
    # MITRE techniques from the four sub-agents survive the join.
    assert set(inner["mitre_mappings"]) == {"T1566.001", "T1078", "T1078.004", "T1567.002"}

    # Telemetry block.
    info = done["info"]
    assert info["topology"] == "parallel"
    assert set(info["signals"]) == {"phishing", "identity", "cloud", "insider"}
    assert info["auto_closed"] is False
    assert info["wall_clock_ms"] >= 0


# ---------------------------------------------------------------------------
# Ledger ordering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_ledger_calls_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ledger sees start_run → N×record_event → record_artifact → complete_run."""
    _patch_runners(monkeypatch)
    tenant_id = uuid.uuid4()
    spy = _install_ledger_spy(monkeypatch, tenant_id=tenant_id)

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    methods = spy.methods_in_order()
    # Boundaries: must open with start_run and close with complete_run.
    assert methods[0] == "start_run"
    assert methods[-1] == "complete_run"
    # record_artifact lands after every record_event but before complete_run.
    assert methods[-2] == "record_artifact"
    # Between the bookends, only record_event is allowed.
    middle = methods[1:-2]
    assert middle and all(m == "record_event" for m in middle), middle
    # One record_event per step yielded.
    step_count = sum(1 for e in events if e["type"] == "step")
    assert len(middle) == step_count, f"expected {step_count} events, got {len(middle)}"

    # Sequence numbers on record_event match the seq carried on the stream.
    recorded_seqs = [kw["seq"] for m, kw in spy.calls if m == "record_event"]
    assert recorded_seqs == sorted(recorded_seqs)
    assert recorded_seqs == list(range(1, len(recorded_seqs) + 1))

    # Artifact is the Markdown report.
    ((_, artifact_kwargs),) = [c for c in spy.calls if c[0] == "record_artifact"]
    assert artifact_kwargs["kind"] == "report_md"
    assert artifact_kwargs["tenant_id"] == tenant_id
    assert artifact_kwargs["content"]  # non-empty
    assert str(state.incident_id) in artifact_kwargs["content"]

    # complete_run carries the terminal status.
    ((_, complete_kwargs),) = [c for c in spy.calls if c[0] == "complete_run"]
    assert complete_kwargs["status"] == "completed"
    assert complete_kwargs["tenant_id"] == tenant_id


@pytest.mark.asyncio
async def test_stream_continues_when_ledger_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``start_run`` returns ``None``, no downstream ledger writes are issued."""
    _patch_runners(monkeypatch)
    spy = _install_ledger_spy(monkeypatch, tenant_id=None)  # start_run -> None

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    # Stream still produces step + done events.
    assert any(e["type"] == "step" for e in events)
    assert events[-1]["type"] == "done"
    assert events[-1]["state"]["status"] == "completed"

    # Ledger only saw the open attempt — every other helper short-circuits
    # because tenant_id is None.
    methods = spy.methods_in_order()
    assert methods == ["start_run"], methods


@pytest.mark.asyncio
async def test_stream_survives_ledger_record_event_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A blowing-up ``record_event`` must not break the stream."""
    _patch_runners(monkeypatch)
    tenant_id = uuid.uuid4()
    spy = _install_ledger_spy(monkeypatch, tenant_id=tenant_id)

    async def boom(**kwargs: Any) -> None:
        raise RuntimeError("ledger offline")

    import app.investigator.ledger as ledger_module

    monkeypatch.setattr(ledger_module, "record_event", boom, raising=True)

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    # Stream completes despite every record_event raising.
    assert events[-1]["type"] == "done"
    assert events[-1]["state"]["status"] == "completed"
    # complete_run still fires.
    assert spy.methods_in_order()[-1] == "complete_run"


# ---------------------------------------------------------------------------
# Auto-triage early exit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_auto_close_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-triage that closes the alert ends the run after the first step."""
    call_log = _patch_runners(monkeypatch, auto_close=True)
    tenant_id = uuid.uuid4()
    spy = _install_ledger_spy(monkeypatch, tenant_id=tenant_id)

    state = _multi_signal_incident()
    events = await _collect(RouterOrchestrator().stream(state, topology="parallel"))

    # No sub-agent should have run.
    assert call_log["phishing"] == call_log["identity"] == []
    assert call_log["cloud"] == call_log["insider"] == []
    assert len(call_log["auto_triage"]) == 1

    # Exactly one step (auto_triage), then done with auto_closed=True.
    types = [e["type"] for e in events]
    assert types == ["step", "done"]
    assert events[0]["agent"] == "auto_triage"
    assert events[1]["info"]["auto_closed"] is True
    assert events[1]["info"]["signals"] == []
    assert events[1]["state"]["status"] == "completed"

    # Ledger sequence on the short path: start_run, one record_event,
    # record_artifact, complete_run.
    assert spy.methods_in_order() == [
        "start_run",
        "record_event",
        "record_artifact",
        "complete_run",
    ]
