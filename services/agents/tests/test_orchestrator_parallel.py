"""
T2.2 — parallel topology wall-clock + MITRE preservation gate.

This test exercises the router orchestrator
(``services.agents.app.orchestrator``) against a deterministic
multi-signal incident (``INC-PH-LATERAL``) under two topologies:

* ``parallel``   — ``asyncio.gather`` fan-out over the triggered
  sub-agents, followed by a Join node and the dry-run responder
* ``sequential`` — the legacy reference path
  ``auto_triage → phishing → identity → cloud → insider → responder``

For both modes we monkeypatch the four sub-agent runners and
``run_auto_triage`` to deterministic shims that ``asyncio.sleep`` for
``SUBAGENT_SLEEP_MS`` to simulate the LLM round-trip. The sleep dominates
the wall-clock, so the ratio of (sequential / parallel) wall-clocks
directly measures the topology speed-up.

Gates
-----

* Parallel ≥ 30% faster than sequential
  (``parallel_ms <= sequential_ms * 0.7``).
* MITRE technique set after the run is identical between modes — the
  topology must not change reasoning correctness.

These numbers are substrate self-consistency gates (mocked sub-agents); the
real LLM-backed deltas land in the wet-eval scoreboard. The substrate
ratio is structurally sound: N concurrent sleeps each of duration ``d``
take ``≈ d`` wall-clock when parallel and ``N · d`` when sequential.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.models.state import AgentStatus, InvestigationState  # noqa: E402
from app.orchestrator import (  # noqa: E402
    PARALLEL_TOPOLOGY_FLAG,
    RouterOrchestrator,
    classify_signals,
    is_parallel_topology_enabled,
)

# Per-sub-agent simulated LLM latency. Picked low enough to keep the
# whole suite fast; high enough that ``asyncio.sleep`` is the dominant
# factor in wall-clock measurement (well above the asyncio scheduler
# overhead on any reasonable machine).
SUBAGENT_SLEEP_MS = 60
AUTO_TRIAGE_SLEEP_MS = 20


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _multi_signal_incident() -> InvestigationState:
    """Build INC-PH-LATERAL — a phishing-pivots-to-lateral-movement alert.

    The raw payload carries fields that match every capability's trigger
    set so the classifier picks ``phishing``, ``identity``, ``cloud``,
    ``insider`` for the same incident. This is the same shape an analyst
    would see for a real spear-phishing → credential-theft → AWS
    impossible-travel → bulk-S3-exfil incident in the eval corpus.
    """
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=(
            "INC-PH-LATERAL: Spear-phishing email with OAuth consent harvest led "
            "to credential theft on aws_iam role; impossible-travel login from "
            "Berlin then bulk download of personal-drive contents to attacker "
            "infrastructure."
        ),
        raw_alert={
            # phishing signal
            "sender": "compliance@trusted-partner.example",
            "subject": "Action required: contract renewal",
            "urls": ["https://contract-renewal[.]example/login"],
            # identity signal
            "username": "alice@corp.example",
            "user_email": "alice@corp.example",
            "source_ip": "203.0.113.42",
            "source_geo": "Berlin, DE",
            "auth_method": "saml",
            "mfa_status": "challenged",
            # cloud signal
            "cloud_provider": "aws",
            "region": "eu-west-1",
            "account_id": "111122223333",
            "resource_arn": "arn:aws:s3:::corp-backups",
            "principal_arn": "arn:aws:iam::111122223333:role/DataAnalyst",
            # insider signal
            "data_volume_mb": 4096,
            "file_count": 871,
            "destination_domain": "attacker[.]example",
            "is_off_hours": True,
        },
        status=AgentStatus.PENDING,
    )


def _patch_runners(monkeypatch: pytest.MonkeyPatch, *, auto_close: bool = False) -> dict[str, list[str]]:
    """Replace the five LLM-backed runners with deterministic shims.

    Each shim ``await asyncio.sleep``s for ``SUBAGENT_SLEEP_MS`` /
    ``AUTO_TRIAGE_SLEEP_MS`` to simulate an LLM round-trip, then mutates
    the state with capability-specific findings + MITRE techniques so the
    Join node has something deterministic to merge.

    Returns a dict tracking which runners were called (for sanity checks
    in the parallel vs sequential paths).
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
        state.add_finding(f"Auto-triage (fake): verdict={state.verdict}, confidence={state.confidence}")
        call_log["auto_triage"].append(str(state.incident_id))
        return state

    def _make_runner(name: str, technique: str):
        async def _runner(state: InvestigationState) -> InvestigationState:
            await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
            state.add_finding(f"{name} (fake): triggered on alert")
            if technique not in state.mitre_mappings:
                state.mitre_mappings.append(technique)
            state.verdict = "true_positive"
            # Use slightly different confidences so the Join node has
            # something to pick a winner on.
            state.confidence = max(state.confidence, 0.7 + 0.05 * len(call_log[name]))
            call_log[name].append(str(state.incident_id))
            return state

        return _runner

    fake_phishing = _make_runner("phishing", "T1566.001")
    fake_identity = _make_runner("identity", "T1078")
    fake_cloud = _make_runner("cloud", "T1078.004")
    fake_insider = _make_runner("insider", "T1567.002")

    # Patch both the public façade and the underlying module-level names so
    # the orchestrator's lazy importlib lookup picks up the fakes regardless
    # of which import surface it walks.
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


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


def test_parallel_topology_flag_default_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flag defaults ON in dev / CI / test (unset == enabled)."""
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    assert is_parallel_topology_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "False", "off", "no", "disabled"])
def test_parallel_topology_flag_off_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Operators flip the flag off in prod until the eval scoreboard is green."""
    monkeypatch.setenv(PARALLEL_TOPOLOGY_FLAG, value)
    assert is_parallel_topology_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "on", "yes"])
def test_parallel_topology_flag_on_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(PARALLEL_TOPOLOGY_FLAG, value)
    assert is_parallel_topology_enabled() is True


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def test_classifier_picks_all_four_for_multi_signal_incident() -> None:
    state = _multi_signal_incident()
    state.confidence_basis = ["alert mentions phishing email, lateral movement, AWS S3, data exfil"]
    signals = classify_signals(state)
    assert set(signals) == {"phishing", "identity", "cloud", "insider"}


def test_classifier_default_fans_out_when_nothing_matches() -> None:
    """A bare alert with no matching keywords still fans out to all four.

    This is the safety property: routing should never silently skip a
    capability just because the keyword bag missed it.
    """
    state = InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="generic suspicious activity",
        raw_alert={"severity": "low"},
    )
    assert classify_signals(state) == ["phishing", "identity", "cloud", "insider"]


# ---------------------------------------------------------------------------
# Wall-clock gate — parallel ≥ 30% faster than sequential
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parallel_beats_sequential_by_at_least_30_percent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Substrate self-consistency: parallel topology saves ≥30% wall-clock.

    Each sub-agent shim sleeps for ``SUBAGENT_SLEEP_MS``. With 4 sub-agents
    triggered:

    - sequential wall-clock ≈ 4 · SUBAGENT_SLEEP_MS + AUTO_TRIAGE_SLEEP_MS
    - parallel wall-clock   ≈ 1 · SUBAGENT_SLEEP_MS + AUTO_TRIAGE_SLEEP_MS

    The ratio (parallel / sequential) is ≈ 0.32, well below the 0.7 gate
    (which corresponds to the user-visible ≥30% speed-up).
    """
    _patch_runners(monkeypatch)
    orch = RouterOrchestrator()

    # Sequential run first so any cold-import cost is paid by the slower mode.
    seq_state = _multi_signal_incident()
    t0 = time.perf_counter()
    seq_final, seq_info = await orch.run(seq_state, topology="sequential")
    seq_ms = (time.perf_counter() - t0) * 1000.0

    par_state = _multi_signal_incident()
    t0 = time.perf_counter()
    par_final, par_info = await orch.run(par_state, topology="parallel")
    par_ms = (time.perf_counter() - t0) * 1000.0

    assert seq_info["topology"] == "sequential"
    assert par_info["topology"] == "parallel"
    assert set(seq_info["signals"]) == {"phishing", "identity", "cloud", "insider"}
    assert set(par_info["signals"]) == {"phishing", "identity", "cloud", "insider"}

    # MITRE preservation — exact-equal sets, both modes have to map the
    # same techniques. (Order can differ; we compare as sets.)
    assert set(seq_final.mitre_mappings) == set(par_final.mitre_mappings)
    assert set(seq_final.mitre_mappings) >= {"T1566.001", "T1078", "T1078.004", "T1567.002"}

    # ≥30% speed-up: parallel_ms must be at most 70% of sequential_ms.
    speedup_ratio = par_ms / seq_ms
    assert speedup_ratio <= 0.70, (
        f"Parallel topology did not beat sequential by ≥30%: "
        f"parallel={par_ms:.1f}ms sequential={seq_ms:.1f}ms ratio={speedup_ratio:.3f} "
        f"(seq info={seq_info}, par info={par_info})"
    )


@pytest.mark.asyncio
async def test_auto_close_short_circuits_both_topologies(monkeypatch: pytest.MonkeyPatch) -> None:
    """High-confidence FP / benign auto-triage skips sub-agent fan-out entirely.

    Verifies the router obeys the same auto-close contract the legacy
    workflow already used (``status == COMPLETED`` after auto-triage), so
    the topology flag never accidentally re-opens auto-closed alerts.
    """
    _patch_runners(monkeypatch, auto_close=True)
    orch = RouterOrchestrator()

    for topology in ("parallel", "sequential"):
        state = _multi_signal_incident()
        final, info = await orch.run(state, topology=topology)
        assert final.status == AgentStatus.COMPLETED
        assert info["auto_closed"] is True
        assert info["signals"] == []
        assert final.verdict == "benign"


@pytest.mark.asyncio
async def test_join_node_dedupes_mitre_and_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Join node must dedupe MITRE techniques and findings across branches.

    Without deduplication, an alert that legitimately fans out to multiple
    sub-agents would multi-count techniques and pollute the audit log; the
    Brier-score calibration in T2.4 would then over-weight popular
    techniques. We pin the contract here.
    """
    _patch_runners(monkeypatch)
    orch = RouterOrchestrator()

    state = _multi_signal_incident()
    # Seed a technique the sub-agents will also add — Join must dedupe.
    state.mitre_mappings.append("T1078")
    state.findings.append("seed-finding-to-preserve")

    final, _ = await orch.run(state, topology="parallel")
    # Each technique appears exactly once.
    assert len(final.mitre_mappings) == len(set(final.mitre_mappings))
    # Seed finding survived; the responder summary was appended once.
    assert "seed-finding-to-preserve" in final.findings
    responder_lines = [f for f in final.findings if f.startswith("Responder (dry-run):")]
    assert len(responder_lines) == 1
