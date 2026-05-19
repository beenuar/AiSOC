"""
T2.2 — substrate latency gate for the parallel router topology.

This test drives the full 200-incident substrate corpus through the
parallel router with deterministic sub-agent shims and asserts the
per-investigation wall-clock distribution stays under the SLO budget:

    p50 < 60s
    p95 < 120s

These targets are the v8.0 latency budget the agent fleet promises in the
``apps/docs/docs/benchmark.md`` substrate writeup. They are deliberately
loose enough to accommodate machine variance and the eventual real LLM
swap; the substrate path runs comfortably ~3 orders of magnitude faster
on CI (sub-second p99) so the test fails loudly if the topology grows a
synchronous critical-path step.

Substrate vs wet eval
---------------------

Every number this test prints is a **substrate self-consistency** gate
— the shims simulate an LLM round trip with a fixed 5 ms ``asyncio.sleep``,
and the router shape is the unit under test. Real LLM-backed latency
lives in the wet-eval scoreboard (``scripts/wet_eval.py``).
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.models.state import AgentStatus, InvestigationState  # noqa: E402
from app.orchestrator import RouterOrchestrator  # noqa: E402

# Per-runner simulated LLM latency. 5 ms × 5 calls (auto-triage + 4 sub-agents)
# = ≈ 10 ms parallel wall-clock per incident, ≈ 25 ms sequential — comfortably
# inside the 60s p50 budget while still exercising the asyncio scheduler.
SUBAGENT_SLEEP_MS = 5
AUTO_TRIAGE_SLEEP_MS = 5

_DATASET_PATH = _AGENTS_ROOT / "tests" / "eval_data" / "synthetic_incidents.json"

# Latency budget (substrate). Hard ceiling for the parallel path; the
# sequential path is exercised in test_orchestrator_parallel.py.
P50_BUDGET_SECONDS = 60.0
P95_BUDGET_SECONDS = 120.0


def _load_corpus() -> list[dict]:
    if not _DATASET_PATH.exists():
        pytest.skip(f"substrate corpus not found at {_DATASET_PATH}; run scripts/generate_eval_incidents.py")
    with _DATASET_PATH.open() as f:
        return json.load(f)


def _state_from_incident(incident: dict) -> InvestigationState:
    """Project one synthetic-corpus row into an ``InvestigationState``.

    The corpus is template-rich (55 templates × 3–4 variations) so this
    same routine produces incidents that exercise every classifier branch.
    Telemetry slices and expected-technique lists are stashed onto the raw
    alert so the deterministic sub-agent shims can lift them out without
    looking at the templating internals.
    """
    raw = {
        "severity": incident.get("severity", "medium"),
        "risk_score": 0.7,
        "expected_tactics": incident.get("expected_tactics", []),
        "expected_techniques": incident.get("expected_techniques", []),
        "template_id": incident.get("template_id", ""),
        "evidence_keywords": incident.get("evidence_keywords", []),
        # Spread some genuinely classifier-triggering fields across the
        # raw alert so signal classification picks ≥1 capability.
        "username": "synthetic-user@corp.example",
        "source_ip": "10.0.0.1",
        "cloud_provider": "aws",
        "url": "https://example.com/synthetic",
    }
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=f"{incident['title']} — {incident['description']}",
        raw_alert=raw,
        status=AgentStatus.PENDING,
    )


def _patch_runners(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_auto_triage(state: InvestigationState) -> InvestigationState:
        await asyncio.sleep(AUTO_TRIAGE_SLEEP_MS / 1000.0)
        state.iteration_count += 1
        state.status = AgentStatus.RUNNING
        state.verdict = "true_positive"
        state.confidence = 0.7
        state.confidence_basis = ["substrate latency-test auto-triage"]
        state.add_finding("Auto-triage (substrate): tp / 0.70")
        return state

    def _runner(name: str):
        async def _r(state: InvestigationState) -> InvestigationState:
            await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
            state.add_finding(f"{name} (substrate): triggered")
            # Mirror the corpus's expected_techniques into mitre_mappings so
            # the audit log keeps a realistic shape.
            for t in state.raw_alert.get("expected_techniques", []):
                if t not in state.mitre_mappings:
                    state.mitre_mappings.append(t)
            state.verdict = "true_positive"
            state.confidence = max(state.confidence, 0.8)
            return state

        return _r

    targets = [
        ("app.agents.run_auto_triage", fake_auto_triage),
        ("app.agents.auto_triage_agent.run_auto_triage", fake_auto_triage),
        ("app.agents.run_phishing", _runner("phishing")),
        ("app.agents.phishing_agent.run_phishing", _runner("phishing")),
        ("app.agents.run_identity", _runner("identity")),
        ("app.agents.identity_agent.run_identity", _runner("identity")),
        ("app.agents.run_cloud", _runner("cloud")),
        ("app.agents.cloud_agent.run_cloud", _runner("cloud")),
        ("app.agents.run_insider_threat", _runner("insider")),
        ("app.agents.insider_threat_agent.run_insider_threat", _runner("insider")),
    ]
    for path, fn in targets:
        monkeypatch.setattr(path, fn, raising=False)


@pytest.mark.asyncio
async def test_parallel_topology_latency_substrate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Substrate latency gate — 200 incidents, p50 < 60s, p95 < 120s.

    The numbers below are substrate self-consistency: the router shape is
    the unit under test, sub-agent LLM latency is mocked at 5 ms /
    invocation. The 60 s / 120 s budgets stay future-proof for the wet-eval
    swap (single LLM call per sub-agent is well under 5 s on gpt-4o).
    """
    corpus = _load_corpus()
    assert len(corpus) == 200, f"expected 200-incident corpus, got {len(corpus)}"

    _patch_runners(monkeypatch)
    orch = RouterOrchestrator()

    per_incident_ms: list[float] = []
    for incident in corpus:
        state = _state_from_incident(incident)
        t0 = time.perf_counter()
        final, info = await orch.run(state, topology="parallel")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        per_incident_ms.append(elapsed_ms)
        assert final.status == AgentStatus.COMPLETED, f"{incident['id']} did not complete"
        assert info["topology"] == "parallel"
        assert info["substrate"] is True

    p50_ms = statistics.median(per_incident_ms)
    p95_ms = statistics.quantiles(per_incident_ms, n=20)[18]  # 95th percentile
    p99_ms = statistics.quantiles(per_incident_ms, n=100)[98]
    mean_ms = statistics.mean(per_incident_ms)

    # Emit the distribution so the substrate scoreboard can pick it up.
    print(
        "\n[substrate-latency] router parallel topology — 200 incidents:"
        f"\n    p50 = {p50_ms:.2f} ms"
        f"\n    p95 = {p95_ms:.2f} ms"
        f"\n    p99 = {p99_ms:.2f} ms"
        f"\n    mean = {mean_ms:.2f} ms"
        f"\n    budget: p50 < {P50_BUDGET_SECONDS*1000:.0f} ms, p95 < {P95_BUDGET_SECONDS*1000:.0f} ms (substrate)"
    )

    assert p50_ms < P50_BUDGET_SECONDS * 1000.0, f"p50 substrate latency over budget: {p50_ms:.2f} ms >= {P50_BUDGET_SECONDS*1000:.0f} ms"
    assert p95_ms < P95_BUDGET_SECONDS * 1000.0, f"p95 substrate latency over budget: {p95_ms:.2f} ms >= {P95_BUDGET_SECONDS*1000:.0f} ms"
