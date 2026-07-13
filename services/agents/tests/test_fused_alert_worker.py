"""Phase B1 — auto-triage worker tests.

Proves every fused alert is auto-triaged (deterministically, no LLM key — the
copilot / air-gapped / CI default), that triage is READ-ONLY (no response is
ever dispatched; proposed actions require approval), that the cost governor's
dedup + circuit-breaker paths are honored, and that state-mapping + fail-soft
behavior hold.
"""

from __future__ import annotations

import uuid

import pytest
from app.core.cost_governor import Decision, GovernorDecision
from app.workers import fused_alert_consumer as worker_mod
from app.workers.fused_alert_consumer import FusedAlertTriageWorker, build_state

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


def _fused(**alert_overrides) -> dict:
    alert = {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "title": "Credential dumping via LSASS access",
        "severity": "critical",
        "hostname": "WIN-DC01",
        "username": "svc-backup",
        "src_ip": "10.20.30.40",
        "mitre_techniques": ["T1003"],
        "risk_score": 0.9,
        "raw_event": {"a": 1},
    }
    alert.update(alert_overrides)
    return {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "incident_id": "33333333-3333-3333-3333-333333333333",
        "fusion_decision": "new_incident",
        "confidence_score": 0.8,
        "narrative": "Fusion correlated 3 signals.",
        "alert": alert,
    }


@pytest.fixture(autouse=True)
def _no_ledger_db(monkeypatch):
    # Ledger writes are best-effort; make them explicit no-ops in tests.
    async def _noop(*args, **kwargs):  # noqa: ANN002, ANN003
        return None

    monkeypatch.setattr(worker_mod.ledger_module, "start_run", _noop)
    monkeypatch.setattr(worker_mod.ledger_module, "complete_run", _noop)
    # Force the deterministic path unless a test overrides (no LLM key in CI).
    monkeypatch.setenv("AISOC_DETERMINISTIC", "0")


def _worker() -> FusedAlertTriageWorker:
    return FusedAlertTriageWorker(bootstrap_servers="unused")


# ── state mapping ─────────────────────────────────────────────────────────────


async def test_build_state_maps_fused_alert():
    state = build_state(_fused())
    assert str(state.tenant_id) == TENANT
    assert "Credential dumping" in state.alert_summary
    assert state.raw_alert["hostname"] == "WIN-DC01"
    assert state.raw_alert["mitre_techniques"] == ["T1003"]


async def test_build_state_rejects_non_alert():
    assert build_state({"tenant_id": TENANT}) is None
    assert build_state("nope") is None


# ── auto-triage (deterministic default) ──────────────────────────────────────


async def test_every_alert_is_triaged_deterministically_without_llm(monkeypatch):
    # No LLM key => deterministic tier.
    monkeypatch.setattr(worker_mod, "resolve_llm_config", _fake_llm_config(allowed=False))
    result = await _worker().triage(_fused())
    assert result is not None
    assert result["tier"] == "deterministic"
    assert result["verdict"] is not None
    assert result["confidence"] >= 0.0


async def test_triage_is_read_only_no_response_dispatched(monkeypatch):
    monkeypatch.setattr(worker_mod, "resolve_llm_config", _fake_llm_config(allowed=False))
    result = await _worker().triage(_fused())
    # Copilot default: never dispatches a response; a critical alert proposes an
    # isolate_host action but it REQUIRES approval.
    assert result["response_dispatched"] is False
    assert any(a["action_type"] == "isolate_host" and a["requires_approval"] for a in result["proposed_actions"])


async def test_deterministic_mode_forces_deterministic_even_with_key(monkeypatch):
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setattr(worker_mod, "resolve_llm_config", _fake_llm_config(allowed=True))
    result = await _worker().triage(_fused())
    assert result["tier"] == "deterministic"


# ── cost governor integration ────────────────────────────────────────────────


async def test_dedup_cache_short_circuits(monkeypatch):
    cached = GovernorDecision(
        decision=Decision.DEDUPLICATED,
        reason="dup",
        remaining_usd=10.0,
        cached_verdict={"verdict": "true_positive", "confidence": 0.91},
    )
    monkeypatch.setattr(worker_mod, "get_governor", lambda: _FakeGovernor(cached))
    result = await _worker().triage(_fused())
    assert result["tier"] == "cached"
    assert result["verdict"] == "true_positive"
    assert result["confidence"] == 0.91


async def test_circuit_open_forces_deterministic(monkeypatch):
    open_decision = GovernorDecision(decision=Decision.CIRCUIT_OPEN, reason="budget", remaining_usd=0.0)
    monkeypatch.setattr(worker_mod, "get_governor", lambda: _FakeGovernor(open_decision))
    monkeypatch.setattr(worker_mod, "resolve_llm_config", _fake_llm_config(allowed=True))
    result = await _worker().triage(_fused())
    assert result["tier"] == "deterministic"


# ── fail-soft ─────────────────────────────────────────────────────────────────


async def test_unprocessable_message_returns_none():
    assert await _worker().triage({"garbage": True}) is None


async def test_worker_enabled_flag(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)
    assert worker_mod.worker_enabled() is False
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    assert worker_mod.worker_enabled() is True
    monkeypatch.setenv("AISOC_AGENT_KAFKA_DISABLE", "1")
    assert worker_mod.worker_enabled() is False


# ── helpers ───────────────────────────────────────────────────────────────────


def _fake_llm_config(*, allowed: bool):
    class _Cfg:
        def __init__(self) -> None:
            self.allowed = allowed
            self.api_key = "sk-test" if allowed else None

    async def _resolve(_tenant):  # noqa: ANN001
        return _Cfg()

    return _resolve


class _FakeGovernor:
    def __init__(self, decision: GovernorDecision) -> None:
        self._decision = decision

    def evidence_fingerprint(self, tenant_id, alert):  # noqa: ANN001, ARG002
        return "fp-" + str(uuid.uuid4())

    def check(self, tenant_id, fingerprint):  # noqa: ANN001, ARG002
        return self._decision
