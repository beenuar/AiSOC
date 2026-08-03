"""Wave 1 - outcome memory closes the loop.

Proves durable outcome priors are written back on every triage, that a repeat
alert matching a trusted prior benign/FP disposition is auto-suppressed WITHOUT
re-triage (so volume shrinks), and that the trust gate distinguishes human vs
corroborated-AI priors and never auto-closes a prior true-positive.
"""

from __future__ import annotations

import pytest
from app.core.cost_governor import get_governor
from app.memory import institutional
from app.memory.outcomes import (
    AI,
    HUMAN,
    lookup_prior,
    record_outcome,
    should_auto_suppress,
)
from app.workers import fused_alert_consumer as worker_mod
from app.workers.fused_alert_consumer import FusedAlertTriageWorker, build_state

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


def _fused(**alert_overrides) -> dict:
    alert = {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "title": "Scheduled Nessus scan from 10.0.0.5",
        "severity": "medium",
        "hostname": "scanner01",
        "src_ip": "10.0.0.5",
        "mitre_techniques": ["T1046"],
        "risk_score": 0.3,
        "raw_event": {"a": 1},
    }
    alert.update(alert_overrides)
    return {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "incident_id": "33333333-3333-3333-3333-333333333333",
        "fusion_decision": "new_incident",
        "confidence_score": 0.5,
        "alert": alert,
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    institutional._FALLBACK.clear()

    async def _persist_noop(*args, **kwargs):  # noqa: ANN002, ANN003
        return False

    async def _rec_supp(*args, **kwargs):  # noqa: ANN002, ANN003
        return True

    monkeypatch.setattr(worker_mod.ledger_module, "persist_auto_triage", _persist_noop)
    monkeypatch.setattr(worker_mod.ledger_module, "record_suppression", _rec_supp)
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setenv("AISOC_AGENT_ESCALATE_TO_GRAPH", "0")
    monkeypatch.setattr(worker_mod, "resolve_llm_config", _fake_cfg)
    yield
    institutional._FALLBACK.clear()


async def _fake_cfg(_tenant):  # noqa: ANN001
    class _Cfg:
        allowed = False
        api_key = None
        base_url = None
        model = "gpt-4o-mini"

    return _Cfg()


def _signature(message: dict) -> str:
    state = build_state(message)
    assert state is not None
    return get_governor().evidence_fingerprint(str(state.tenant_id), state.raw_alert)


# ── unit: trust gate ─────────────────────────────────────────────────────────


async def test_should_auto_suppress_trust_gate():
    # Human benign prior → always trusted.
    assert should_auto_suppress({"disposition": "false_positive", "author": HUMAN, "count": 1, "confidence": 0.5})
    # AI prior needs corroboration (count) + high confidence.
    assert not should_auto_suppress({"disposition": "benign", "author": AI, "count": 1, "confidence": 0.99})
    assert should_auto_suppress({"disposition": "benign", "author": AI, "count": 3, "confidence": 0.95})
    # A prior true-positive NEVER auto-closes a future alert.
    assert not should_auto_suppress({"disposition": "true_positive", "author": HUMAN, "count": 9, "confidence": 1.0})


async def test_record_and_lookup_roundtrip_and_count_bump():
    v1 = await record_outcome(TENANT, "sig-1", disposition="false_positive", confidence=0.9, author=AI)
    assert v1["count"] == 1
    v2 = await record_outcome(TENANT, "sig-1", disposition="false_positive", confidence=0.92, author=AI)
    assert v2["count"] == 2  # same disposition bumps the count
    prior = await lookup_prior(TENANT, "sig-1")
    assert prior is not None and prior["count"] == 2
    # Human authorship is sticky: a later AI write does not downgrade it.
    await record_outcome(TENANT, "sig-1", disposition="false_positive", confidence=0.5, author=HUMAN)
    assert (await lookup_prior(TENANT, "sig-1"))["author"] == HUMAN
    await record_outcome(TENANT, "sig-1", disposition="false_positive", confidence=0.5, author=AI)
    assert (await lookup_prior(TENANT, "sig-1"))["author"] == HUMAN


# ── worker: forward suppression + write-back ─────────────────────────────────


async def test_repeat_alert_is_suppressed_from_human_prior(monkeypatch):
    msg = _fused()
    sig = _signature(msg)
    # A human previously dispositioned this signature benign.
    await record_outcome(TENANT, sig, disposition="false_positive", confidence=0.95, author=HUMAN)

    # run_triage must NOT be called — suppression short-circuits it.
    called = {"triage": 0}

    async def _no_triage(state):
        called["triage"] += 1
        return state

    monkeypatch.setattr(worker_mod, "run_triage", _no_triage)

    result = await FusedAlertTriageWorker(bootstrap_servers="unused").triage(msg)
    assert result is not None
    assert result["suppressed_by_memory"] is True
    assert result["tier"] == "memory"
    assert result["verdict"] == "false_positive"
    assert called["triage"] == 0  # no re-triage → volume shrinks
    assert FusedAlertTriageWorker.get_metrics()["outcome_suppressed"] >= 1


async def test_no_suppression_without_trusted_prior():
    # A single low-confidence AI prior is NOT enough to suppress.
    msg = _fused()
    sig = _signature(msg)
    await record_outcome(TENANT, sig, disposition="benign", confidence=0.5, author=AI)
    result = await FusedAlertTriageWorker(bootstrap_servers="unused").triage(msg)
    assert result is not None
    assert result.get("suppressed_by_memory") is not True  # normal triage ran


async def test_triage_writes_outcome_prior_back(monkeypatch):
    # Deterministic triage produces a verdict; it must be written back as a prior.
    msg = _fused()
    sig = _signature(msg)
    assert await lookup_prior(TENANT, sig) is None
    await FusedAlertTriageWorker(bootstrap_servers="unused").triage(msg)
    prior = await lookup_prior(TENANT, sig)
    assert prior is not None
    assert prior["author"] == AI
    assert prior["disposition"]  # a real verdict was recorded
