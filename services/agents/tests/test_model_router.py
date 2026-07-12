"""Phase 7 — the multi-model router contract.

Proves the router (a) picks the cheapest sufficient tier, (b) attributes every
decision to a tier, (c) NEVER silently uses the LLM (a skipped/blocked LLM tier
is always recorded), and (d) honours the determinism contract: in deterministic
mode it never touches ML/LLM and is reproducible.

The tiers are injected as plain functions so the contract is proven without any
real model — that is the point of the router: one auditable place for the
deterministic→ML→LLM ladder.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from app.routing.model_router import (
    DETERMINISTIC_ENV_FLAG,
    ModelRouter,
    ModelTier,
    RoutingRequest,
    TierResult,
    is_deterministic_mode,
)

pytestmark = pytest.mark.asyncio

REQ = RoutingRequest(payload={"title": "suspicious login", "severity": "high"})


def _tier(conf: float, label: str):
    def fn(_request):
        return TierResult(output={"by": label}, confidence=conf, reason=f"{label} says {conf}", model=label)

    return fn


def _exploding_tier(_request):
    raise RuntimeError("provider 500")


async def test_confident_deterministic_wins_and_llm_never_called():
    llm_calls = {"n": 0}

    def llm(_r):
        llm_calls["n"] += 1
        return TierResult(output={}, confidence=1.0, model="llm")

    router = ModelRouter(deterministic_fn=_tier(0.95, "det"), ml_fn=_tier(0.99, "ml"), llm_fn=llm)
    decision = await router.route(REQ)

    assert decision.tier is ModelTier.DETERMINISTIC
    assert decision.deterministic is True
    assert llm_calls["n"] == 0  # the whole point — cheap tier answered
    assert decision.tiers_considered == ["deterministic"]
    assert any("confident" in a for a in decision.attribution)


async def test_low_confidence_escalates_deterministic_to_ml_to_llm():
    router = ModelRouter(
        deterministic_fn=_tier(0.2, "det"),
        ml_fn=_tier(0.4, "ml"),
        llm_fn=_tier(0.9, "llm"),
    )
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.LLM
    assert decision.tiers_considered == ["deterministic", "ml", "llm"]


async def test_ml_wins_when_confident_and_llm_not_reached():
    llm_calls = {"n": 0}

    def llm(_r):
        llm_calls["n"] += 1
        return TierResult(output={}, confidence=1.0, model="llm")

    router = ModelRouter(deterministic_fn=_tier(0.1, "det"), ml_fn=_tier(0.95, "ml"), llm_fn=llm)
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.ML
    assert llm_calls["n"] == 0


async def test_no_silent_llm_when_llm_tier_absent():
    """Low-confidence deterministic + no LLM tier: must fall back to
    deterministic AND record why the escalation was blocked — never silent."""
    router = ModelRouter(deterministic_fn=_tier(0.3, "det"), ml_fn=None, llm_fn=None)
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.DETERMINISTIC
    assert decision.escalation_blocked_reason == "no ML/LLM tier configured"


async def test_llm_failure_degrades_to_best_lower_tier_with_reason():
    router = ModelRouter(
        deterministic_fn=_tier(0.3, "det"),
        ml_fn=_tier(0.5, "ml"),
        llm_fn=_exploding_tier,
    )
    decision = await router.route(REQ)
    # ML was the best lower tier (0.5 > 0.3); LLM blew up → fall back to ML.
    assert decision.tier is ModelTier.ML
    assert decision.escalation_blocked_reason is not None
    assert "LLM tier failed" in decision.escalation_blocked_reason


async def test_deterministic_only_never_touches_ml_or_llm():
    ml_calls = {"n": 0}
    llm_calls = {"n": 0}

    def ml(_r):
        ml_calls["n"] += 1
        return TierResult(output={}, confidence=1.0, model="ml")

    def llm(_r):
        llm_calls["n"] += 1
        return TierResult(output={}, confidence=1.0, model="llm")

    # Deterministic tier is LOW confidence, so absent the flag it would escalate.
    router = ModelRouter(deterministic_fn=_tier(0.1, "det"), ml_fn=ml, llm_fn=llm, deterministic_only=True)
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.DETERMINISTIC
    assert decision.deterministic is True
    assert ml_calls["n"] == 0 and llm_calls["n"] == 0
    assert any("deterministic-only" in a for a in decision.attribution)


async def test_env_flag_forces_deterministic_mode(monkeypatch):
    monkeypatch.setenv(DETERMINISTIC_ENV_FLAG, "1")
    assert is_deterministic_mode() is True
    router = ModelRouter(deterministic_fn=_tier(0.1, "det"), ml_fn=_tier(0.99, "ml"), llm_fn=_tier(0.99, "llm"))
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.DETERMINISTIC


async def test_governor_circuit_open_forces_deterministic():
    class OpenGovernor:
        def check(self, tenant_id, fingerprint):  # noqa: ANN001, ARG002
            return SimpleNamespace(use_llm=False, decision=SimpleNamespace(value="circuit_open"))

    router = ModelRouter(
        deterministic_fn=_tier(0.1, "det"),
        ml_fn=_tier(0.99, "ml"),
        llm_fn=_tier(0.99, "llm"),
        governor=OpenGovernor(),
    )
    decision = await router.route(REQ)
    assert decision.tier is ModelTier.DETERMINISTIC
    assert any("cost governor" in a for a in decision.attribution)


async def test_determinism_contract_identical_input_identical_decision():
    """The headline contract: in deterministic mode, the same input twice
    yields an identical decision (the deterministic tier is pure)."""
    router = ModelRouter(deterministic_fn=_tier(0.42, "det"), ml_fn=_tier(0.9, "ml"), deterministic_only=True)
    d1 = await router.route(REQ)
    d2 = await router.route(REQ)
    assert d1.to_dict() == d2.to_dict()


async def test_every_decision_is_attributed():
    for det_conf in (0.05, 0.5, 0.95):
        router = ModelRouter(deterministic_fn=_tier(det_conf, "det"), ml_fn=_tier(0.5, "ml"), llm_fn=_tier(0.99, "llm"))
        decision = await router.route(REQ)
        assert decision.attribution, "every decision must carry an attribution trail"
        assert decision.model_used
        assert decision.tiers_considered


async def test_fingerprint_is_stable_and_order_independent():
    a = RoutingRequest(payload={"x": 1, "y": 2})
    b = RoutingRequest(payload={"y": 2, "x": 1})
    assert a.fingerprint() == b.fingerprint()


async def test_is_deterministic_mode_default_off(monkeypatch):
    monkeypatch.delenv(DETERMINISTIC_ENV_FLAG, raising=False)
    assert is_deterministic_mode() is False
    assert os.environ.get(DETERMINISTIC_ENV_FLAG) is None
