"""Wave 5a — cost-aware cheap-first model cascade."""

from __future__ import annotations

import pytest
from app.routing.cascade import cost_aware_cascade


def _conf(r):
    return r["confidence"]


@pytest.mark.asyncio
async def test_confident_cheap_answer_skips_strong_tier():
    strong_called = {"n": 0}

    async def cheap():
        return {"verdict": "false_positive", "confidence": 0.9}

    async def strong():
        strong_called["n"] += 1
        return {"verdict": "true_positive", "confidence": 0.99}

    out = await cost_aware_cascade(cheap=cheap, strong=strong, extract_confidence=_conf, confidence_floor=0.75)
    assert out.tier_used == "cheap"
    assert out.escalated is False
    assert strong_called["n"] == 0  # never paid for the strong model


@pytest.mark.asyncio
async def test_uncertain_cheap_answer_escalates_to_strong():
    async def cheap():
        return {"verdict": "needs_review", "confidence": 0.4}

    async def strong():
        return {"verdict": "true_positive", "confidence": 0.95}

    out = await cost_aware_cascade(cheap=cheap, strong=strong, extract_confidence=_conf, confidence_floor=0.75)
    assert out.tier_used == "strong"
    assert out.escalated is True
    assert out.result["verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_strong_tier_failure_degrades_to_cheap():
    async def cheap():
        return {"verdict": "benign", "confidence": 0.3}

    async def strong():
        raise RuntimeError("provider 500")

    out = await cost_aware_cascade(cheap=cheap, strong=strong, extract_confidence=_conf, confidence_floor=0.75)
    assert out.tier_used == "cheap"
    assert out.escalated is True
    assert out.strong_error is not None
    assert out.result["verdict"] == "benign"
