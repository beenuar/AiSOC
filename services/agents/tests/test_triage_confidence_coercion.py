"""A verdict must not be discarded because the confidence field was odd.

``float(data.get("confidence", 0.5))`` was unguarded, so a reply of
``"confidence": "high"`` raised ``ValueError``; the caller converts that into an
``AutoTriageError`` and falls back to deterministic triage, throwing away a
verdict and rationale that may have been perfectly good.

This was not the cause of the measured failures — those were all malformed
``rationale`` — but it is reachable by any model, and a fallback nobody can
explain is worse than one that names its reason.

The safety property this must not break: the *verdict* still fails closed. A
degraded confidence lands at 0.5, below the 0.85 auto-close default, so it
routes to a human.
"""

from __future__ import annotations

import json

import pytest
from app.agents.auto_triage_agent import AUTO_CLOSE_THRESHOLD, _parse_llm_response


def _reply(confidence: object) -> str:
    return json.dumps({"verdict": "benign", "confidence": confidence, "rationale": "because"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (0.8, 0.8),
        (1, 1.0),
        (0, 0.0),
        ("0.8", 0.8),
        ("  0.8  ", 0.8),
        ("85%", 0.85),
        ("85", 0.85),  # a bare out-of-range number is a percentage
        (1.7, 1.0),  # clamped
        (-0.4, 0.0),  # clamped
    ],
)
def test_reads_the_confidences_a_model_actually_emits(raw: object, expected: float) -> None:
    assert _parse_llm_response(_reply(raw))["confidence"] == pytest.approx(expected)


@pytest.mark.parametrize("raw", ["high", "very confident", "", None, True, False, [], {}])
def test_unreadable_confidence_keeps_the_verdict_instead_of_raising(raw: object) -> None:
    """The regression: this used to raise and discard the whole reply."""
    parsed = _parse_llm_response(_reply(raw))
    assert parsed["verdict"] == "benign"
    assert parsed["rationale"] == "because"
    assert 0.0 <= parsed["confidence"] <= 1.0


@pytest.mark.parametrize("raw", ["high", None, True])
def test_a_degraded_confidence_cannot_auto_close(raw: object) -> None:
    """The safety property. An unread field must not close an alert."""
    assert _parse_llm_response(_reply(raw))["confidence"] < AUTO_CLOSE_THRESHOLD


def test_a_missing_confidence_still_defaults() -> None:
    parsed = _parse_llm_response(json.dumps({"verdict": "benign", "rationale": "r"}))
    assert parsed["confidence"] < AUTO_CLOSE_THRESHOLD


def test_an_unparseable_reply_still_fails_closed() -> None:
    """Tolerance for one odd field must not become tolerance for anything.

    The fail-closed contract is the reason this module is trusted; a reply that
    is not a JSON object still raises so the caller falls back.
    """
    with pytest.raises(Exception):  # noqa: B017 — any failure is the contract
        _parse_llm_response("I think this alert is probably fine, honestly")
