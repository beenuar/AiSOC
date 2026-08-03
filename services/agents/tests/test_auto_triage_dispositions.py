"""#526 — benign_true_positive disposition in LLM auto-triage.

Covers the four required outcomes (approved pen-test, scheduled scanner,
genuine false positive, malicious true positive), the parser/normalization
layer, and the invariant that a benign true positive is never counted as a
false positive.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.agents import auto_triage_agent as ata
from app.agents.dispositions import (
    AUTO_CLOSEABLE_DISPOSITIONS,
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    FALSE_POSITIVE,
    INVALID_DETECTION_DISPOSITIONS,
    NEEDS_REVIEW,
    TRUE_POSITIVE,
    normalize_disposition,
)
from app.models.state import AgentStatus, InvestigationState


def _state(summary: str, raw: dict) -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=summary,
        raw_alert=raw,
        status=AgentStatus.PENDING,
    )


def _patch_llm(monkeypatch, verdict: str, confidence: float, rationale: str = "because") -> None:
    payload = json.dumps({"verdict": verdict, "confidence": confidence, "rationale": rationale})

    async def _fake_ainvoke(_llm, _messages):
        return SimpleNamespace(content=payload)

    monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())
    monkeypatch.setattr(ata, "safe_ainvoke", _fake_ainvoke)


# --- parser + normalization layer ------------------------------------------


def test_parser_accepts_benign_true_positive():
    out = ata._parse_llm_response('{"verdict": "benign_true_positive", "confidence": 0.9, "rationale": "approved pentest"}')
    assert out["verdict"] == BENIGN_TRUE_POSITIVE


def test_parser_normalizes_synonym_and_spacing():
    assert ata._parse_llm_response('{"verdict": "BTP", "confidence": 0.9}')["verdict"] == BENIGN_TRUE_POSITIVE
    assert ata._parse_llm_response('{"verdict": "benign true positive", "confidence": 0.9}')["verdict"] == BENIGN_TRUE_POSITIVE


def test_parser_unknown_verdict_fails_safe_to_true_positive():
    out = ata._parse_llm_response('{"verdict": "banana", "confidence": 0.9}')
    assert out["verdict"] == TRUE_POSITIVE


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("likely_true_positive", TRUE_POSITIVE),
        ("likely_benign", BENIGN),
        ("likely_false_positive", FALSE_POSITIVE),
        ("needs_human_review", NEEDS_REVIEW),
        ("confirmed_incident", TRUE_POSITIVE),
        ("probable_incident", TRUE_POSITIVE),
        ("benign_true_positive", BENIGN_TRUE_POSITIVE),
    ],
)
def test_normalize_bridges_deterministic_and_llm_vocabularies(raw, expected):
    assert normalize_disposition(raw) == expected


def test_btp_is_a_valid_detection_not_a_false_positive():
    # The core invariant of #526: BTP is a valid detection kept out of the FP
    # set (so it never corrupts false-positive-rate metrics), yet still safe to
    # auto-close because no active threat / response is warranted.
    assert BENIGN_TRUE_POSITIVE not in INVALID_DETECTION_DISPOSITIONS
    assert FALSE_POSITIVE in INVALID_DETECTION_DISPOSITIONS
    assert BENIGN_TRUE_POSITIVE in AUTO_CLOSEABLE_DISPOSITIONS


# --- end-to-end scenarios via a mocked LLM ---------------------------------


@pytest.mark.asyncio
async def test_approved_penetration_test_is_benign_true_positive(monkeypatch):
    _patch_llm(monkeypatch, BENIGN_TRUE_POSITIVE, 0.95, "approved red-team engagement, matches change ticket")
    out = await ata.run_auto_triage(_state("Credential dumping on HR-LAPTOP", {"severity": "high", "risk_score": 0.8}))
    assert out.verdict == BENIGN_TRUE_POSITIVE
    # A valid detection of authorized activity is auto-closeable, not escalated.
    assert out.status == AgentStatus.COMPLETED


@pytest.mark.asyncio
async def test_scheduled_scanner_is_benign_true_positive(monkeypatch):
    _patch_llm(monkeypatch, BENIGN_TRUE_POSITIVE, 0.9, "source matches the authorized Nessus scanner window")
    out = await ata.run_auto_triage(_state("Port scan from 10.0.0.5", {"severity": "medium", "risk_score": 0.4}))
    assert out.verdict == BENIGN_TRUE_POSITIVE


@pytest.mark.asyncio
async def test_genuine_false_positive(monkeypatch):
    _patch_llm(monkeypatch, FALSE_POSITIVE, 0.92, "rule misfired on a mis-parsed command-line field")
    out = await ata.run_auto_triage(_state("Suspicious PowerShell", {"severity": "low", "risk_score": 0.1}))
    assert out.verdict == FALSE_POSITIVE
    assert out.status == AgentStatus.COMPLETED


@pytest.mark.asyncio
async def test_malicious_true_positive_escalates(monkeypatch):
    _patch_llm(monkeypatch, TRUE_POSITIVE, 0.97, "active C2 beacon to a known-bad IP")
    out = await ata.run_auto_triage(_state("Beaconing to 45.9.148.99", {"severity": "critical", "risk_score": 0.95}))
    assert out.verdict == TRUE_POSITIVE
    # A malicious true positive must never auto-close.
    assert out.status != AgentStatus.COMPLETED


@pytest.mark.asyncio
async def test_btp_metric_is_tracked_separately_from_fp(monkeypatch):
    ata._metrics.update({"fp_count": 0, "btp_count": 0, "benign_count": 0, "tp_count": 0, "total_processed": 0, "confidence_sum": 0.0})
    _patch_llm(monkeypatch, BENIGN_TRUE_POSITIVE, 0.95, "approved pentest")
    await ata.run_auto_triage(_state("cred dump", {"severity": "high"}))
    m = ata.get_metrics()
    assert m["btp_count"] == 1
    assert m["fp_count"] == 0
    assert m["btp_rate"] > 0
