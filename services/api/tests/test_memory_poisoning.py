"""Tests for memory-poisoning defenses (Phase 1.2).

Pure/offline (stdlib + the pure app.services.memory_poisoning module). Runs in
the api job's unfiltered `pytest tests/`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.services.memory_poisoning import (
    DEFAULT_MAX_REDISPOSITION_BATCH,
    DispositionEvent,
    MemoryAuthor,
    MemoryProvenance,
    PoisoningDetector,
    compute_confirmation_token,
    plan_redisposition,
    trust_weight,
)

NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=UTC)


# ── Trust weighting + decay ──────────────────────────────────────────────────


def test_trust_weight_ordering():
    assert trust_weight(MemoryAuthor.HUMAN_VERIFIED) > trust_weight(MemoryAuthor.AUTONOMOUS)
    assert trust_weight(MemoryAuthor.AUTONOMOUS) > trust_weight(MemoryAuthor.IMPORTED)
    assert trust_weight("nonsense") == 0.0
    assert trust_weight("human_verified") == 1.0


def test_effective_confidence_decays_with_age():
    prov = MemoryProvenance(
        author=MemoryAuthor.HUMAN_VERIFIED,
        tenant_id="t1",
        source_alert_id="a1",
        confidence=1.0,
        recorded_at=NOW,
    )
    fresh = prov.effective_confidence(NOW, half_life_days=30)
    half = prov.effective_confidence(NOW + timedelta(days=30), half_life_days=30)
    quarter = prov.effective_confidence(NOW + timedelta(days=60), half_life_days=30)
    assert fresh == pytest.approx(1.0)
    assert half == pytest.approx(0.5, abs=0.01)
    assert quarter == pytest.approx(0.25, abs=0.01)


def test_autonomous_memory_outranked_by_human():
    human = MemoryProvenance(MemoryAuthor.HUMAN_VERIFIED, "t", "a", confidence=1.0, recorded_at=NOW)
    auto = MemoryProvenance(MemoryAuthor.AUTONOMOUS, "t", "a", confidence=1.0, recorded_at=NOW)
    assert human.effective_confidence(NOW) > auto.effective_confidence(NOW)


def test_provenance_to_dict_has_no_anonymous_memory():
    prov = MemoryProvenance(MemoryAuthor.AUTONOMOUS, "t1", "a1", analyst_id=None, recorded_at=NOW)
    d = prov.to_dict()
    assert d["author"] == "autonomous"
    assert d["tenant_id"] == "t1"
    assert d["source_alert_id"] == "a1"
    assert d["trust_weight"] == trust_weight(MemoryAuthor.AUTONOMOUS)


# ── Confirmation token + re-disposition plan ─────────────────────────────────


def test_confirmation_token_is_order_independent_and_binding():
    t1 = compute_confirmation_token(["a", "b", "c"], "false_positive")
    t2 = compute_confirmation_token(["c", "a", "b"], "false_positive")
    assert t1 == t2  # order-independent (set semantics)
    assert compute_confirmation_token(["a", "b"], "false_positive") != t1  # different set
    assert compute_confirmation_token(["a", "b", "c"], "benign") != t1  # different disposition


def test_plan_token_matches_and_caps_batch():
    ids = [f"alert-{i}" for i in range(500)]
    plan = plan_redisposition(ids, "false_positive", max_batch=200)
    assert plan.capped is True
    assert len(plan.alert_ids) == 200
    assert plan.total_matched == 500
    assert plan.confirmation_token == compute_confirmation_token(plan.alert_ids, "false_positive")
    assert any("capped" in r for r in plan.reasons)


def test_plan_quarantines_when_flagged():
    plan = plan_redisposition(["a", "b"], "false_positive", flagged=True)
    assert plan.quarantined is True
    assert any("flagged" in r for r in plan.reasons)


def test_plan_default_cap():
    assert DEFAULT_MAX_REDISPOSITION_BATCH == 200


# ── Poisoning detector ───────────────────────────────────────────────────────


def _fp_burst(sig: str, n: int, *, author: MemoryAuthor, start: datetime, spacing_s: int = 10, analyst_id=None):
    return [
        DispositionEvent(
            signature_key=sig,
            disposition="false_positive",
            author=author,
            at=start + timedelta(seconds=i * spacing_s),
            analyst_id=analyst_id,
        )
        for i in range(n)
    ]


def test_detector_flags_autonomous_fp_burst():
    sig = "override:v2:deadbeef"
    events = _fp_burst(sig, 30, author=MemoryAuthor.AUTONOMOUS, start=NOW - timedelta(minutes=10))
    detector = PoisoningDetector(window_seconds=3600, min_fp_burst=10)
    verdict = detector.assess(sig, events, now=NOW)
    assert verdict.flagged is True
    assert verdict.should_block_autoclose is True
    assert verdict.fp_count == 30
    assert verdict.reasons


def test_detector_ignores_slow_human_corrections():
    sig = "override:v2:cafe"
    # 6 human corrections spread over 6 days — normal analyst tuning, not a burst.
    events = [
        DispositionEvent(sig, "false_positive", MemoryAuthor.HUMAN_VERIFIED, NOW - timedelta(days=d), analyst_id=f"u{d}") for d in range(6)
    ]
    detector = PoisoningDetector(window_seconds=3600, min_fp_burst=10)
    verdict = detector.assess(sig, events, now=NOW)
    assert verdict.flagged is False


def test_detector_not_flagged_when_humans_confirm():
    sig = "override:v2:beef"
    events = _fp_burst(sig, 20, author=MemoryAuthor.HUMAN_VERIFIED, start=NOW - timedelta(minutes=5), analyst_id="analyst-1")
    # Many, but all human-verified confirmations -> above the human threshold -> trusted.
    detector = PoisoningDetector(window_seconds=3600, min_fp_burst=10, max_human_confirmations=2)
    verdict = detector.assess(sig, events, now=NOW)
    assert verdict.flagged is False


def test_detector_ignores_events_outside_window():
    sig = "override:v2:old"
    events = _fp_burst(sig, 30, author=MemoryAuthor.AUTONOMOUS, start=NOW - timedelta(days=2))
    detector = PoisoningDetector(window_seconds=3600, min_fp_burst=10)
    verdict = detector.assess(sig, events, now=NOW)
    assert verdict.fp_count == 0
    assert verdict.flagged is False


def test_detector_scopes_to_signature():
    sig_a = "override:v2:a"
    sig_b = "override:v2:b"
    events = _fp_burst(sig_a, 30, author=MemoryAuthor.AUTONOMOUS, start=NOW - timedelta(minutes=10))
    detector = PoisoningDetector(min_fp_burst=10)
    assert detector.assess(sig_a, events, now=NOW).flagged is True
    assert detector.assess(sig_b, events, now=NOW).flagged is False


# ── The eval: farming attack must not teach auto-close ───────────────────────


def test_farming_attack_then_real_attack_is_not_auto_closed():
    """Attacker farms benign alerts under a signature, closes them FP, then
    runs the real technique. The detector must flag the signature and the
    retroactive plan must quarantine, so the real attack is NOT auto-closed."""
    sig = "override:v2:targeted-signature"
    start = NOW - timedelta(minutes=20)

    # 1) Attacker farms 40 benign alerts under `sig`, auto-closed as FP, with
    #    no independent human confirmation.
    farmed = _fp_burst(sig, 40, author=MemoryAuthor.AUTONOMOUS, start=start)

    # 2) Detector assessment at the moment the real attack arrives.
    detector = PoisoningDetector(window_seconds=3600, min_fp_burst=10, max_human_confirmations=2)
    verdict = detector.assess(sig, farmed, now=NOW)

    # The poisoned signature is flagged -> autonomous closure is blocked.
    assert verdict.flagged is True
    assert verdict.should_block_autoclose is True

    # 3) Any retroactive bulk re-disposition under this signature is quarantined
    #    (nothing auto-applies; requires explicit human clearance).
    real_attack_alert_ids = [f"real-attack-{i}" for i in range(3)]
    plan = plan_redisposition(real_attack_alert_ids, "false_positive", flagged=verdict.flagged)
    assert plan.quarantined is True
