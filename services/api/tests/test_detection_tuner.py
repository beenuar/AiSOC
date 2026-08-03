"""Wave 4c — self-improving detections: feedback -> tuning suggestions."""

from __future__ import annotations

from app.services.detection_tuner import DispositionRecord, suggest_tuning


def _fp(rule, entity=None, human=False):
    return DispositionRecord(rule_id=rule, disposition="false_positive", entity=entity, human_verified=human)


def _tp(rule):
    return DispositionRecord(rule_id=rule, disposition="true_positive")


def _btp(rule):
    return DispositionRecord(rule_id=rule, disposition="benign_true_positive")


def test_low_fp_rule_gets_no_suggestion():
    records = [_tp("r1")] * 8 + [_fp("r1")] * 2  # 20% FP
    assert suggest_tuning(records, min_samples=10) == []


def test_entity_clustered_fps_suggest_exception():
    records = [_fp("r1", entity="scanner-01") for _ in range(9)] + [_fp("r1", entity="other")] + [_tp("r1")] * 2
    out = suggest_tuning(records, min_samples=10)
    assert len(out) == 1
    assert out[0].action == "add_exception"
    assert out[0].entity == "scanner-01"


def test_diffuse_fps_suggest_lower_severity():
    records = [_fp("r2", entity=f"h{i}") for i in range(12)] + [_tp("r2")] * 3
    out = suggest_tuning(records, min_samples=10)
    assert out and out[0].action == "lower_severity"


def test_overwhelming_human_confirmed_fps_suggest_suppress():
    records = [_fp("r3", entity=f"h{i % 8}", human=True) for i in range(40)]
    out = suggest_tuning(records, min_samples=10)
    assert out and out[0].action == "suppress"
    assert out[0].requires_approval is True


def test_benign_true_positive_not_counted_as_fp():
    # 10 BTP (valid detections) + 0 FP -> the rule is NOT tuned into silence.
    records = [_btp("r4") for _ in range(10)] + [_tp("r4")] * 2
    assert suggest_tuning(records, min_samples=10) == []
