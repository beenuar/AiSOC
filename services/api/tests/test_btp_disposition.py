"""#526 — benign_true_positive is a first-class analyst disposition, kept
distinct from false_positive throughout the feedback / rule-tuning surface."""

from __future__ import annotations

from app.api.v1.endpoints.feedback import _VALID_VERDICTS, OverrideSummaryResponse
from app.services.memory_poisoning import PoisoningDetector


def test_feedback_api_accepts_benign_true_positive():
    assert "benign_true_positive" in _VALID_VERDICTS


def test_feedback_api_still_accepts_legacy_benign():
    # Existing ``benign`` records/verdicts stay valid — no migration required.
    assert "benign" in _VALID_VERDICTS


def test_override_summary_tracks_btp_separately_from_fp():
    fields = OverrideSummaryResponse.model_fields
    assert "benign_true_positive_corrections" in fields
    assert "false_positive_corrections" in fields


def test_btp_is_not_treated_as_false_positive_for_rule_suppression():
    # The poisoning / re-disposition window keys on FP-like dispositions. A
    # benign true positive is a VALID detection: if it landed in this set an
    # attacker could farm authorized-looking activity to suppress a good rule,
    # and per-rule FP-rate metrics would be corrupted.
    detector = PoisoningDetector()
    assert "false_positive" in detector._fp_dispositions
    assert "benign_true_positive" not in detector._fp_dispositions
