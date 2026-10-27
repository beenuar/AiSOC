"""Calibrated-confidence utilities for AiSOC agents.

Public surface:

- ``score_triage`` / ``score_investigation`` — heuristic scorers that emit
  a calibrated ``(confidence, basis)`` tuple from agent state.
- ``brier_score`` — strict-proper scoring rule for binary outcomes.
- ``reliability_curve`` — bucketed (predicted, empirical, count) tuples used
  by the calibration eval suite to plot a reliability diagram.
- ``score_claim_support`` — whether the claims that license a closure trace
  to the evidence. Independent of indicator grounding, which is blind to it.
- ``SignalKind`` — the seven distinct things "the AI was right" can mean,
  named so a report cannot publish one of them under another's name.

The calibration evaluation lives in
``services/agents/tests/test_confidence_calibration.py`` and gates merges in CI.
"""

from .calibration import brier_score, reliability_curve
from .claim_support import ClaimKind, ClaimSupportResult, score_claim_support
from .scoring import score_investigation, score_triage
from .signals import UNMEASURED, SignalKind

__all__ = [
    "UNMEASURED",
    "ClaimKind",
    "ClaimSupportResult",
    "SignalKind",
    "brier_score",
    "reliability_curve",
    "score_claim_support",
    "score_investigation",
    "score_triage",
]
