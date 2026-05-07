"""Calibrated-confidence utilities for AiSOC agents.

Public surface:

- ``score_triage`` / ``score_investigation`` — heuristic scorers that emit
  a calibrated ``(confidence, basis)`` tuple from agent state.
- ``brier_score`` — strict-proper scoring rule for binary outcomes.
- ``reliability_curve`` — bucketed (predicted, empirical, count) tuples used
  by the calibration eval suite to plot a reliability diagram.

The calibration evaluation lives in
``services/agents/tests/test_confidence_calibration.py`` and gates merges in CI.
"""

from .calibration import brier_score, reliability_curve
from .scoring import score_investigation, score_triage

__all__ = [
    "brier_score",
    "reliability_curve",
    "score_investigation",
    "score_triage",
]
