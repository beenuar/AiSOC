"""Replay evaluation: measure triage against a customer's own closed findings.

Gap-closure Phase 1.2. See :mod:`app.replay.runner` for what runs, and
:mod:`app.replay.shadow` for why it writes nothing and reads a frozen world.
"""

from __future__ import annotations

from app.replay.findings import UNLABELED, HistoricalFinding
from app.replay.normalize import (
    ENVELOPE_LIMITS,
    ConnectorNormalizer,
    FindingNormalizer,
    NormalizerUnavailable,
    to_fused_envelope,
)
from app.replay.runner import (
    DEFAULT_TRAIN_FRACTION,
    ReplayDecision,
    ReplayRun,
    ReplayRunner,
    TimeSplit,
    split_by_time,
)
from app.replay.shadow import (
    ContextSnapshot,
    FrozenTriageContextReader,
    ShadowTriageWriter,
    capture_context,
)

__all__ = [
    "DEFAULT_TRAIN_FRACTION",
    "ENVELOPE_LIMITS",
    "UNLABELED",
    "ConnectorNormalizer",
    "ContextSnapshot",
    "FindingNormalizer",
    "FrozenTriageContextReader",
    "HistoricalFinding",
    "NormalizerUnavailable",
    "ReplayDecision",
    "ReplayRun",
    "ReplayRunner",
    "ShadowTriageWriter",
    "TimeSplit",
    "capture_context",
    "split_by_time",
    "to_fused_envelope",
]
