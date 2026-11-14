"""Detection Author Agent — threat-report → Sigma/SPL/KQL + GitOps PR.

Public surface:

- :func:`propose_detection` — run the full pipeline on a ``ThreatReport``
  and return a ``DetectionProposal`` without mutating the engine.
- :func:`activate_in_engine` — install an approved proposal's rule
  into the live ``DetectionEngine`` via hot-reload.

The dataclasses (`ThreatReport`, `DetectionProposal`, etc.) are
re-exported so callers don't need to import from the internal modules.
"""

from .models import (
    DetectionProposal,
    GitOpsArtifact,
    SelfTestResult,
    SyntheticEvent,
    ThreatReport,
    TranslationSet,
)
from .pipeline import activate_in_engine, propose_detection

__all__ = [
    "DetectionProposal",
    "GitOpsArtifact",
    "SelfTestResult",
    "SyntheticEvent",
    "ThreatReport",
    "TranslationSet",
    "activate_in_engine",
    "propose_detection",
]
