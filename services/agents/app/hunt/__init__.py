"""Hunt-as-code module (Wave 2 — w2-hac).

Loads YAML hunt hypotheses from the repo's ``hunts/`` corpus, runs them on a
schedule against the synthetic telemetry corpus (in dev) or the live event
warehouse (in prod), and persists hunt runs + findings as first-class
artifacts alongside the Investigation Ledger.

The public surface is intentionally thin:

* :class:`HuntCorpus`     — load + access the YAML corpus
* :class:`HuntEngine`     — match indicators against telemetry events
* :class:`HuntScheduler`  — APScheduler-driven continuous runner
* :mod:`store`            — persistence helpers (``hunt_runs`` / ``hunt_findings``)
"""

from __future__ import annotations

from .engine import HuntEngine, HuntFindingDraft, HuntRunResult
from .loader import HuntCorpus, HuntDefinition

__all__ = [
    "HuntCorpus",
    "HuntDefinition",
    "HuntEngine",
    "HuntFindingDraft",
    "HuntRunResult",
]
