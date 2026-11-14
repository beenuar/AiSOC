"""Closed-loop Exposure->Detection->Response->Verification module.

Implements Theme 3a (t3a-closed-loop). The :class:`ExposureAgent` runs a
four-phase sweep per tenant on a schedule:

1. **Exposure** – query Cyble CTI tools (dark-web, brand, ASM, vuln-intel)
   against a per-tenant fingerprint and normalise findings into
   :class:`ExposureFinding` records.
2. **Detection** – cross-reference findings against the Threat Graph;
   anything new is materialised as an ``EXPOSURE`` node with edges to the
   affected asset/identity and opened as a proactive :class:`Case`.
3. **Response** – for findings with a deterministic containment action
   (revoke leaked credential, block typosquat sender, raise ticket for an
   exposed asset), route the case to the Responder via a narrow action
   spec; otherwise leave at ``CaseStatus.NEW`` for human triage.
4. **Verification** – after ``exposure_verification_window_seconds``, the
   next sweep re-queries the same CTI signals; if the signal is gone the
   case is closed as ``CLOSED_BENIGN``; if it persists the case is
   escalated.

Distinct from :class:`HunterAgent` (investigative hypothesis exploration)
and the :class:`DetectionValidationAgent` (BAS) so its per-tenant
scheduled sweep and case-factory traces are independently observable.
"""
from __future__ import annotations

from app.agents.exposure.agent import ExposureAgent
from app.agents.exposure.models import (
    ExposureFinding,
    ExposureKind,
    ExposureSweepResult,
)

__all__ = [
    "ExposureAgent",
    "ExposureFinding",
    "ExposureKind",
    "ExposureSweepResult",
]
