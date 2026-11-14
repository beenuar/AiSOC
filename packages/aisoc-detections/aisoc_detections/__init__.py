"""AiSOC Python detection framework (Wave 3, W3.1).

Detection engineers write detections as Python — a module with a ``rule(event)``
function plus metadata and inline test cases — complementing the YAML/Sigma
corpus. Detections are unit-tested against their own positive/negative fixtures
and gated in CI.

A detection module looks like::

    ID = "py-okta-mfa-bombing"
    TITLE = "Okta MFA fatigue (push bombing)"
    SEVERITY = "high"          # info | low | medium | high | critical
    MITRE = ["T1621"]
    DESCRIPTION = "Many MFA push challenges to one user in a short window."

    def rule(event: dict) -> bool:
        return event.get("eventType") == "user.mfa.attempt" and event.get("attempts", 0) >= 5

    # Optional overrides:
    def title(event: dict) -> str: ...   # dynamic title
    def dedup(event: dict) -> str: ...   # dedup key

    TESTS = [
        {"name": "fires on 5 attempts", "event": {"eventType": "user.mfa.attempt", "attempts": 6}, "expect": True},
        {"name": "quiet on 1 attempt",  "event": {"eventType": "user.mfa.attempt", "attempts": 1}, "expect": False},
    ]
"""

from __future__ import annotations

from .base import (
    Detection,
    DetectionError,
    evaluate,
    load_detection,
    load_detections,
)
from .runner import FixtureFailure, TestReport, run_fixtures, run_suite

__all__ = [
    "Detection",
    "DetectionError",
    "FixtureFailure",
    "TestReport",
    "evaluate",
    "load_detection",
    "load_detections",
    "run_fixtures",
    "run_suite",
]
