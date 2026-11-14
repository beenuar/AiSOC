"""Run the SOC agent benchmark against any agent, including one that is not ours.

A benchmark a vendor cannot run against their own product is a self-report.
This package is the boundary that makes it a standard instead: implement one
method, get graded on the same corpus by the same code.
"""

from .adapter import AgentVerdict, BenchmarkIncident, HTTPAgent, SOCAgent
from .metrics import (
    BenchmarkResult,
    IncidentScore,
    aggregate,
    extract_checkable_indicators,
    score_incident,
)
from .replay import (
    LATENCY_FIELDS,
    LATENCY_LINE_PREFIX,
    MALICIOUS,
    MIN_MALICIOUS_FOR_HEADLINE,
    CalibrationBin,
    ClassScore,
    ReplayScore,
    SegmentScore,
    format_replay_report,
    score_replay,
    strip_latency,
)
from .runner import format_report, load_corpus, run_benchmark

__all__ = [
    "LATENCY_FIELDS",
    "LATENCY_LINE_PREFIX",
    "MALICIOUS",
    "MIN_MALICIOUS_FOR_HEADLINE",
    "AgentVerdict",
    "BenchmarkIncident",
    "BenchmarkResult",
    "CalibrationBin",
    "ClassScore",
    "HTTPAgent",
    "IncidentScore",
    "ReplayScore",
    "SOCAgent",
    "SegmentScore",
    "aggregate",
    "extract_checkable_indicators",
    "format_report",
    "load_corpus",
    "run_benchmark",
    "score_incident",
    "format_replay_report",
    "score_replay",
    "strip_latency",
]
__version__ = "0.1.0"
