"""Run the SOC agent benchmark against any agent, including one that is not ours.

A benchmark a vendor cannot run against their own product is a self-report.
This package is the boundary that makes it a standard instead: implement one
method, get graded on the same corpus by the same code.
"""

from .adapter import AgentVerdict, BenchmarkIncident, HTTPAgent, SOCAgent
from .metrics import BenchmarkResult, IncidentScore, aggregate, score_incident
from .runner import format_report, load_corpus, run_benchmark

__all__ = [
    "AgentVerdict",
    "BenchmarkIncident",
    "BenchmarkResult",
    "HTTPAgent",
    "IncidentScore",
    "SOCAgent",
    "aggregate",
    "format_report",
    "load_corpus",
    "run_benchmark",
    "score_incident",
]
__version__ = "0.1.0"
