"""Sigma-based detection engine.

This package exposes a small, dependency-light implementation of the
parts of the Sigma specification we actually use inside AiSOC:

- A YAML rule loader (`SigmaRule.from_yaml`, `RulePack.load_directory`)
- An in-memory matcher (`SigmaRule.matches(event)`) that evaluates the
  Sigma `detection:` block against a normalized event dict
- Multi-backend translators that compile a rule into Splunk SPL,
  Microsoft Sentinel KQL, Elastic Lucene, and Google Chronicle UDM
  Search / YARA-L 2.0 (`translate_splunk`, `translate_kql`,
  `translate_lucene`, `translate_chronicle`, `translate_chronicle_yaral`)
- A `DetectionEngine` that holds a `RulePack` and yields `Hit` objects

The goal is *not* full Sigma parity. The goal is: every rule we ship in
``app/detections/rules/`` is parsed by this engine, runs against OCSF /
normalized events on the hot path, and is also compilable to SPL/KQL so
the same logic ships to Splunk Enterprise Security and Sentinel
Analytics Rules.
"""

from .sigma import (
    SigmaRule,
    SigmaParseError,
    Hit,
    Severity,
)
from .pack import RulePack
from .engine import DetectionEngine
from .translator import (
    translate_splunk,
    translate_kql,
    translate_lucene,
    translate_chronicle,
    translate_chronicle_yaral,
    translate,
    BackendError,
)

__all__ = [
    "SigmaRule",
    "SigmaParseError",
    "Hit",
    "Severity",
    "RulePack",
    "DetectionEngine",
    "translate_splunk",
    "translate_kql",
    "translate_lucene",
    "translate_chronicle",
    "translate_chronicle_yaral",
    "translate",
    "BackendError",
]
