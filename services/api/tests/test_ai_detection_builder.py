"""Wave 3 (W3.2) - AI Detection Builder: auto-derived fixtures + eval gate.

The endpoint needs a DB (proposal insert) and is covered in api integration.
These pin the pure, deterministic core: fixtures are DERIVED from the rule's own
selection (not invented), and those fixtures genuinely pass the non-circular
eval gate — proving the generated rule fires on a positive and stays quiet on a
negative.
"""

from __future__ import annotations

from app.services.detection_eval import evaluate_candidate_rule
from app.services.fixture_synth import derive_fixtures_from_sigma

_SIGMA_CONTAINS = """
title: Credential dumping via mimikatz
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection
level: high
"""

_SIGMA_MULTI = """
title: Encoded PowerShell
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: medium
"""


def test_derive_positive_matches_negative_breaks():
    derived = derive_fixtures_from_sigma(_SIGMA_CONTAINS)
    assert derived is not None
    pos, neg = derived
    assert "mimikatz" in pos[0]["CommandLine"]
    assert "mimikatz" not in neg[0]["CommandLine"]


def test_derived_fixtures_pass_the_non_circular_gate():
    derived = derive_fixtures_from_sigma(_SIGMA_CONTAINS)
    assert derived is not None
    pos, neg = derived
    result = evaluate_candidate_rule(rule_language="sigma", rule_body=_SIGMA_CONTAINS, positive_fixtures=pos, negative_fixtures=neg)
    assert result.passed, result.to_dict()


def test_multi_selector_derivation_and_gate():
    derived = derive_fixtures_from_sigma(_SIGMA_MULTI)
    assert derived is not None
    pos, neg = derived
    assert pos[0]["Image"].endswith("powershell.exe")
    assert "-EncodedCommand" in pos[0]["CommandLine"]
    result = evaluate_candidate_rule(rule_language="sigma", rule_body=_SIGMA_MULTI, positive_fixtures=pos, negative_fixtures=neg)
    assert result.passed, result.to_dict()


def test_unusable_sigma_returns_none():
    assert derive_fixtures_from_sigma("just a plain string") is None
    assert derive_fixtures_from_sigma("title: x\nlevel: high\n") is None  # no detection block
