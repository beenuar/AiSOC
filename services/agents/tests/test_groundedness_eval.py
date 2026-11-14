"""Wave 6 — groundedness / hallucination eval axis."""

from __future__ import annotations

from app.confidence.groundedness import score_groundedness


def test_fully_grounded_output_scores_one():
    evidence = "Beacon from 45.9.148.99 to c2.evil.example matching T1071. CVE-2024-1234 present."
    output = "Malicious beacon: 45.9.148.99 contacting c2.evil.example (T1071); exploited CVE-2024-1234."
    r = score_groundedness(output, evidence)
    assert r.score == 1.0
    assert r.has_hallucination is False


def test_hallucinated_indicator_is_flagged():
    evidence = "Beacon from 45.9.148.99 observed."
    # 203.0.113.7 is NOT in the evidence -> hallucination.
    output = "Attacker used 45.9.148.99 and pivoted to 203.0.113.7."
    r = score_groundedness(output, evidence)
    assert r.score == 0.5
    assert "203.0.113.7" in r.hallucinated
    assert "45.9.148.99" in r.grounded
    assert r.has_hallucination is True


def test_output_with_no_indicators_is_grounded():
    r = score_groundedness("The activity appears benign and expected.", "some evidence")
    assert r.score == 1.0
    assert r.has_hallucination is False


def test_fabricated_cve_and_hash_flagged():
    evidence = "Suspicious process launch on host web-01."
    output = "Linked to CVE-2021-44228 and hash " + "a" * 64
    r = score_groundedness(output, evidence)
    assert r.score == 0.0
    assert any("cve-2021-44228" == h for h in r.hallucinated)
