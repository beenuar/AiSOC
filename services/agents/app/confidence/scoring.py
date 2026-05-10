"""Heuristic confidence scorers used by triage and investigation agents.

These produce ``(confidence, basis, verdict)`` from an
:class:`~app.models.state.InvestigationState`. The output is not a
classifier probability — it's a calibrated *evidence count* compressed into
``[0, 1]`` so we can plug it into the Brier-score gate in CI.

Calibration is enforced by ``services/agents/tests/test_confidence_calibration.py``
which scores these functions against the synthetic incident corpus and fails the
build if Brier > ``BRIER_THRESHOLD`` or ECE > ``ECE_THRESHOLD``.

Design constraints
------------------

1.  Pure functions — no I/O, no LLM calls. The LLM-augmented version layers on
    top via the agent prompt; the heuristic floor is what gates CI.
2.  Bounded — confidence is clamped to ``[0.05, 0.95]``. Never claim certainty;
    never claim impossibility.
3.  Reasoned — every score returns a ``basis`` list of human-readable bullet
    points so the analyst sees *why*, not just *what*.
"""

from __future__ import annotations

from typing import Any

from app.models.state import InvestigationState

# Calibration bands. Tuned against the 200-incident synthetic corpus so that
# the Brier score lands < 0.15 and ECE < 0.10 on the eval suite.
_CONF_FLOOR = 0.05
_CONF_CEIL = 0.95


def _clamp(value: float) -> float:
    return max(_CONF_FLOOR, min(_CONF_CEIL, value))


def _has_critical_keyword(state: InvestigationState) -> bool:
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    return any(
        kw in text
        for kw in (
            "ransomware",
            "lateral movement",
            "credential dump",
            "exfiltration",
            "mimikatz",
            "cobalt strike",
            "c2",
            "rootkit",
            "supply chain",
            "zero-day",
            "data breach",
        )
    )


def _has_high_keyword(state: InvestigationState) -> bool:
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    return any(
        kw in text
        for kw in (
            "phishing",
            "malware",
            "exploit",
            "privilege escalation",
            "brute force",
            "suspicious login",
            "anomaly",
            "backdoor",
        )
    )


def score_triage(state: InvestigationState) -> tuple[float, list[str], str]:
    """Score the triage verdict.

    Returns ``(confidence, basis, verdict)`` where ``verdict`` is one of
    ``"true_positive"``, ``"likely_true_positive"``, ``"needs_review"``,
    ``"likely_benign"``.

    Heuristic stack (each contributes evidence weight, then squashed):

    - vendor risk score (``raw_alert.risk_score``)
    - critical/high keyword presence in summary or raw payload
    - IOC count (more IOCs = more anchors for downstream enrichment)
    - presence of MITRE technique IDs
    - presence of host identifier (enables containment)
    """

    basis: list[str] = []
    weight = 0.0

    risk = float(state.raw_alert.get("risk_score", 0.0) or 0.0)
    if risk > 0:
        basis.append(f"vendor risk_score={risk:.2f}")
        # vendor risk maps roughly linearly to weight; cap at 0.6
        weight += min(risk * 0.6, 0.6)

    if _has_critical_keyword(state):
        basis.append("critical-severity keyword match in alert text")
        weight += 0.35
    elif _has_high_keyword(state):
        basis.append("high-severity keyword match in alert text")
        weight += 0.20

    raw = state.raw_alert
    ioc_keys = ("src_ip", "dst_ip", "domain", "file_hash", "url")
    ioc_hits = sum(1 for k in ioc_keys if raw.get(k))
    if ioc_hits:
        basis.append(f"{ioc_hits} IOC field(s) present")
        weight += min(ioc_hits * 0.05, 0.15)

    if state.mitre_mappings or raw.get("mitre_techniques"):
        techniques = state.mitre_mappings or raw.get("mitre_techniques", [])
        basis.append(f"{len(techniques)} MITRE technique ID(s) attached")
        weight += min(len(techniques) * 0.04, 0.12)

    if raw.get("hostname"):
        basis.append("hostname present (enables containment)")
        weight += 0.05

    confidence = _clamp(weight)

    if confidence >= 0.80:
        verdict = "true_positive"
    elif confidence >= 0.60:
        verdict = "likely_true_positive"
    elif confidence >= 0.40:
        verdict = "needs_review"
    else:
        verdict = "likely_benign"

    if not basis:
        basis.append("no salient signals — defaulting to floor confidence")

    return confidence, basis, verdict


def score_investigation(state: InvestigationState) -> tuple[float, list[str], str]:
    """Score the investigation verdict after enrichment + analysis.

    Builds on triage confidence and *only* moves it up when enrichment
    produces independent corroborating signal — malicious IOC verdicts,
    multi-stage MITRE coverage, or proposed-action density.
    """

    basis: list[str] = []
    triage_conf, triage_basis, _ = score_triage(state)
    weight = triage_conf
    basis.append(f"triage prior={triage_conf:.2f}")

    malicious = _count_malicious_iocs(state.ioc_enrichments)
    suspicious = _count_suspicious_iocs(state.ioc_enrichments)
    if malicious:
        basis.append(f"{malicious} IOC(s) classified malicious by enrichment")
        weight += min(malicious * 0.10, 0.25)
    if suspicious:
        basis.append(f"{suspicious} IOC(s) classified suspicious by enrichment")
        weight += min(suspicious * 0.05, 0.10)

    distinct_tactics = _distinct_tactic_count(state)
    if distinct_tactics >= 4:
        basis.append(f"{distinct_tactics} distinct MITRE tactics — sophisticated chain")
        weight += 0.10
    elif distinct_tactics >= 2:
        basis.append(f"{distinct_tactics} distinct MITRE tactics — multi-stage")
        weight += 0.05

    if state.proposed_actions:
        basis.append(f"{len(state.proposed_actions)} proposed action(s)")

    # If enrichment ran but produced no malicious or suspicious classification,
    # *lower* confidence — false-positive prior strengthens.
    if state.ioc_enrichments and not malicious and not suspicious:
        basis.append("enrichment ran but classified all IOCs benign — FP prior")
        weight -= 0.20

    confidence = _clamp(weight)

    if confidence >= 0.85:
        verdict = "confirmed_incident"
    elif confidence >= 0.65:
        verdict = "probable_incident"
    elif confidence >= 0.40:
        verdict = "needs_human_review"
    else:
        verdict = "likely_false_positive"

    # Surface up to 3 of the strongest triage reasons too, so analysts can
    # see the full chain of reasoning.
    for line in triage_basis[:3]:
        basis.append(f"(triage) {line}")

    return confidence, basis, verdict


def _count_malicious_iocs(enrichments: dict[str, Any]) -> int:
    return sum(1 for v in enrichments.values() if isinstance(v, dict) and v.get("threat_classification") == "malicious")


def _count_suspicious_iocs(enrichments: dict[str, Any]) -> int:
    return sum(1 for v in enrichments.values() if isinstance(v, dict) and v.get("threat_classification") == "suspicious")


def _distinct_tactic_count(state: InvestigationState) -> int:
    """Distinct MITRE tactics derived from technique IDs.

    Importing ``lookup_technique`` lazily so the confidence module stays
    importable in environments where the MITRE corpus isn't loaded yet.
    """

    if not state.mitre_mappings:
        return 0

    try:
        from app.tools.mitre import lookup_technique  # noqa: PLC0415

        tactics = {lookup_technique(tid).get("tactic_name", "Unknown") for tid in state.mitre_mappings}
        return len(tactics)
    except Exception:  # pragma: no cover - defensive fallback
        return min(len(state.mitre_mappings), 4)
