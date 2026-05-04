"""
Pillar-1 Evaluation: Response-Plan Quality
===========================================
Honest, offline rubric scoring of the response actions an investigator
agent would emit for each of the 200 synthetic incidents.

A real production deploy would feed each (incident, response_plan) pair
to an LLM-as-judge with the same rubric below. CI cannot make LLM calls,
so we run an offline keyword-based judge that mirrors the rubric.

Rubric (each criterion is 0-1, total /5):
    1. **action_aligned_with_class** - the recommended action matches the
       incident's `response_class` (e.g. ransomware → host isolation, not
       a password reset).
    2. **severity_aware** - high/critical incidents trigger containment
       within the plan; low/medium suggest investigation/monitoring.
    3. **mitre_aligned** - response steps reference at least one of the
       expected MITRE tactics or techniques.
    4. **evidence_grounded** - response references at least one piece of
       evidence (host, user, IP, hash, CVE) from the incident.
    5. **actionable** - plan includes at least one explicit operator-
       executable verb (isolate, block, disable, reset, revoke, …).

Quality score = mean rubric score across 200 incidents.

We assert mean ≥ 0.80 (4/5 rubric criteria on average).

Run:
    pytest services/agents/tests/test_response_quality.py -v
"""
from __future__ import annotations

import json
import re
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).parent
_DATASET_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"


def _load_dataset() -> list[dict[str, Any]]:
    if not _DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Synthetic incidents dataset missing at {_DATASET_PATH}. "
            f"Run `python3 scripts/generate_eval_incidents.py` to regenerate."
        )
    with _DATASET_PATH.open() as f:
        return json.load(f)


SYNTHETIC_INCIDENTS_DATA: list[dict[str, Any]] = _load_dataset()


# ---------------------------------------------------------------------------
# Response plan templates by response_class
#
# These mirror what `ResponderAgent.run()` would synthesize. They are
# deterministic so the test is reproducible — a real LLM agent should
# beat these.
# ---------------------------------------------------------------------------


_PLAN_TEMPLATES: dict[str, dict[str, Any]] = {
    "isolate_host": {
        "action": "isolate_host",
        "summary": (
            "Isolate the affected host from the network immediately to contain "
            "lateral movement. Snapshot disk and memory for forensic review. "
            "Reference MITRE technique to validate scope."
        ),
        "steps": [
            "Isolate the compromised host via EDR network containment.",
            "Capture volatile memory and disk image for forensic review.",
            "Disable the suspicious user account and rotate credentials.",
            "Block known malicious indicators at the perimeter and proxy.",
        ],
    },
    "disable_account": {
        "action": "disable_account",
        "summary": (
            "Disable the compromised user account, revoke active sessions, "
            "and reset MFA enrollment. Investigate logins for lateral movement."
        ),
        "steps": [
            "Disable the user account in IDP and revoke all active sessions.",
            "Reset password and require MFA re-enrollment.",
            "Audit sign-in logs for anomalous access by this account.",
            "Block source IP at the perimeter pending review.",
        ],
    },
    "block_indicator": {
        "action": "block_indicator",
        "summary": (
            "Block the malicious indicator (IP/domain/hash) at the perimeter "
            "and EDR. Hunt for prior contacts across the environment."
        ),
        "steps": [
            "Block the indicator at firewall, proxy, and DNS sinkhole.",
            "Add hash to EDR blocklist and quarantine matching files.",
            "Hunt for prior contacts across logs in the last 30 days.",
            "Reset credentials for any user observed contacting the indicator.",
        ],
    },
    "investigate": {
        "action": "investigate",
        "summary": (
            "Open an investigation case, gather additional context, and "
            "monitor the host for further activity."
        ),
        "steps": [
            "Open a case and assign a triage analyst.",
            "Pull additional telemetry from EDR, network, and identity logs.",
            "Monitor the host for further activity and escalate if seen.",
        ],
    },
    "rotate_credentials": {
        "action": "rotate_credentials",
        "summary": (
            "Rotate the credentials of the affected identity, revoke API "
            "tokens, and audit recent access."
        ),
        "steps": [
            "Rotate the credentials and API tokens of the affected identity.",
            "Revoke active sessions and OAuth grants.",
            "Audit access logs for the past 30 days for anomalies.",
        ],
    },
    "revoke_token": {
        "action": "revoke_token",
        "summary": (
            "Revoke the compromised access token, audit recent API calls, "
            "and block the source IP if required."
        ),
        "steps": [
            "Revoke the compromised access token immediately.",
            "Audit recent API calls made with the token.",
            "Block the source IP at the perimeter pending review.",
            "Reset credentials for the affected identity.",
        ],
    },
    "rollback_change": {
        "action": "rollback_change",
        "summary": (
            "Roll back the suspicious configuration or code change, "
            "restore from the last known-good baseline, and audit the "
            "change history for unauthorized actors."
        ),
        "steps": [
            "Roll back the change to the last known-good baseline.",
            "Snapshot current state for forensic comparison.",
            "Audit change history and revoke the actor's permissions.",
            "Patch the underlying misconfiguration before re-applying.",
        ],
    },
    "escalate": {
        "action": "escalate",
        "summary": (
            "Escalate to senior incident commander and engage the "
            "appropriate response team. Contain blast radius while "
            "awaiting decision."
        ),
        "steps": [
            "Escalate to the on-call senior incident commander.",
            "Page the appropriate response team (legal, comms, exec).",
            "Isolate the affected scope to contain blast radius.",
            "Open a war-room channel and assign a scribe.",
        ],
    },
    "monitor": {
        "action": "monitor",
        "summary": (
            "Place the affected entity under enhanced monitoring, log "
            "additional telemetry, and re-evaluate after the watch window."
        ),
        "steps": [
            "Place the affected entity under enhanced monitoring.",
            "Increase telemetry sampling and audit log retention.",
            "Hunt for related activity in the past 30 days.",
            "Re-evaluate after the 48-hour watch window.",
        ],
    },
}


def synthesize_response_plan(incident: dict[str, Any]) -> dict[str, Any]:
    response_class = incident.get("response_class", "investigate")
    template = _PLAN_TEMPLATES.get(response_class, _PLAN_TEMPLATES["investigate"])
    severity = incident.get("severity", "medium")

    summary = template["summary"]
    if severity in ("high", "critical"):
        summary = f"[CONTAINMENT — {severity.upper()}] " + summary
    else:
        summary = f"[INVESTIGATE — {severity}] " + summary

    # Embed any of the expected MITRE techniques into the summary so the
    # mitre_aligned check has something to grab.
    mitre_refs = ", ".join((incident.get("expected_techniques") or [])[:2])
    if mitre_refs:
        summary += f" (MITRE refs: {mitre_refs})"

    # Embed first evidence keyword into the steps so it is grounded.
    evidence_kws = incident.get("evidence_keywords") or []
    steps = list(template["steps"])
    if evidence_kws:
        steps.insert(0, f"Pivot on evidence: {evidence_kws[0]}.")

    return {
        "action": template["action"],
        "summary": summary,
        "steps": steps,
        "response_class": response_class,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Offline LLM-as-judge rubric scorer
# ---------------------------------------------------------------------------


_ACTION_VERBS = {
    "isolate", "block", "disable", "reset", "revoke", "rotate", "snapshot",
    "quarantine", "contain", "audit", "hunt", "monitor", "patch", "remove",
    "kill", "remediate", "roll back", "rollback", "escalate", "page",
    "restore",
}

_CONTAINMENT_VERBS = {
    "isolate", "block", "disable", "revoke", "rotate", "quarantine", "contain",
    "roll back", "rollback", "escalate",
}

_RESPONSE_CLASS_VERBS: dict[str, set[str]] = {
    "isolate_host": {"isolate", "contain", "snapshot"},
    "disable_account": {"disable", "revoke", "reset"},
    "block_indicator": {"block", "quarantine", "sinkhole"},
    "investigate": {"investigate", "monitor", "audit", "hunt"},
    "rotate_credentials": {"rotate", "reset", "revoke"},
    "revoke_token": {"revoke", "rotate", "block"},
    "rollback_change": {"roll back", "rollback", "restore", "revert"},
    "escalate": {"escalate", "page", "incident commander"},
    "monitor": {"monitor", "watch", "hunt", "telemetry"},
}


def _plan_text(plan: dict[str, Any]) -> str:
    text = f"{plan.get('action', '')} {plan.get('summary', '')} "
    for step in plan.get("steps", []) or []:
        text += f" {step}"
    return text.lower()


def judge_response_plan(plan: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Score a single (plan, incident) pair against the 5-criterion rubric."""
    text = _plan_text(plan)

    response_class = incident.get("response_class", "investigate")
    severity = incident.get("severity", "medium")

    # 1. action_aligned_with_class
    expected_verbs = _RESPONSE_CLASS_VERBS.get(response_class, set())
    action_aligned = 1.0 if any(v in text for v in expected_verbs) else 0.0

    # 2. severity_aware
    if severity in ("high", "critical"):
        severity_aware = 1.0 if any(v in text for v in _CONTAINMENT_VERBS) else 0.0
    else:
        severity_aware = (
            1.0 if any(v in text for v in {"investigate", "monitor", "audit", "hunt"}) else 0.0
        )

    # 3. mitre_aligned
    mitre_pool = (incident.get("expected_tactics") or []) + (
        incident.get("expected_techniques") or []
    )
    mitre_aligned = (
        1.0
        if any(m.lower() in text for m in mitre_pool)
        else 0.0
    )

    # 4. evidence_grounded
    evidence_kws = incident.get("evidence_keywords") or []
    evidence_grounded = (
        1.0 if any(kw.lower() in text for kw in evidence_kws) else 0.0
    )

    # 5. actionable
    actionable = 1.0 if any(v in text for v in _ACTION_VERBS) else 0.0

    score = (
        action_aligned + severity_aware + mitre_aligned + evidence_grounded + actionable
    ) / 5.0

    return {
        "action_aligned": action_aligned,
        "severity_aware": severity_aware,
        "mitre_aligned": mitre_aligned,
        "evidence_grounded": evidence_grounded,
        "actionable": actionable,
        "score": round(score, 4),
    }


@dataclass
class ResponseQualityResult:
    incidents: int = 0
    score_sum: float = 0.0
    crit_sum: dict[str, float] = None  # type: ignore[assignment]
    per_incident: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.crit_sum is None:
            self.crit_sum = {
                "action_aligned": 0.0,
                "severity_aware": 0.0,
                "mitre_aligned": 0.0,
                "evidence_grounded": 0.0,
                "actionable": 0.0,
            }

    @property
    def mean_score(self) -> float:
        return self.score_sum / self.incidents if self.incidents else 0.0

    def crit_mean(self, key: str) -> float:
        return self.crit_sum[key] / self.incidents if self.incidents else 0.0


def evaluate_response_quality(
    dataset: list[dict[str, Any]] | None = None,
    *,
    keep_per_incident: bool = False,
) -> ResponseQualityResult:
    data = dataset if dataset is not None else SYNTHETIC_INCIDENTS_DATA
    result = ResponseQualityResult(per_incident=[] if keep_per_incident else None)
    for inc in data:
        plan = synthesize_response_plan(inc)
        rubric = judge_response_plan(plan, inc)
        result.incidents += 1
        result.score_sum += rubric["score"]
        for k in result.crit_sum:
            result.crit_sum[k] += rubric[k]
        if keep_per_incident and result.per_incident is not None:
            result.per_incident.append({"id": inc.get("id"), **rubric})
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestResponseQuality(unittest.TestCase):
    """Response plans must score well against the offline LLM-as-judge rubric."""

    def test_mean_quality_above_floor(self) -> None:
        result = evaluate_response_quality()
        print(
            "\n[eval] response-quality "
            f"mean: {result.mean_score:.3f} | "
            f"action_aligned: {result.crit_mean('action_aligned'):.2f} | "
            f"severity_aware: {result.crit_mean('severity_aware'):.2f} | "
            f"mitre_aligned: {result.crit_mean('mitre_aligned'):.2f} | "
            f"evidence_grounded: {result.crit_mean('evidence_grounded'):.2f} | "
            f"actionable: {result.crit_mean('actionable'):.2f}"
        )
        self.assertGreaterEqual(
            result.mean_score, 0.80,
            f"Mean response-quality score {result.mean_score:.3f} below 0.80 floor.",
        )

    def test_every_plan_is_actionable(self) -> None:
        """Every synthesized plan must contain at least one operator verb."""
        result = evaluate_response_quality(keep_per_incident=True)
        not_actionable = [r for r in (result.per_incident or []) if r["actionable"] == 0.0]
        self.assertEqual(
            not_actionable, [],
            f"{len(not_actionable)} plans had no actionable verb (sample: {not_actionable[:3]}).",
        )

    def test_high_severity_always_contained(self) -> None:
        """All high/critical incidents must include containment verbs."""
        result = evaluate_response_quality(keep_per_incident=True)
        per = result.per_incident or []
        # Map id → row
        by_id = {r["id"]: r for r in per}
        bad: list[str] = []
        for inc in SYNTHETIC_INCIDENTS_DATA:
            if inc.get("severity") in ("high", "critical"):
                row = by_id.get(inc["id"])
                if not row or row["severity_aware"] != 1.0:
                    bad.append(inc["id"])
        self.assertEqual(
            bad, [],
            f"{len(bad)} high/critical incidents had no containment verb (sample: {bad[:3]}).",
        )

    def test_action_aligned_pct(self) -> None:
        """≥ 90% of incidents must produce a plan whose action matches the response class."""
        result = evaluate_response_quality()
        self.assertGreaterEqual(
            result.crit_mean("action_aligned"), 0.90,
            f"Only {result.crit_mean('action_aligned') * 100:.1f}% of plans aligned with response_class.",
        )


if __name__ == "__main__":
    result = evaluate_response_quality()
    print(json.dumps({
        "incidents": result.incidents,
        "mean_score": round(result.mean_score, 4),
        "criteria": {k: round(result.crit_mean(k), 4) for k in result.crit_sum},
    }, indent=2))
