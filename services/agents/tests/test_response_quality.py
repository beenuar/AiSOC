"""
Pillar-1 Evaluation: Response-Plan Quality — Substrate Self-Consistency Gate
=============================================================================
Offline rubric scoring of the deterministic substrate response-plan
generator against each of the 200 synthetic incidents.

A real production deploy would feed each (incident, response_plan) pair
to an LLM-as-judge with the same rubric below, on real (or held-out
adversarial) incidents. CI cannot make LLM calls, so we run an offline
keyword-based judge that mirrors the rubric *against a templated plan
built from the same synthetic incident* — by construction the plan
references the incident's response_class, severity, MITRE labels, and
evidence keywords, so this is a SUBSTRATE SELF-CONSISTENCY GATE that
catches regressions in the templater or the dataset, NOT a measurement
of whether a real LLM agent emits a high-quality plan on blind data.

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

We assert mean ≥ 0.80 (4/5 rubric criteria on average) as a substrate
regression floor, AND per-template macro mean ≥ 0.75 across the ~55
distinct templates. The per-template gate is the regression-signal-
preserving metric: with ~3-4 duplicates per template, a single broken
template moves per-case mean by ~0.5% but per-template mean by ~1.5%
(addressing the dilution concern raised in
`docs/research/dataset-design-notes.md`).

See `apps/docs/docs/benchmark.md` for what each suite actually measures.

Run:
    pytest services/agents/tests/test_response_quality.py -v
"""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).parent
_DATASET_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"


def _load_dataset() -> list[dict[str, Any]]:
    if not _DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Synthetic incidents dataset missing at {_DATASET_PATH}. Run `python3 scripts/generate_eval_incidents.py` to regenerate."
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
            "Block the malicious indicator (IP/domain/hash) at the perimeter and EDR. Hunt for prior contacts across the environment."
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
        "summary": ("Open an investigation case, gather additional context, and monitor the host for further activity."),
        "steps": [
            "Open a case and assign a triage analyst.",
            "Pull additional telemetry from EDR, network, and identity logs.",
            "Monitor the host for further activity and escalate if seen.",
        ],
    },
    "rotate_credentials": {
        "action": "rotate_credentials",
        "summary": ("Rotate the credentials of the affected identity, revoke API tokens, and audit recent access."),
        "steps": [
            "Rotate the credentials and API tokens of the affected identity.",
            "Revoke active sessions and OAuth grants.",
            "Audit access logs for the past 30 days for anomalies.",
        ],
    },
    "revoke_token": {
        "action": "revoke_token",
        "summary": ("Revoke the compromised access token, audit recent API calls, and block the source IP if required."),
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
            "Escalate to senior incident commander and engage the appropriate response team. Contain blast radius while awaiting decision."
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
            "Place the affected entity under enhanced monitoring, log additional telemetry, and re-evaluate after the watch window."
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
    "isolate",
    "block",
    "disable",
    "reset",
    "revoke",
    "rotate",
    "snapshot",
    "quarantine",
    "contain",
    "audit",
    "hunt",
    "monitor",
    "patch",
    "remove",
    "kill",
    "remediate",
    "roll back",
    "rollback",
    "escalate",
    "page",
    "restore",
}

_CONTAINMENT_VERBS = {
    "isolate",
    "block",
    "disable",
    "revoke",
    "rotate",
    "quarantine",
    "contain",
    "roll back",
    "rollback",
    "escalate",
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
        severity_aware = 1.0 if any(v in text for v in {"investigate", "monitor", "audit", "hunt"}) else 0.0

    # 3. mitre_aligned
    mitre_pool = (incident.get("expected_tactics") or []) + (incident.get("expected_techniques") or [])
    mitre_aligned = 1.0 if any(m.lower() in text for m in mitre_pool) else 0.0

    # 4. evidence_grounded
    evidence_kws = incident.get("evidence_keywords") or []
    evidence_grounded = 1.0 if any(kw.lower() in text for kw in evidence_kws) else 0.0

    # 5. actionable
    actionable = 1.0 if any(v in text for v in _ACTION_VERBS) else 0.0

    score = (action_aligned + severity_aware + mitre_aligned + evidence_grounded + actionable) / 5.0

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

    def per_template_summary(self) -> dict[str, Any]:
        """Aggregate response-quality scores by `template_id`.

        Equal-weights each unique scenario so a broken template can't be
        averaged into oblivion by 3-4 duplicate cases — same multiplier
        math as in `test_mitre_accuracy` / `test_investigation_completeness`.
        """
        if not self.per_incident:
            return {
                "templates": [],
                "template_count": 0,
                "template_macro_score": 0.0,
                "failing_templates": [],
            }
        buckets: dict[str, dict[str, Any]] = {}
        for row in self.per_incident:
            tpl = row.get("template_id") or "unknown"
            b = buckets.setdefault(tpl, {"sum": 0.0, "count": 0})
            b["sum"] += row.get("score", 0.0)
            b["count"] += 1
        templates: list[dict[str, Any]] = []
        for tpl, b in buckets.items():
            mean = b["sum"] / b["count"] if b["count"] else 0.0
            templates.append(
                {
                    "template_id": tpl,
                    "cases": b["count"],
                    "score": round(mean, 4),
                }
            )
        templates.sort(key=lambda t: (t["score"], -t["cases"]))
        macro = sum(t["score"] for t in templates) / len(templates) if templates else 0.0
        failing = [t for t in templates if t["score"] < 0.70]
        return {
            "templates": templates,
            "template_count": len(templates),
            "template_macro_score": round(macro, 4),
            "failing_templates": failing,
        }


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
            result.per_incident.append(
                {
                    "id": inc.get("id"),
                    "template_id": inc.get("template_id"),
                    "template_index": inc.get("template_index"),
                    **rubric,
                }
            )
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
            result.mean_score,
            0.80,
            f"Mean response-quality score {result.mean_score:.3f} below 0.80 floor.",
        )

    def test_every_plan_is_actionable(self) -> None:
        """Every synthesized plan must contain at least one operator verb."""
        result = evaluate_response_quality(keep_per_incident=True)
        not_actionable = [r for r in (result.per_incident or []) if r["actionable"] == 0.0]
        self.assertEqual(
            not_actionable,
            [],
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
            bad,
            [],
            f"{len(bad)} high/critical incidents had no containment verb (sample: {bad[:3]}).",
        )

    def test_action_aligned_pct(self) -> None:
        """≥ 90% of incidents must produce a plan whose action matches the response class."""
        result = evaluate_response_quality()
        self.assertGreaterEqual(
            result.crit_mean("action_aligned"),
            0.90,
            f"Only {result.crit_mean('action_aligned') * 100:.1f}% of plans aligned with response_class.",
        )

    def test_per_template_quality(self) -> None:
        """Per-template macro response-quality must be ≥ 0.75.

        Equal-weighting templates ensures a single broken scenario can't be
        averaged into oblivion by 3-4 duplicate cases. The 0.75 floor is
        intentionally below the per-case 0.80 because each template
        contributes ~1/55 of the macro average — a single template at
        0 drags macro by ~1.5%, vs. ~0.5% per case.
        """
        result = evaluate_response_quality(keep_per_incident=True)
        summary = result.per_template_summary()
        print(
            f"\n[eval] per-template response-quality: "
            f"{summary['template_macro_score']:.3f} "
            f"({summary['template_count']} templates, "
            f"{len(summary['failing_templates'])} below 0.70)"
        )
        self.assertGreaterEqual(
            summary["template_count"],
            50,
            f"Only {summary['template_count']} distinct templates in dataset; expected ≥50.",
        )
        self.assertGreaterEqual(
            summary["template_macro_score"],
            0.75,
            f"Per-template response-quality below 0.75.\nFailing templates: {summary['failing_templates']}",
        )


if __name__ == "__main__":
    result = evaluate_response_quality(keep_per_incident=True)
    summary = result.per_template_summary()
    print(
        json.dumps(
            {
                "incidents": result.incidents,
                "mean_score": round(result.mean_score, 4),
                "criteria": {k: round(result.crit_mean(k), 4) for k in result.crit_sum},
                "template_count": summary["template_count"],
                "template_macro_score": summary["template_macro_score"],
                "failing_templates": [t["template_id"] for t in summary["failing_templates"]],
            },
            indent=2,
        )
    )
