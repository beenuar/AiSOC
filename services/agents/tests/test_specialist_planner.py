"""Wave 4b — scored specialist planner: bounded, ranked selection that does not
brute-force all four specialists on an ambiguous alert."""

from __future__ import annotations

from uuid import uuid4

from app.models.state import AgentStatus, InvestigationState
from app.orchestrator.planner import plan_specialists


def _state(summary: str = "", raw: dict | None = None) -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=summary,
        raw_alert=raw or {},
        status=AgentStatus.PENDING,
    )


def test_raw_fields_outrank_keywords_and_pick_phishing():
    plan = plan_specialists(_state("email reported", raw={"sender": "x@evil.test", "subject": "urgent", "urls": ["h"]}))
    assert plan.specialists[0] == "phishing"
    assert plan.scores["phishing"] >= 3.0
    assert plan.ambiguous is False


def test_ambiguous_alert_does_not_fan_out_to_all_four():
    plan = plan_specialists(_state("something happened with no clear signal"))
    assert plan.ambiguous is True
    assert plan.specialists == ["identity"]
    assert len(plan.specialists) == 1  # NOT the whole roster


def test_selection_is_bounded_by_max_agents():
    # An alert that trips many specialists is still capped.
    raw = {"sender": "a", "username": "u", "cloud_provider": "aws", "data_volume_mb": 999}
    plan = plan_specialists(_state("phishing login to aws with large data transfer exfil", raw=raw), max_agents=2)
    assert len(plan.specialists) == 2
    # The two highest-scoring win.
    assert set(plan.specialists) <= {"phishing", "identity", "cloud", "insider"}


def test_cloud_keyword_routes_to_cloud():
    plan = plan_specialists(_state("suspicious AWS IAM privilege escalation in the cloud console"))
    assert "cloud" in plan.specialists
