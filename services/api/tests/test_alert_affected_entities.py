"""AlertResponse fills affected_* from what the fusion sink actually stores.

services/fusion/app/services/alert_sink.py writes the host and user into
`entities` and the addresses into `iocs`; no pipeline path writes the
affected_hosts / affected_users / affected_ips columns. On a v17.1 stack, 522
of 524 alerts had entities and 0 had affected_hosts, so the console showed no
affected entity on any pipeline alert.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.alerts import AlertDetailResponse, AlertResponse

NOW = datetime(2026, 10, 10, 3, 20, tzinfo=UTC)


def _row(**overrides):
    base = dict.fromkeys(AlertResponse.model_fields)
    base.update(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        title="CS Credential Dumping via ProcDump",
        description=None,
        severity="high",
        status="new",
        priority=50,
        category=None,
        mitre_tactics=[],
        mitre_techniques=["T1003.001"],
        connector_type="crowdstrike",
        ai_score=None,
        ai_summary=None,
        ai_recommendations=[],
        tags=[],
        affected_ips=[],
        affected_hosts=[],
        affected_users=[],
        case_id=None,
        event_time=NOW,
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
        updated_at=NOW,
        # As alert_sink._entities / _iocs write them.
        entities=[{"type": "host", "value": "WIN-FIN-09"}, {"type": "user", "value": "jdoe@corp"}],
        iocs=[{"type": "ip", "value": "203.0.113.10"}, {"type": "hash", "value": "abc"}],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_pipeline_alert_reports_its_host_user_and_ip() -> None:
    out = AlertResponse.model_validate(_row())
    assert out.affected_hosts == ["WIN-FIN-09"]
    assert out.affected_users == ["jdoe@corp"]
    assert out.affected_ips == ["203.0.113.10"]


def test_columns_that_are_set_win_over_entities() -> None:
    out = AlertResponse.model_validate(_row(affected_hosts=["from-api-create"]))
    assert out.affected_hosts == ["from-api-create"]
    assert out.affected_users == ["jdoe@corp"]


def test_malformed_or_missing_entities_leave_the_lists_empty() -> None:
    out = AlertResponse.model_validate(_row(entities=None, iocs={"oops": 1}))
    assert out.affected_hosts == [] and out.affected_users == [] and out.affected_ips == []


def test_detail_response_inherits_the_fill() -> None:
    assert issubclass(AlertDetailResponse, AlertResponse)
