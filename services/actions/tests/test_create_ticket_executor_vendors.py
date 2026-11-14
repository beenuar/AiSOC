"""
Phase 3.5 vendor-dispatch tests for CreateTicketExecutor.

We stub the per-vendor client factories so we can verify the
executor's priority logic (explicit ticket_system → Jira →
ServiceNow → PagerDuty → simulation) without touching real APIs.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors import notification
from app.executors.notification import CreateTicketExecutor
from app.models.action import ActionRequest, ActionStatus, ActionType


def _request(**params: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.CREATE_TICKET,
        target="incident",
        parameters=dict(params),
        rationale="suspicious login from TOR",
    )


class _FakeJira:
    async def create_issue(self, **_kw: object) -> dict:
        return {"external_id": "SEC-1", "external_url": "https://j/browse/SEC-1", "vendor": "jira"}


class _FakeServiceNow:
    async def create_incident(self, **_kw: object) -> dict:
        return {
            "external_id": "deadbeef",
            "external_number": "INC0010023",
            "external_url": "https://snow/incident.do?sys_id=deadbeef",
            "vendor": "servicenow",
            "state": "1",
        }


class _FakePagerDuty:
    async def trigger_incident(self, **_kw: object) -> dict:
        return {"dedup_key": "aisoc-x", "status": "success", "vendor": "pagerduty"}


@pytest.mark.asyncio
async def test_prefers_jira_when_jira_and_snow_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notification, "_jira_client", lambda p: _FakeJira())
    monkeypatch.setattr(notification, "_snow_client", lambda p: _FakeServiceNow())
    monkeypatch.setattr(notification, "_pd_client", lambda p: None)

    result = await CreateTicketExecutor().execute(_request())
    assert result.status == ActionStatus.COMPLETED
    assert result.output["ticket_system"] == "jira"
    assert result.output["ticket_id"] == "SEC-1"
    assert result.rollback_data["vendor"] == "jira"


@pytest.mark.asyncio
async def test_falls_through_to_servicenow_when_jira_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notification, "_jira_client", lambda p: None)
    monkeypatch.setattr(notification, "_snow_client", lambda p: _FakeServiceNow())
    monkeypatch.setattr(notification, "_pd_client", lambda p: None)

    result = await CreateTicketExecutor().execute(_request())
    assert result.output["ticket_system"] == "servicenow"
    assert result.output["ticket_number"] == "INC0010023"


@pytest.mark.asyncio
async def test_explicit_pagerduty_system_overrides_default_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    """When operator sets ticket_system=pagerduty, we page even if
    Jira credentials are also available — they explicitly want a
    page, not a ticket."""
    monkeypatch.setattr(notification, "_jira_client", lambda p: _FakeJira())
    monkeypatch.setattr(notification, "_snow_client", lambda p: _FakeServiceNow())
    monkeypatch.setattr(notification, "_pd_client", lambda p: _FakePagerDuty())

    result = await CreateTicketExecutor().execute(_request(ticket_system="pagerduty"))
    assert result.output["ticket_system"] == "pagerduty"
    assert result.output["dedup_key"] == "aisoc-x"
    assert result.rollback_data["vendor"] == "pagerduty"


@pytest.mark.asyncio
async def test_explicit_unknown_system_falls_through_to_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown ticket_system value (e.g. typo) shouldn't blow
    the action up — fall through to the default priority order."""
    monkeypatch.setattr(notification, "_jira_client", lambda p: _FakeJira())
    monkeypatch.setattr(notification, "_snow_client", lambda p: None)
    monkeypatch.setattr(notification, "_pd_client", lambda p: None)

    result = await CreateTicketExecutor().execute(_request(ticket_system="github"))
    assert result.output["ticket_system"] == "jira"


@pytest.mark.asyncio
async def test_simulation_when_no_credentials_lists_all_vendors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notification, "_jira_client", lambda p: None)
    monkeypatch.setattr(notification, "_snow_client", lambda p: None)
    monkeypatch.setattr(notification, "_pd_client", lambda p: None)

    result = await CreateTicketExecutor().execute(_request())
    assert result.status == ActionStatus.COMPLETED
    note = result.output["note"]
    assert "Simulation mode" in note
    assert "jira_" in note
    assert "snow_" in note
    assert "pd_routing_key" in note
    assert result.output["ticket_id"].startswith("SIM-TICKET-")


@pytest.mark.asyncio
async def test_vendor_failure_surfaces_as_failed_status(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenJira:
        async def create_issue(self, **_kw: object) -> dict:
            raise RuntimeError("jira 500: Service Unavailable")

    monkeypatch.setattr(notification, "_jira_client", lambda p: _BrokenJira())
    monkeypatch.setattr(notification, "_snow_client", lambda p: None)
    monkeypatch.setattr(notification, "_pd_client", lambda p: None)

    result = await CreateTicketExecutor().execute(_request())
    assert result.status == ActionStatus.FAILED
    assert "jira 500" in (result.error or "")


@pytest.mark.asyncio
async def test_pagerduty_pageonly_fires_when_only_pd_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirms the default-priority path falls all the way through
    to PagerDuty if it's the only vendor with creds — important for
    on-call-only deployments."""
    monkeypatch.setattr(notification, "_jira_client", lambda p: None)
    monkeypatch.setattr(notification, "_snow_client", lambda p: None)
    monkeypatch.setattr(notification, "_pd_client", lambda p: _FakePagerDuty())

    result = await CreateTicketExecutor().execute(_request())
    assert result.output["ticket_system"] == "pagerduty"
