"""
Phase 3.5 wire-shape tests for the new ticketing clients.

These mock httpx via respx so they never touch Atlassian, the
ServiceNow Table API, or PagerDuty. Each test pins the URL,
method, payload shape, and headers AiSOC sends. If a vendor
silently changes their contract, CI catches it on PR rather than
at 3am during an incident.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from app.clients.jira_client import JiraClient
from app.clients.pagerduty_client import PagerDutyClient
from app.clients.servicenow_client import ServiceNowClient

# --------------------------- Jira ---------------------------


@pytest.mark.asyncio
async def test_jira_create_issue_sends_adf_description_and_round_trips_case_label() -> None:
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://acme.atlassian.net/rest/api/3/issue").mock(
            return_value=httpx.Response(201, json={"id": "10001", "key": "SEC-42"})
        )
        client = JiraClient(
            base_url="https://acme.atlassian.net",
            email="aisoc@acme.com",
            api_token="token",
            project_key="SEC",
        )
        result = await client.create_issue(
            summary="Suspicious login from TOR",
            description="User alice logged in from a TOR exit node.",
            severity="high",
            case_id="case-42",
        )
        assert result["external_id"] == "SEC-42"
        assert result["external_url"] == "https://acme.atlassian.net/browse/SEC-42"
        body = json.loads(route.calls[0].request.content)
        assert body["fields"]["project"] == {"key": "SEC"}
        assert body["fields"]["priority"] == {"name": "High"}
        assert body["fields"]["issuetype"] == {"name": "Task"}
        # ADF: not a raw string
        assert body["fields"]["description"]["type"] == "doc"
        # Labels: case identifier must round-trip exactly
        assert "aisoc-case-case-42" in body["fields"]["labels"]
        assert "aisoc" in body["fields"]["labels"]


@pytest.mark.asyncio
async def test_jira_create_issue_requires_project_key() -> None:
    client = JiraClient(
        base_url="https://acme.atlassian.net",
        email="aisoc@acme.com",
        api_token="token",
    )
    with pytest.raises(ValueError):
        await client.create_issue(summary="x", description="y")


@pytest.mark.asyncio
async def test_jira_transition_issue_resolves_then_posts_transition() -> None:
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://acme.atlassian.net/rest/api/3/issue/SEC-1/transitions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "transitions": [
                        {"id": "11", "name": "To Do", "to": {"name": "To Do"}},
                        {"id": "21", "name": "Done", "to": {"name": "Done"}},
                    ]
                },
            )
        )
        post = mock.post("https://acme.atlassian.net/rest/api/3/issue/SEC-1/transitions").mock(return_value=httpx.Response(204))

        client = JiraClient(
            base_url="https://acme.atlassian.net",
            email="aisoc@acme.com",
            api_token="token",
        )
        result = await client.transition_issue("SEC-1", "Done")
        assert result["transitioned"] is True
        body = json.loads(post.calls[0].request.content)
        assert body == {"transition": {"id": "21"}}


@pytest.mark.asyncio
async def test_jira_transition_issue_handles_missing_workflow_path() -> None:
    """When Jira's workflow has no transition to the target, we
    must return ``transitioned=False`` rather than retry — no
    amount of retrying will make the workflow contain the
    transition."""
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://acme.atlassian.net/rest/api/3/issue/SEC-1/transitions").mock(
            return_value=httpx.Response(200, json={"transitions": []})
        )
        client = JiraClient(
            base_url="https://acme.atlassian.net",
            email="aisoc@acme.com",
            api_token="token",
        )
        result = await client.transition_issue("SEC-1", "Done")
        assert result["transitioned"] is False
        assert result["reason"] == "no_transition"


# --------------------------- ServiceNow ---------------------------


@pytest.mark.asyncio
async def test_servicenow_create_incident_posts_to_table_api() -> None:
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://acme.service-now.com/api/now/table/incident").mock(
            return_value=httpx.Response(
                201,
                json={
                    "result": {
                        "sys_id": "deadbeefcafebabedeadbeefcafebabe",
                        "number": "INC0010023",
                        "state": "1",
                    }
                },
            )
        )
        client = ServiceNowClient(
            instance_url="https://acme.service-now.com",
            username="aisoc",
            password="pw",
        )
        result = await client.create_incident(
            short_description="Suspicious login from TOR",
            description="User alice from TOR exit",
            severity="critical",
            case_id="case-42",
        )
        assert result["external_id"].startswith("deadbeef")
        assert result["external_number"] == "INC0010023"
        body = json.loads(route.calls[0].request.content)
        # Severity=critical → impact=1 + urgency=1
        assert body["impact"] == "1"
        assert body["urgency"] == "1"
        # correlation_id is how the inbound webhook finds us
        assert body["correlation_id"] == "aisoc:case-42"
        assert body["correlation_display"] == "AiSOC"


@pytest.mark.asyncio
async def test_servicenow_set_state_resolved_fills_close_metadata() -> None:
    """Resolved (6) and Closed (7) states fail silently on stock SN
    UI policies unless close_code + close_notes are sent. The client
    must inject benign defaults — confirm that on the wire."""
    with respx.mock(assert_all_called=True) as mock:
        patch = mock.patch("https://acme.service-now.com/api/now/table/incident/sys-id-1").mock(
            return_value=httpx.Response(200, json={"result": {}})
        )

        client = ServiceNowClient(
            instance_url="https://acme.service-now.com",
            username="aisoc",
            password="pw",
        )
        await client.set_state("sys-id-1", "6", case_id="case-7")
        body = json.loads(patch.calls[0].request.content)
        assert body["state"] == "6"
        assert "close_code" in body
        assert "close_notes" in body
        assert "case-7" in body["close_notes"]


@pytest.mark.asyncio
async def test_servicenow_set_state_in_progress_omits_close_metadata() -> None:
    with respx.mock(assert_all_called=True) as mock:
        patch = mock.patch("https://acme.service-now.com/api/now/table/incident/sys-id-1").mock(
            return_value=httpx.Response(200, json={"result": {}})
        )

        client = ServiceNowClient(
            instance_url="https://acme.service-now.com",
            username="aisoc",
            password="pw",
        )
        await client.set_state("sys-id-1", "2")
        body = json.loads(patch.calls[0].request.content)
        assert body == {"state": "2"}


@pytest.mark.asyncio
async def test_servicenow_add_work_note_patches_journal() -> None:
    with respx.mock(assert_all_called=True) as mock:
        patch = mock.patch("https://acme.service-now.com/api/now/table/incident/sys-id-1").mock(
            return_value=httpx.Response(200, json={"result": {}})
        )

        client = ServiceNowClient(
            instance_url="https://acme.service-now.com",
            username="aisoc",
            password="pw",
        )
        result = await client.add_work_note("sys-id-1", "AiSOC investigation update")
        assert result["noted"] is True
        body = json.loads(patch.calls[0].request.content)
        assert body == {"work_notes": "AiSOC investigation update"}


# --------------------------- PagerDuty Events API v2 ---------------------------


@pytest.mark.asyncio
async def test_pagerduty_trigger_uses_aisoc_dedup_key_and_correct_severity() -> None:
    """Re-firing the same case must hit the existing PD incident
    (idempotency via dedup_key), and the AiSOC severity must fold
    to PagerDuty's closed enum {critical/error/warning/info}."""
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(
                202,
                json={"dedup_key": "aisoc-case-42", "status": "success", "message": "Event processed"},
            )
        )
        client = PagerDutyClient(routing_key="routing-key-32-chars")
        result = await client.trigger_incident(
            summary="Suspicious login from TOR",
            severity="critical",
            case_id="case-42",
            source="aisoc",
        )
        assert result["status"] == "success"
        assert result["dedup_key"] == "aisoc-case-42"
        body = json.loads(route.calls[0].request.content)
        assert body["routing_key"] == "routing-key-32-chars"
        assert body["event_action"] == "trigger"
        assert body["dedup_key"] == "aisoc-case-42"
        assert body["payload"]["severity"] == "critical"
        assert body["payload"]["source"] == "aisoc"


@pytest.mark.asyncio
async def test_pagerduty_acknowledge_targets_same_dedup_key() -> None:
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"dedup_key": "aisoc-case-42", "status": "success"})
        )
        client = PagerDutyClient(routing_key="routing-key")
        result = await client.acknowledge_incident("case-42")
        assert result["status"] == "success"
        body = json.loads(route.calls[0].request.content)
        assert body["event_action"] == "acknowledge"
        assert body["dedup_key"] == "aisoc-case-42"
        # acknowledge has no payload block
        assert "payload" not in body


@pytest.mark.asyncio
async def test_pagerduty_resolve_targets_same_dedup_key() -> None:
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://events.pagerduty.com/v2/enqueue").mock(
            return_value=httpx.Response(202, json={"dedup_key": "aisoc-case-42", "status": "success"})
        )
        client = PagerDutyClient(routing_key="routing-key")
        result = await client.resolve_incident("case-42")
        assert result["status"] == "success"
        body = json.loads(route.calls[0].request.content)
        assert body["event_action"] == "resolve"
        assert body["dedup_key"] == "aisoc-case-42"
