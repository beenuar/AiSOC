"""Two-way ticket sync, driven end to end against mock vendors.

Wave-2 Phase 6.4 asks for this to be *verified* before anything is built,
and the verification is the finding: both directions are implemented and
wired, and **neither had ever been driven end to end**. Four layers, each
unit-tested with the next one mocked:

* ``services/api``'s ``case_fanout`` patches ``httpx.AsyncClient``, so the
  call to the connectors service never forms;
* the connectors ``push_case`` / ``push_status_change`` **routes** are
  exercised by nothing at all;
* ``test_push_capabilities.py`` patches ``httpx.AsyncClient`` with a
  ``MagicMock``, so the request that would reach Jira is never built and
  the response that comes back is whatever the test taught it;
* the inbound webhook test mocks the database session.

A chain of four correct unit tests is not a loop. This file closes the half
that lives in this service: the production route handlers, the production
connector classes, and a mock HTTP server returning recorded vendor shapes,
so the request that reaches Jira in a test is the request that reaches Jira.

Vendor references, fetched before the fixtures were written:

* Jira create issue — https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
* Jira transitions — https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
* ServiceNow Table API — https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from app.api.router import (
    PushCaseRequest,
    PushStatusChangeRequest,
    push_case,
    push_status_change,
)

pytestmark = pytest.mark.asyncio

JIRA_BASE = "https://acme.atlassian.net"
SNOW_BASE = "https://acme.service-now.com"

CASE: dict[str, Any] = {
    "id": "6f1a0d6e-0000-4000-8000-000000000001",
    "case_number": "CASE-412",
    "title": "Impossible travel on a finance account",
    "description": "Two sign-ins 4,100 km apart inside eleven minutes.",
    "severity": "high",
    "status": "investigating",
    "assignee": "ana@example.invalid",
    "tags": {},
    "mitre_techniques": ["T1078"],
}

JIRA_AUTH = {"base_url": JIRA_BASE, "email": "svc@example.invalid", "api_token": "unit-test-placeholder"}
JIRA_CONFIG = {"project_key": "SOC"}
SNOW_AUTH = {"instance_url": SNOW_BASE, "username": "svc", "password": "unit-test-placeholder"}
SNOW_CONFIG: dict[str, Any] = {}


class TestCaseChangeReachesTheTicket:
    """Direction one: AiSOC is the source and the ITSM mirrors it."""

    async def test_a_case_becomes_a_jira_issue_with_the_documented_shape(self) -> None:
        captured: dict[str, Any] = {}

        async def _create(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = request.read().decode()
            captured["auth"] = request.headers.get("authorization", "")
            return httpx.Response(201, json={"id": "10042", "key": "SOC-17", "self": f"{JIRA_BASE}/rest/api/3/issue/10042"})

        with respx.mock:
            respx.post(f"{JIRA_BASE}/rest/api/3/issue").mock(side_effect=_create)
            envelope = await push_case(
                "jira",
                PushCaseRequest(auth_config=JIRA_AUTH, connector_config=JIRA_CONFIG, case=CASE, external_ref=None),
            )

        # The envelope is exactly what `case_external_refs` stores, so an
        # envelope missing a field is a linkage the API cannot persist.
        assert envelope["external_id"] == "SOC-17"
        assert envelope["external_url"]
        assert envelope["vendor"] == "jira"

        assert captured["url"] == f"{JIRA_BASE}/rest/api/3/issue"
        assert captured["auth"].startswith("Basic ")
        # The case id round-trips as a label, which is how the inbound
        # webhook finds its way back to the case. A ticket minted without
        # it is a ticket the other direction cannot resolve.
        assert f"aisoc-case-{CASE['id']}" in captured["body"]
        assert "SOC" in captured["body"]

    async def test_a_case_becomes_a_servicenow_incident(self) -> None:
        captured: dict[str, Any] = {}

        async def _create(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = request.read().decode()
            return httpx.Response(
                201,
                json={"result": {"sys_id": "a1b2c3", "number": "INC0012345", "state": "2"}},
            )

        with respx.mock:
            respx.post(url__regex=rf"{SNOW_BASE}/api/now/table/incident.*").mock(side_effect=_create)
            envelope = await push_case(
                "servicenow",
                PushCaseRequest(auth_config=SNOW_AUTH, connector_config=SNOW_CONFIG, case=CASE, external_ref=None),
            )

        assert envelope["external_id"]
        assert envelope["vendor"] == "servicenow"
        assert "correlation_id" in captured["body"], "without a correlation id a retried push mints a second incident"

    async def test_a_status_change_reaches_the_existing_ticket(self) -> None:
        """The half that makes it two-way rather than fire-and-forget."""
        seen: list[tuple[str, str]] = []

        async def _record(request: httpx.Request) -> httpx.Response:
            seen.append((request.method, str(request.url)))
            if request.url.path.endswith("/transitions") and request.method == "GET":
                return httpx.Response(200, json={"transitions": [{"id": "31", "name": "Done", "to": {"name": "Done"}}]})
            return httpx.Response(204)

        with respx.mock:
            respx.route(host="acme.atlassian.net").mock(side_effect=_record)
            envelope = await push_status_change(
                "jira",
                PushStatusChangeRequest(
                    auth_config=JIRA_AUTH,
                    connector_config=JIRA_CONFIG,
                    case={**CASE, "status": "closed"},
                    old_status="investigating",
                    new_status="closed",
                    external_ref={"external_id": "SOC-17", "external_url": f"{JIRA_BASE}/browse/SOC-17", "vendor": "jira"},
                ),
            )

        assert envelope["external_id"] == "SOC-17"
        # Something was sent to the issue that already exists, rather than
        # a second issue being created — which is what "reaches the ticket"
        # has to mean for the loop to be a loop.
        assert seen, "no request reached Jira at all"
        assert all("/rest/api/3/issue" in url for _method, url in seen)
        assert not any(method == "POST" and url.endswith("/rest/api/3/issue") for method, url in seen), (
            "a status change minted a new issue instead of updating the existing one"
        )

    async def test_a_vendor_refusal_is_a_502_rather_than_a_silent_success(self) -> None:
        """A push that failed must not look like a ticket that exists."""
        from fastapi import HTTPException

        with respx.mock:
            respx.post(f"{JIRA_BASE}/rest/api/3/issue").respond(403, json={"errorMessages": ["no create permission"]})
            with pytest.raises(HTTPException) as raised:
                await push_case(
                    "jira",
                    PushCaseRequest(auth_config=JIRA_AUTH, connector_config=JIRA_CONFIG, case=CASE, external_ref=None),
                )
        assert raised.value.status_code == 502
        # The vendor's own body sometimes echoes request headers, so the
        # route is expected to generalise rather than forward it.
        assert "no create permission" not in str(raised.value.detail)

    async def test_a_connector_without_the_capability_is_refused(self) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as raised:
            await push_case(
                "splunk",
                PushCaseRequest(auth_config={}, connector_config={}, case=CASE, external_ref=None),
            )
        assert raised.value.status_code in (404, 501)
