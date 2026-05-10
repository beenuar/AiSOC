"""Unit tests for Workstream 8 ``push_case`` / ``push_status_change`` paths.

These tests cover the bidirectional ITSM capability shipped on the Jira and
ServiceNow connectors:

* ``push_case`` happy paths (correct payload, correct vendor mapping) and the
  HTTP error → ``HTTPStatusError`` propagation contract the fan-out service
  depends on.
* ``push_status_change`` decision tree:
    - ``external_ref is None`` → falls through to ``push_case`` so callers
      don't have to special-case "first push".
    - Unknown AiSOC status → no-op return (no HTTP call) since the contract
      is "best-effort projection", not "schema match".
    - Jira: discover-then-transition path including the "no transition
      available for target status" workflow no-op.
    - ServiceNow: ``Resolved`` / ``Closed`` states require ``close_code`` +
      ``close_notes`` or the API silently ignores the state change.

We deliberately avoid ``respx`` (not installed in this env per
``pyproject.toml`` dev deps) and instead patch ``httpx.AsyncClient`` with
``unittest.mock`` mirroring ``services/api/tests/test_case_fanout.py``. That
also keeps these tests aligned with the in-repo mock patterns reviewers
already understand.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.connectors.jira_connector import JiraConnector
from app.connectors.servicenow import ServiceNowConnector

# ---------------------------------------------------------------------------
# Helpers — build httpx.Response stubs without instantiating a real Client.
# ---------------------------------------------------------------------------


def _build_response(
    *,
    status_code: int = 200,
    json_body: dict[str, Any] | list[Any] | None = None,
    text: str = "",
    method: str = "POST",
    url: str = "http://example.invalid/",
) -> MagicMock:
    """Build a MagicMock that walks like an ``httpx.Response``.

    We only need the attributes the connector code touches:
    ``status_code``, ``json()``, ``text``, ``request``, plus ``raise_for_status``
    (called by ``_resolve_transition_id`` on the Jira side).
    """
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_body if json_body is not None else {})
    resp.text = text
    # ``request`` is required for ``HTTPStatusError`` construction.
    resp.request = httpx.Request(method, url)

    def _raise_for_status() -> None:
        if status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{status_code} error",
                request=resp.request,
                response=resp,
            )

    resp.raise_for_status = MagicMock(side_effect=_raise_for_status)
    return resp


def _patch_async_client(
    *,
    post_responses: list[MagicMock] | MagicMock | None = None,
    get_responses: list[MagicMock] | MagicMock | None = None,
    patch_responses: list[MagicMock] | MagicMock | None = None,
) -> tuple[Any, AsyncMock, AsyncMock, AsyncMock]:
    """Patch ``httpx.AsyncClient`` for a connector module.

    Returns ``(context_manager, post_mock, get_mock, patch_mock)``. Use as::

        with _patch_async_client(...) as ctx:
            post_mock, get_mock, patch_mock = ctx

    Or, more commonly here, drive each patch context directly per test.
    """
    raise NotImplementedError  # placeholder — kept for shape; tests use the inline pattern below.


def _async_responses(responses: list[MagicMock] | MagicMock | None) -> AsyncMock:
    """Build an AsyncMock that returns each response in sequence (or always
    the same one if a single mock is supplied)."""
    if responses is None:
        return AsyncMock(side_effect=AssertionError("unexpected HTTP call"))
    if isinstance(responses, list):
        return AsyncMock(side_effect=responses)
    return AsyncMock(return_value=responses)


# ===========================================================================
# Jira: push_case
# ===========================================================================


@pytest.mark.asyncio
async def test_jira_push_case_builds_correct_payload_and_url() -> None:
    """Happy path: severity → priority, ADF description, aisoc-case label."""
    case = {
        "id": "11111111-2222-3333-4444-555555555555",
        "case_number": "AIS-42",
        "title": "Suspected lateral movement",
        "description": "Multiple SMB connects from finance subnet to DC.",
        "severity": "high",
        "status": "investigating",
    }

    connector = JiraConnector(
        base_url="https://acme.atlassian.net/",  # trailing slash on purpose.
        email="bot@acme.io",
        api_token="api-token-xyz",
        project_key="SEC",
    )
    response = _build_response(
        status_code=201,
        json_body={"key": "SEC-42", "id": "10042"},
    )

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        result = await connector.push_case(case)

    assert post_mock.await_count == 1
    call = post_mock.await_args
    # ``base_url`` was rstripped, so the resulting URL has exactly one slash.
    assert call.args[0] == "https://acme.atlassian.net/rest/api/3/issue"

    payload = call.kwargs["json"]
    assert payload["fields"]["project"] == {"key": "SEC"}
    assert payload["fields"]["priority"] == {"name": "High"}
    # ADF doc shape — connector wraps the plain string under content[0].text.
    assert payload["fields"]["description"]["type"] == "doc"
    assert payload["fields"]["description"]["content"][0]["content"][0]["text"] == case["description"]
    # Label round-trips the AiSOC case identifier so the inbound webhook
    # can link the issue back to us without a custom field.
    assert f"aisoc-case-{case['id']}" in payload["fields"]["labels"]
    assert "aisoc" in payload["fields"]["labels"]

    headers = call.kwargs["headers"]
    assert headers["Authorization"].startswith("Basic ")

    assert result == {
        "external_id": "SEC-42",
        "external_url": "https://acme.atlassian.net/browse/SEC-42",
        "vendor": "jira",
        "external_status": "To Do",
    }


@pytest.mark.asyncio
async def test_jira_push_case_requires_project_key() -> None:
    """Missing project_key MUST raise rather than silently 400 against Jira."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key=None,
    )

    with pytest.raises(ValueError, match="project_key not configured"):
        await connector.push_case({"id": "1", "title": "x"})


@pytest.mark.asyncio
async def test_jira_push_case_severity_collapses_to_default() -> None:
    """Unknown severity falls back to Medium rather than crashing."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    response = _build_response(status_code=201, json_body={"key": "SEC-1", "id": "1"})

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        await connector.push_case({"id": "1", "title": "x", "severity": "absurdly-bad"})

    payload = post_mock.await_args.kwargs["json"]
    assert payload["fields"]["priority"] == {"name": "Medium"}


@pytest.mark.asyncio
async def test_jira_push_case_summary_truncates_at_255() -> None:
    """Jira hard-caps summary at 255 chars; longer titles must be sliced."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    long_title = "x" * 400
    response = _build_response(status_code=201, json_body={"key": "SEC-1", "id": "1"})

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        await connector.push_case({"id": "1", "title": long_title})

    payload = post_mock.await_args.kwargs["json"]
    assert len(payload["fields"]["summary"]) == 255


@pytest.mark.asyncio
async def test_jira_push_case_raises_on_4xx() -> None:
    """Jira 4xx must surface as HTTPStatusError so the fan-out service can
    persist a ``failed`` external_ref instead of silently dropping the push."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    response = _build_response(status_code=400, text="bad project key")

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        with pytest.raises(httpx.HTTPStatusError, match="jira.push_case failed"):
            await connector.push_case({"id": "1", "title": "x"})


# ===========================================================================
# Jira: push_status_change
# ===========================================================================


@pytest.mark.asyncio
async def test_jira_push_status_change_falls_through_to_push_case_when_no_ref() -> None:
    """First-time push (no existing external_ref) must mint the issue."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    response = _build_response(status_code=201, json_body={"key": "SEC-7", "id": "7"})

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        result = await connector.push_status_change(
            case={"id": "abc", "title": "lateral", "severity": "low"},
            old_status="new",
            new_status="investigating",
            external_ref=None,
        )

    # Single POST to /rest/api/3/issue, no transitions discovery.
    assert post_mock.await_count == 1
    assert post_mock.await_args.args[0].endswith("/rest/api/3/issue")
    assert result["external_id"] == "SEC-7"


@pytest.mark.asyncio
async def test_jira_push_status_change_requires_external_id_in_ref() -> None:
    """An external_ref dict without ``external_id`` is operator error."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    with pytest.raises(ValueError, match="missing external_id"):
        await connector.push_status_change(
            case={"id": "abc"},
            old_status="new",
            new_status="resolved",
            external_ref={"vendor": "jira"},  # no external_id
        )


@pytest.mark.asyncio
async def test_jira_push_status_change_unknown_status_is_noop() -> None:
    """Unknown AiSOC statuses return without making any HTTP call."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        # If we DO end up calling httpx, the context manager's get/post
        # mocks are AsyncMock() defaults — nothing assertable here, so the
        # real check is "we never enter the client at all".
        result = await connector.push_status_change(
            case={"id": "abc"},
            old_status="new",
            new_status="alien-status",
            external_ref={"external_id": "SEC-9", "external_status": "To Do"},
        )
        # Connector must NOT instantiate a client when there's no work.
        assert mock_client.call_count == 0

    assert result["external_id"] == "SEC-9"
    assert result["external_status"] == "To Do"  # unchanged from external_ref


@pytest.mark.asyncio
async def test_jira_push_status_change_no_matching_transition_is_noop() -> None:
    """Workflow may not expose a transition to the target status — return
    without mutating, since retrying won't change the workflow."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    transitions_response = _build_response(
        status_code=200,
        json_body={
            "transitions": [
                {"id": "11", "name": "Reopen", "to": {"name": "To Do"}},
                # No "Done" or "In Progress" transition exposed.
            ]
        },
    )

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        get_mock = AsyncMock(return_value=transitions_response)
        post_mock = AsyncMock()  # MUST NOT be called.
        mock_client.return_value.__aenter__.return_value.get = get_mock
        mock_client.return_value.__aenter__.return_value.post = post_mock

        result = await connector.push_status_change(
            case={"id": "abc"},
            old_status="new",
            new_status="resolved",  # → "Done", not in workflow.
            external_ref={"external_id": "SEC-9", "external_status": "To Do"},
        )

    assert get_mock.await_count == 1
    assert post_mock.await_count == 0  # critical: no transition POST
    assert result["external_id"] == "SEC-9"


@pytest.mark.asyncio
async def test_jira_push_status_change_resolves_and_posts_transition() -> None:
    """Happy path: discover the transition then POST it with that ID."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    transitions_response = _build_response(
        status_code=200,
        json_body={
            "transitions": [
                {"id": "11", "name": "Start", "to": {"name": "In Progress"}},
                {"id": "21", "name": "Resolve", "to": {"name": "Done"}},
            ]
        },
    )
    transition_post = _build_response(status_code=204)

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        get_mock = AsyncMock(return_value=transitions_response)
        post_mock = AsyncMock(return_value=transition_post)
        mock_client.return_value.__aenter__.return_value.get = get_mock
        mock_client.return_value.__aenter__.return_value.post = post_mock

        result = await connector.push_status_change(
            case={"id": "abc"},
            old_status="new",
            new_status="resolved",
            external_ref={"external_id": "SEC-9", "external_status": "To Do"},
        )

    # GET .../transitions then POST .../transitions with id=21.
    assert get_mock.await_args.args[0].endswith("/rest/api/3/issue/SEC-9/transitions")
    assert post_mock.await_args.args[0].endswith("/rest/api/3/issue/SEC-9/transitions")
    assert post_mock.await_args.kwargs["json"] == {"transition": {"id": "21"}}
    assert result["external_status"] == "Done"


@pytest.mark.asyncio
async def test_jira_push_status_change_raises_on_transition_4xx() -> None:
    """A non-2xx on the transition POST surfaces as HTTPStatusError."""
    connector = JiraConnector(
        base_url="https://acme.atlassian.net",
        email="bot@acme.io",
        api_token="t",
        project_key="SEC",
    )
    transitions_response = _build_response(
        status_code=200,
        json_body={"transitions": [{"id": "21", "name": "Resolve", "to": {"name": "Done"}}]},
    )
    transition_post = _build_response(status_code=403, text="forbidden")

    with patch("app.connectors.jira_connector.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=transitions_response)
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=transition_post)

        with pytest.raises(httpx.HTTPStatusError, match="jira.push_status_change failed"):
            await connector.push_status_change(
                case={"id": "abc"},
                old_status="new",
                new_status="closed",
                external_ref={"external_id": "SEC-9"},
            )


# ===========================================================================
# ServiceNow: push_case
# ===========================================================================


@pytest.mark.asyncio
async def test_snow_push_case_posts_to_table_with_correlation_id() -> None:
    """Happy path: incident table POST, correlation_id round-trips case id."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com/",
        username="aisoc-bot",
        password="hunter2",
    )
    response = _build_response(
        status_code=201,
        json_body={
            "result": {
                "sys_id": "abcdef0123456789abcdef0123456789",
                "number": "INC0010023",
                "state": "1",
            }
        },
    )

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock

        result = await connector.push_case(
            {
                "id": "case-uuid-1",
                "case_number": "AIS-42",
                "title": "Lateral movement detected",
                "description": "SMB scan",
                "severity": "critical",
            }
        )

    assert post_mock.await_count == 1
    call = post_mock.await_args
    assert call.args[0] == "https://acme.service-now.com/api/now/table/incident"
    body = call.kwargs["json"]
    assert body["short_description"] == "Lateral movement detected"
    # severity=critical → impact=1 (urgency mirrors impact for OOTB).
    assert body["impact"] == "1"
    assert body["urgency"] == "1"
    # correlation_id round-trips the AiSOC case identifier.
    assert body["correlation_id"] == "aisoc:case-uuid-1"

    assert result["external_id"] == "abcdef0123456789abcdef0123456789"
    assert result["vendor"] == "servicenow"
    # _record_url with number returns the nav_to.do form.
    assert "sys_id=abcdef0123456789abcdef0123456789" in result["external_url"]


@pytest.mark.asyncio
async def test_snow_push_case_short_description_truncates_at_160() -> None:
    """short_description in ServiceNow caps at 160 chars."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=201, json_body={"result": {"sys_id": "x" * 32, "state": "1"}})

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        await connector.push_case({"id": "1", "title": "y" * 300})

    body = post_mock.await_args.kwargs["json"]
    assert len(body["short_description"]) == 160


@pytest.mark.asyncio
async def test_snow_push_case_raises_on_4xx() -> None:
    """ServiceNow 4xx must propagate so the fan-out service can mark
    the external_ref ``failed`` rather than silently dropping the push."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=400, text="ACL denied")

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        with pytest.raises(httpx.HTTPStatusError, match="servicenow.push_case failed"):
            await connector.push_case({"id": "1", "title": "x"})


# ===========================================================================
# ServiceNow: push_status_change
# ===========================================================================


@pytest.mark.asyncio
async def test_snow_push_status_change_falls_through_to_push_case_when_no_ref() -> None:
    """No ref → mint the incident."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=201, json_body={"result": {"sys_id": "x" * 32, "state": "1"}})

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post_mock
        result = await connector.push_status_change(
            case={"id": "1", "title": "x"},
            old_status="new",
            new_status="investigating",
            external_ref=None,
        )

    assert post_mock.await_count == 1
    assert post_mock.await_args.args[0].endswith("/api/now/table/incident")
    assert result["external_id"] == "x" * 32


@pytest.mark.asyncio
async def test_snow_push_status_change_requires_external_id_in_ref() -> None:
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    with pytest.raises(ValueError, match="missing external_id"):
        await connector.push_status_change(
            case={"id": "1"},
            old_status="new",
            new_status="resolved",
            external_ref={"vendor": "servicenow"},
        )


@pytest.mark.asyncio
async def test_snow_push_status_change_unknown_status_is_noop() -> None:
    """Unknown AiSOC status → no HTTP call, return ref unchanged."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        result = await connector.push_status_change(
            case={"id": "1"},
            old_status="new",
            new_status="alien-status",
            external_ref={"external_id": "ABC", "external_status": "1"},
        )
        assert mock_client.call_count == 0

    assert result["external_id"] == "ABC"
    assert result["external_status"] == "1"


@pytest.mark.asyncio
async def test_snow_push_status_change_in_progress_patches_state_only() -> None:
    """Non-resolved transitions only set ``state`` — no close metadata."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=200, json_body={"result": {"sys_id": "abc", "state": "2"}})

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        patch_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.patch = patch_mock

        result = await connector.push_status_change(
            case={"id": "case-uuid"},
            old_status="new",
            new_status="investigating",
            external_ref={"external_id": "abc", "external_status": "1"},
        )

    assert patch_mock.await_count == 1
    body = patch_mock.await_args.kwargs["json"]
    assert body == {"state": "2"}
    # Critically: no close_code / close_notes when not Resolved/Closed.
    assert "close_code" not in body
    assert "close_notes" not in body
    assert result["external_status"] == "2"


@pytest.mark.asyncio
async def test_snow_push_status_change_resolved_includes_close_metadata() -> None:
    """Resolved/Closed transitions MUST send close_code+close_notes or
    ServiceNow silently rejects the state change on most stock instances."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=200, json_body={"result": {"sys_id": "abc", "state": "6"}})

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        patch_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.patch = patch_mock

        await connector.push_status_change(
            case={"id": "case-uuid", "case_number": "AIS-42"},
            old_status="investigating",
            new_status="resolved",
            external_ref={"external_id": "abc", "external_status": "2"},
        )

    body = patch_mock.await_args.kwargs["json"]
    assert body["state"] == "6"
    assert body["close_code"]  # any non-empty default
    assert "AIS-42" in body["close_notes"]


@pytest.mark.asyncio
async def test_snow_push_status_change_closed_includes_close_metadata() -> None:
    """Same contract as Resolved for the Closed (state=7) bucket."""
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=200, json_body={"result": {"sys_id": "abc", "state": "7"}})

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        patch_mock = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.patch = patch_mock

        await connector.push_status_change(
            case={"id": "case-uuid"},
            old_status="resolved",
            new_status="closed",
            external_ref={"external_id": "abc", "external_status": "6"},
        )

    body = patch_mock.await_args.kwargs["json"]
    assert body["state"] == "7"
    assert "close_code" in body
    assert "close_notes" in body


@pytest.mark.asyncio
async def test_snow_push_status_change_raises_on_4xx() -> None:
    connector = ServiceNowConnector(
        instance_url="https://acme.service-now.com",
        username="u",
        password="p",
    )
    response = _build_response(status_code=403, text="ACL denied on incident")

    with patch("app.connectors.servicenow.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.patch = AsyncMock(return_value=response)
        with pytest.raises(httpx.HTTPStatusError, match="servicenow.push_status_change failed"):
            await connector.push_status_change(
                case={"id": "1"},
                old_status="new",
                new_status="resolved",
                external_ref={"external_id": "abc"},
            )


# ===========================================================================
# Capability declarations — guard against accidental drop in future PRs.
# ===========================================================================


def test_jira_capabilities_advertise_push() -> None:
    from app.connectors.base import Capability

    caps = JiraConnector.capabilities()
    assert Capability.PUSH_CASE in caps
    assert Capability.PUSH_STATUS in caps
    assert Capability.PULL_ALERTS in caps  # pre-WS8 capability still intact


def test_servicenow_capabilities_advertise_push() -> None:
    from app.connectors.base import Capability

    caps = ServiceNowConnector.capabilities()
    assert Capability.PUSH_CASE in caps
    assert Capability.PUSH_STATUS in caps
    assert Capability.PULL_ALERTS in caps
