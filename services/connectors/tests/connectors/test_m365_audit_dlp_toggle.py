"""The M365 audit DLP.All switch is real, per instance (WS4.2).

What was wrong
--------------
The module docstring promised "DLP can be re-enabled per-instance later via
``connector_config``" while ``_DEFAULT_CONTENT_TYPES`` was hard-coded and
``__init__`` accepted no such setting — the aspirational-comment family the
registry already carries in three other connectors. A tenant who wanted
Purview DLP events through the audit trail had no switch to flip, and the
docstring said there was one coming, indefinitely.

What this asserts
-----------------
* ``schema()`` declares the opt-in boolean (``default=False``) so the wizard
  renders it and the instance row persists it.
* The constructor accepts it; coercion follows the house `_truthy` rule — a
  boolean from the wizard and a string from a hand-written row mean the same
  thing, and **an unparseable value means off** (a collector that defaults
  to on when it cannot read its own switch is a poll the tenant did not ask
  for).
* With the switch off (the default), the content types polled are exactly
  the four ``Audit.*`` streams — the subscription and listing calls never
  name ``DLP.All``.
* With the switch on, ``DLP.All`` joins them — observed through the real
  fetch path against a mock vendor, not inferred from a constant.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.connectors import m365_audit
from app.connectors.m365_audit import M365AuditConnector


class _FakeManagementApi:
    """The Office 365 Management Activity API: token, subscriptions, content."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def content_types_listed(self) -> set[str]:
        types: set[str] = set()
        for request in self.requests:
            ct = request.url.params.get("contentType")
            if ct:
                types.add(ct)
        return types

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3599})
        if "/subscriptions/list" in path:
            return httpx.Response(200, json=[])
        if "/subscriptions/start" in path:
            return httpx.Response(200, json={"status": "enabled"})
        if "/subscriptions/content" in path:
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"error": f"no route {path}"})


def _connector(api: _FakeManagementApi, **kwargs: Any) -> M365AuditConnector:
    return M365AuditConnector(
        tenant_id="t-1",
        client_id="c-1",
        client_secret="s-1",
        transport=httpx.MockTransport(api.handle),
        **kwargs,
    )


class TestSchema:
    def test_the_switch_is_declared_and_defaults_off(self) -> None:
        fields = {f.name: f for f in M365AuditConnector.schema().fields}
        assert "include_dlp" in fields, "the per-instance switch must be a declared field"
        assert fields["include_dlp"].default in (False, "false", None)

    def test_the_docstring_no_longer_promises_later(self) -> None:
        assert "later" not in (m365_audit.__doc__ or ""), (
            "the docstring promised the switch 'later'; now that it exists, say what is true instead"
        )


class TestContentTypeSelection:
    def test_default_excludes_dlp(self) -> None:
        api = _FakeManagementApi()
        connector = _connector(api)
        assert "DLP.All" not in connector.content_types()
        assert set(connector.content_types()) == {
            "Audit.AzureActiveDirectory",
            "Audit.Exchange",
            "Audit.SharePoint",
            "Audit.General",
        }

    @pytest.mark.parametrize("value", [True, "true", "1", "yes", "on"])
    def test_truthy_values_enable_dlp(self, value: Any) -> None:
        api = _FakeManagementApi()
        connector = _connector(api, include_dlp=value)
        assert "DLP.All" in connector.content_types()

    @pytest.mark.parametrize("value", [False, "false", "0", "", None, "banana"])
    def test_everything_else_means_off(self, value: Any) -> None:
        api = _FakeManagementApi()
        connector = _connector(api, include_dlp=value)
        assert "DLP.All" not in connector.content_types()


@pytest.mark.asyncio
class TestFetchPath:
    async def test_the_switch_reaches_the_wire(self) -> None:
        api_off = _FakeManagementApi()
        await _connector(api_off).fetch_alerts(since_seconds=300)
        assert "DLP.All" not in api_off.content_types_listed()
        assert "Audit.Exchange" in api_off.content_types_listed()

        api_on = _FakeManagementApi()
        await _connector(api_on, include_dlp=True).fetch_alerts(since_seconds=300)
        assert "DLP.All" in api_on.content_types_listed()
