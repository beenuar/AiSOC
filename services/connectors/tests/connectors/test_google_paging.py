"""Google collection reads follow ``nextPageToken`` to the end of the window.

All three of these APIs cap a response and hand back an opaque token, and all
three document that the token is how a client gets the rest:

* Cloud Logging ``entries.list`` —
  https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
  ``pageSize``: "The presence of ``nextPageToken`` in the response indicates
  that more results might be available." ``nextPageToken``: "If there might be
  more results than those appearing in this response, then ``nextPageToken``
  is included."
* Security Command Center ``findings.list`` —
  https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list
  ``pageToken``: "The value returned by the last ``ListFindingsResponse``;
  indicates that this is a continuation of a prior ``findings.list`` call, and
  that the system should return the next page of data." ``pageSize`` defaults
  to **10**.
* Admin SDK Reports ``activities.list`` —
  https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
  ``maxResults``: "Determines how many activity records are shown on each
  response page [...] The response's ``nextPageToken`` property has the token
  to the second page."

The loss is unrecoverable. ``fetch_alerts`` derives its window from the clock
with no checkpoint and the scheduler passes the poll interval as
``since_seconds``, so consecutive windows abut and nothing re-reads an earlier
one.

One Cloud Logging behaviour gets its own test because it is sharper than
truncation and a reasonable-looking loop gets it wrong. The same reference
states:

    If a value for nextPageToken appears and the entries field is empty, it
    means that the search found no log entries so far but it did not have time
    to search all the possible log entries. Retry the method with this value
    for pageToken to continue the search.

So an empty page is **not** the end of the collection. A connector that stops
on one can return zero events from a window that contained plenty.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from app.connectors import gcp_cloud_audit, gcp_scc, google_workspace
from app.connectors.gcp_cloud_audit import GCPCloudAuditConnector
from app.connectors.gcp_scc import GCPSCCConnector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_TOKEN_HOSTS = {"oauth2.googleapis.com", "accounts.google.com", "www.googleapis.com"}


@pytest.fixture(scope="module")
def service_account_json() -> str:
    """A structurally real key, so the connector's own JWT signing runs."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "example-project",
            "private_key": pem,
            "client_email": "aisoc@example-project.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


def _mock_client(monkeypatch: pytest.MonkeyPatch, module: Any, handler: Any) -> None:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


def _is_token_request(request: httpx.Request) -> bool:
    return request.url.host in _TOKEN_HOSTS and "token" in request.url.path


def _token_response() -> httpx.Response:
    return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})


@pytest.mark.asyncio
async def test_cloud_audit_reads_every_page_of_a_truncated_window(monkeypatch: pytest.MonkeyPatch, service_account_json: str) -> None:
    """460 Cloud Audit entries in one window arrive in full, not the newest 200."""
    rows = [{"insertId": f"e-{i}", "timestamp": "2099-01-01T00:00:00Z", "protoPayload": {"methodName": "m"}} for i in range(460)]
    tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _is_token_request(request):
            return _token_response()
        body = json.loads(request.content or b"{}")
        start = int(body.get("pageToken") or 0)
        tokens.append(str(start))
        page = rows[start : start + 200]
        out: dict[str, Any] = {"entries": page}
        if start + 200 < len(rows):
            out["nextPageToken"] = str(start + 200)
        return httpx.Response(200, json=out)

    _mock_client(monkeypatch, gcp_cloud_audit, handler)
    connector = GCPCloudAuditConnector(project_id="p", service_account_json=service_account_json)

    out = await connector.fetch_alerts()

    assert tokens == ["0", "200", "400"], "every page of the window must be requested"
    assert len(out) == 460, "reading one page silently discards 260 audit entries of the window"


@pytest.mark.asyncio
async def test_cloud_audit_keeps_going_through_an_empty_page_with_a_token(
    monkeypatch: pytest.MonkeyPatch, service_account_json: str
) -> None:
    """An empty page carrying a token means "still searching", not "done".

    Cloud Logging returns this when the search has not had time to scan every
    possible entry. Treating it as the end of the collection returns zero
    events from a window that had them.
    """
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _is_token_request(request):
            return _token_response()
        body = json.loads(request.content or b"{}")
        token = str(body.get("pageToken") or "")
        calls.append(token)
        if token == "":
            # The documented "found nothing so far, keep going" response.
            return httpx.Response(200, json={"entries": [], "nextPageToken": "keep-going"})
        return httpx.Response(200, json={"entries": [{"insertId": "late", "timestamp": "2099-01-01T00:00:00Z"}]})

    _mock_client(monkeypatch, gcp_cloud_audit, handler)
    connector = GCPCloudAuditConnector(project_id="p", service_account_json=service_account_json)

    out = await connector.fetch_alerts()

    assert calls == ["", "keep-going"], "an empty page with a token must be followed, not treated as the end"
    assert len(out) == 1, "the entry behind the empty page was never read"


@pytest.mark.asyncio
async def test_scc_reads_every_page_of_a_truncated_window(monkeypatch: pytest.MonkeyPatch, service_account_json: str) -> None:
    """430 SCC findings in one window arrive in full, not the first 200."""
    rows = [{"finding": {"name": f"f-{i}", "category": "C", "severity": "HIGH", "eventTime": "2099-01-01T00:00:00Z"}} for i in range(430)]
    tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _is_token_request(request):
            return _token_response()
        start = int(request.url.params.get("pageToken") or 0)
        tokens.append(str(start))
        page = rows[start : start + 200]
        out: dict[str, Any] = {"listFindingsResults": page}
        if start + 200 < len(rows):
            out["nextPageToken"] = str(start + 200)
        return httpx.Response(200, json=out)

    _mock_client(monkeypatch, gcp_scc, handler)
    connector = GCPSCCConnector(organization_id="org", service_account_json=service_account_json)

    out = await connector.fetch_alerts()

    assert tokens == ["0", "200", "400"], "every page of the window must be requested"
    assert len(out) == 430, "reading one page silently discards 230 findings of the window"


@pytest.mark.asyncio
async def test_workspace_reads_every_page_of_each_application(monkeypatch: pytest.MonkeyPatch, service_account_json: str) -> None:
    """A noisy Workspace application is read to the end of the window."""
    per_app = 1200
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if _is_token_request(request):
            return _token_response()
        app_name = request.url.path.rsplit("/", 1)[-1]
        token = str(request.url.params.get("pageToken") or "0")
        seen.append((app_name, token))
        start = int(token)
        rows = [
            {
                "id": {"time": "2099-01-01T00:00:00Z", "uniqueQualifier": f"{app_name}-{i}", "applicationName": app_name},
                "events": [{"name": "login"}],
            }
            for i in range(per_app)
        ]
        page = rows[start : start + 500]
        out: dict[str, Any] = {"items": page}
        if start + 500 < per_app:
            out["nextPageToken"] = str(start + 500)
        return httpx.Response(200, json=out)

    _mock_client(monkeypatch, google_workspace, handler)
    connector = GoogleWorkspaceConnector(admin_email="a@b.c", service_account_json=service_account_json)

    out = await connector.fetch_alerts()

    apps = {app for app, _ in seen}
    for app in apps:
        assert [t for a, t in seen if a == app] == ["0", "500", "1000"], f"{app} was not read to the end of the window"
    assert len(out) == per_app * len(apps), "reading one page per application discards the rest of each window"
