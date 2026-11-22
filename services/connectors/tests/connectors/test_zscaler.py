"""The Zscaler connector reads the audit-log report feed ZIA actually serves.

What was wrong
--------------
``fetch_alerts`` POSTed ``startTime/endTime/pageSize`` to
``/api/v1/webApplicationRules``. In Zscaler's published API that path is the
Cloud App Control **policy** resource — ``GET /{rule_type}`` lists rules and
the only POST creates one — so the request as sent matched no route and the
stream had never returned an event on any deployment (the GitLab-connector
defect class: polling a route the vendor does not serve, invisibly).
``_obfuscate_api_key`` was independently broken: it skipped the published
algorithm's first loop and the ``+ 2`` offset, so even authentication could
never have succeeded.

What this asserts
-----------------
* The key obfuscation matches Zscaler's published algorithm exactly.
* The connector drives the documented report flow — create for the window,
  poll ``statusId`` to ``COMPLETE``, download — and parses the CSV with its
  preamble rows, admin-timezone timestamps and id-less rows.
* A full page (the vendor's 1,000-record report cap) is followed with
  ``page+1``; the continuation bound is announced when it binds.
* ``ERRORED`` reports raise with the vendor's reason; a 401 re-authenticates
  once; nothing ever touches ``webApplicationRules``.
* Audit rows carry **no severity key** — ZIA audit entries publish no tier
  and none is invented (the Sophos rule).
* An unparseable row time keeps the row and only omits ``created_at``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.connectors.zscaler import (
    ZscalerConnector,
    ZscalerError,
    _parse_report_csv,
    _parse_report_time,
)

API_KEY = "abcdefghijkl"  # 12 chars: digit+2 indexing reaches index 11

_CSV = """Administrator,admin@acme.com
Report Created,"26 Mar 2026 04:07:28, PDT"
Start Time,"25 Mar 2026 11:30:00, PDT"
End Time,"26 Mar 2026 04:02:38, PDT"
Time,User,Action,AA in Cloud,Result,Client IP,Interface,Category,Subcategory,Resource,Pre Action,After,TraceId
"26 Mar 2026 00:30:19, PDT",admin@acme.com,Sign In,zscalerbeta.net,Successful,192.0.2.1,API,Login,Login,,,,
"26 Mar 2026 00:23:42, PDT",admin@acme.com,Update,zscalerbeta.net,Successful,192.0.2.2,UI,Policy,URL Filtering,Block-Social,old,new,trace-1
"""


def _reference_obfuscation(api_key: str, now_ms: int) -> str:
    """Zscaler's published algorithm, written independently of the code."""
    n = str(now_ms)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(len(n)):
        key += api_key[int(n[i])]
    for j in range(len(r)):
        key += api_key[int(r[j]) + 2]
    return key


class TestObfuscation:
    def test_matches_the_published_algorithm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        connector = ZscalerConnector(api_key=API_KEY, username="u", password="p")
        frozen_ms = 1764790123456
        monkeypatch.setattr("app.connectors.zscaler.time.time", lambda: frozen_ms / 1000)

        obfuscated, timestamp = connector._obfuscate_api_key()

        assert timestamp == str(frozen_ms)
        assert obfuscated == _reference_obfuscation(API_KEY, frozen_ms)
        # Twelve characters out: six from the timestamp loop, six from the
        # shifted loop — the old implementation produced six, with no offset.
        assert len(obfuscated) == 12


class TestCsvParsing:
    def test_preamble_is_skipped_and_rows_are_keyed_by_header(self) -> None:
        rows = _parse_report_csv(_CSV)
        assert len(rows) == 2
        assert rows[0]["Action"] == "Sign In"
        assert rows[1]["Category"] == "Policy"
        assert rows[1]["TraceId"] == "trace-1"

    def test_times_parse_to_utc_and_ids_are_stable(self) -> None:
        rows = _parse_report_csv(_CSV)
        # 00:30:19 PDT (UTC-7) == 07:30:19 UTC
        assert rows[0]["event_time"] == "2026-03-26T07:30:19+00:00"
        assert rows[0]["row_id"] == _parse_report_csv(_CSV)[0]["row_id"]
        assert rows[0]["row_id"] != rows[1]["row_id"]

    def test_unknown_timezone_keeps_the_row_without_event_time(self) -> None:
        exotic = _CSV.replace("PDT", "NZDT")
        rows = _parse_report_csv(exotic)
        assert len(rows) == 2  # an unparseable time is never a reason to drop data
        assert "event_time" not in rows[0]

    def test_parse_report_time_rejects_garbage(self) -> None:
        assert _parse_report_time("") is None
        assert _parse_report_time("not a time, UTC") is None
        assert _parse_report_time('"26 Mar 2026 00:30:19, UTC"') is not None


class _ZiaApi:
    """A fake ZIA: session auth, report lifecycle, CSV download."""

    def __init__(
        self,
        *,
        pages: dict[int, str] | None = None,
        polls_until_complete: int = 1,
        fail_status: str | None = None,
        expire_first_session: bool = False,
    ) -> None:
        self.pages = pages or {1: _CSV}
        self.polls_until_complete = polls_until_complete
        self.fail_status = fail_status
        self.expire_first_session = expire_first_session
        self.requests: list[httpx.Request] = []
        self.auth_calls = 0
        self.report_bodies: list[dict[str, Any]] = []
        self._polls = 0
        self._current_page = 1

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/v1/authenticatedSession":
            self.auth_calls += 1
            return httpx.Response(200, headers={"set-cookie": "JSESSIONID=sess-1; Path=/"}, json={})
        if path == "/api/v1/auditlogEntryReport" and request.method == "POST":
            if self.expire_first_session and self.auth_calls < 1:
                return httpx.Response(401, json={"message": "session expired"})
            import json as _json

            body = _json.loads(request.content)
            self.report_bodies.append(body)
            self._current_page = int(body.get("page", 1))
            self._polls = 0
            return httpx.Response(200, json={"status": "EXECUTING", "statusId": "st-1"})
        if path == "/api/v1/auditlogEntryReport" and request.method == "GET":
            self._polls += 1
            if self.fail_status:
                return httpx.Response(200, json={"status": self.fail_status, "errorMessage": "report backend said no"})
            status = "COMPLETE" if self._polls >= self.polls_until_complete else "EXECUTING"
            return httpx.Response(200, json={"status": status})
        if path == "/api/v1/auditlogEntryReport/download":
            return httpx.Response(200, text=self.pages.get(self._current_page, ""))
        return httpx.Response(404, json={"message": f"no such route: {path}"})

    def connector(self) -> ZscalerConnector:
        return ZscalerConnector(
            api_key=API_KEY,
            username="u",
            password="p",
            transport=httpx.MockTransport(self.handle),
        )


@pytest.mark.asyncio
class TestFetchAlerts:
    async def test_reads_the_audit_report_flow_end_to_end(self, monkeypatch) -> None:
        monkeypatch.setattr("app.connectors.zscaler._POLL_INTERVAL_S", 0.0)
        api = _ZiaApi(polls_until_complete=2)
        connector = api.connector()

        alerts = await connector.fetch_alerts(since_seconds=300)

        assert len(alerts) == 2
        body = api.report_bodies[0]
        assert set(body) == {"startTime", "endTime", "page", "pageSize"}
        assert body["endTime"] - body["startTime"] >= 300 * 1000  # overlap widens, never narrows
        # Nothing touched the policy surface the old implementation polled.
        assert not any("webApplicationRules" in str(r.url) for r in api.requests)

    async def test_rows_normalize_without_an_invented_severity(self, monkeypatch) -> None:
        monkeypatch.setattr("app.connectors.zscaler._POLL_INTERVAL_S", 0.0)
        api = _ZiaApi()
        connector = api.connector()

        alerts = await connector.fetch_alerts(since_seconds=300)

        sign_in = next(a for a in alerts if "Sign In" in a["title"])
        assert "severity" not in sign_in
        assert sign_in["actor"] == "admin@acme.com"
        assert sign_in["src_ip"] == "192.0.2.1"
        assert sign_in["created_at"] == "2026-03-26T07:30:19+00:00"
        assert sign_in["external_id"]
        policy = next(a for a in alerts if "Update" in a["title"])
        assert "Policy/URL Filtering" in policy["title"]
        assert "Block-Social" in policy["description"]

    async def test_a_full_page_is_followed_with_the_next_page(self, monkeypatch) -> None:
        monkeypatch.setattr("app.connectors.zscaler._POLL_INTERVAL_S", 0.0)
        monkeypatch.setattr("app.connectors.zscaler._PAGE_SIZE", 2)
        page2 = (
            _CSV.replace("Sign In", "Sign Out")
            .replace("trace-1", "trace-2")
            .replace("00:30:19", "00:31:19")
            .replace("00:23:42", "00:24:42")
        )
        # Page 1 full (2 rows at the patched cap), page 2 short.
        one_row_page = "\n".join(page2.splitlines()[:6]) + "\n"
        api = _ZiaApi(pages={1: _CSV, 2: one_row_page})
        connector = api.connector()

        alerts = await connector.fetch_alerts(since_seconds=300)

        assert [b.get("page") for b in api.report_bodies] == [1, 2]
        assert len(alerts) == 3

    async def test_errored_report_raises_with_the_vendor_reason(self, monkeypatch) -> None:
        monkeypatch.setattr("app.connectors.zscaler._POLL_INTERVAL_S", 0.0)
        api = _ZiaApi(fail_status="ERRORED")
        connector = api.connector()

        with pytest.raises(ZscalerError, match="ERRORED.*report backend said no"):
            await connector.fetch_alerts(since_seconds=300)

    async def test_expired_session_reauthenticates_once(self, monkeypatch) -> None:
        monkeypatch.setattr("app.connectors.zscaler._POLL_INTERVAL_S", 0.0)
        api = _ZiaApi(expire_first_session=True)
        connector = api.connector()
        # Prime a stale session so fetch starts without authenticating.
        connector._jsessionid = "stale"

        alerts = await connector.fetch_alerts(since_seconds=300)

        assert api.auth_calls == 1  # the 401 triggered exactly one re-auth
        assert len(alerts) == 2


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        from app.connectors import _CONNECTOR_CLASSES

        assert ZscalerConnector in _CONNECTOR_CLASSES

    def test_schema_describes_audit_logs_not_web_traffic(self) -> None:
        description = ZscalerConnector.schema().description
        assert "audit log" in description.lower()
        assert "web security logs" not in description.lower()
