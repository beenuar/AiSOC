"""Smoke test for the SplunkSiemConnector.

Intercepts HTTP calls with `httpx.MockTransport` so the test never hits
a real Splunk server. Verifies:

  1. Factory is registered for ConnectorKind.SIEM / vendor=splunk in the
     builtin pack.
  2. Construction picks BearerAuth when `token` is in secrets and
     BasicAuth when `username`+`password` are in secrets.
  3. Missing secrets raise ConnectorAuthError.
  4. Missing base_url raises ConnectorError.
  5. SPL injection prevention: control chars and empty strings are
     rejected by `_escape_spl_value`; backslashes/quotes are escaped.
  6. Invalid `index` and `notable_index` are rejected.
  7. `search_events` posts to the correct oneshot endpoint with the
     expected form fields (exec_mode, output_mode, count, search) and
     normalizes the response into the SIEM event envelope, including
     `_time` -> `ts` conversion and stripping of `_`-prefixed fields
     (except `_time`).
  8. `get_related_alerts` posts a notable-index search and normalizes
     the response into the related-alert shape with id/title/severity.
  9. Splunk-side FATAL messages in the response surface as ConnectorError.
 10. Unsupported entity_type raises ConnectorError unless an
     events_search_template override is supplied.
 11. Custom SPL templates substitute placeholders correctly.
 12. 401 from Splunk raises ConnectorAuthError via the HTTP layer.

Run with:

    cd platform/backend
    python -m tests._check_splunk_connector
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-splunk-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "splunk-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors.sdk.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
)
from app.connectors.sdk.builtin import register_builtin_factories  # noqa: E402
from app.connectors.sdk.http import BasicAuth, BearerAuth  # noqa: E402
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402
from app.connectors.splunk import (  # noqa: E402
    SplunkSiemConnector,
    _escape_spl_value,
    _validate_index,
    make_splunk_siem,
)


# ─── fake Splunk REST endpoint ───────────────────────────────────────────


class FakeSplunk:
    """In-memory Splunk REST stub plugged into httpx via MockTransport.

    Records every request so the test can assert SPL, form fields, and
    headers after the fact. Each test resets `next_response` to drive
    one specific scenario.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.next_response: dict[str, Any] = {"results": []}
        # If set, every request returns this status + body verbatim
        # (used to simulate 401 from auth failures).
        self.force_status: int | None = None
        self.force_body: bytes = b""

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)

        if self.force_status is not None:
            return httpx.Response(
                self.force_status,
                content=self.force_body,
                headers={"Content-Type": "application/json"},
            )

        # Splunk server/info for health_check
        if request.url.path == "/services/server/info":
            return httpx.Response(
                200,
                json={
                    "entry": [
                        {
                            "content": {
                                "serverName": "splunk-fake-01",
                                "version": "9.2.0",
                            }
                        }
                    ]
                },
            )

        # Search jobs (oneshot) — accept POST form-encoded only.
        if request.url.path.endswith("/search/jobs"):
            assert request.method == "POST", (
                f"expected POST for search/jobs, got {request.method}"
            )
            return httpx.Response(
                200,
                json=self.next_response,
                headers={"Content-Type": "application/json"},
            )

        return httpx.Response(404, content=b"")

    def last_form(self) -> dict[str, list[str]]:
        """Form fields of the most recent request as a parsed dict."""
        assert self.requests, "no requests captured"
        return parse_qs(self.requests[-1].content.decode("utf-8"))


def _make_connector(
    *,
    fake: FakeSplunk,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> SplunkSiemConnector:
    """Build a SplunkSiemConnector wired to the FakeSplunk transport."""
    cfg = ConnectorConfig(
        tenant_id="t-splunk-test",
        kind=ConnectorKind.SIEM,
        vendor="splunk",
        params=params
        if params is not None
        else {
            "base_url": "https://splunk.example.test:8089",
            "index": "main",
            "max_results": 50,
        },
        secrets=secrets if secrets is not None else {"token": "sek-test-token"},
    )
    conn = SplunkSiemConnector(cfg)
    # Hot-swap the underlying httpx client with one bound to MockTransport.
    transport = httpx.MockTransport(fake.handler)
    # Close the real client (created in __init__) before replacing it.
    # We do this synchronously by reaching into the inner client; aclose()
    # is async and not needed for a never-used socketless client.
    conn._http._client = httpx.AsyncClient(
        base_url="https://splunk.example.test:8089",
        transport=transport,
        headers={"Accept": "application/json"},
    )
    return conn


# ─── checks ──────────────────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.SIEM, "splunk"))
    assert factory is make_splunk_siem, (
        f"expected make_splunk_siem registered for SIEM/splunk, got {factory}"
    )
    print("OK  factory registered: ConnectorKind.SIEM, vendor='splunk'")


def check_construction_auth_modes() -> None:
    fake = FakeSplunk()
    # Bearer
    conn = _make_connector(fake=fake, secrets={"token": "abc"})
    assert isinstance(conn._http.auth, BearerAuth), "expected BearerAuth"
    assert conn._http.auth.token == "abc"
    print("OK  token in secrets -> BearerAuth")

    # Basic
    conn = _make_connector(
        fake=fake,
        secrets={"username": "admin", "password": "pw"},
    )
    assert isinstance(conn._http.auth, BasicAuth), "expected BasicAuth"
    assert conn._http.auth.username == "admin"
    print("OK  username+password in secrets -> BasicAuth")


def check_missing_secrets_rejected() -> None:
    fake = FakeSplunk()
    try:
        _make_connector(fake=fake, secrets={})
    except ConnectorAuthError as e:
        assert "token" in str(e) and "username" in str(e), (
            f"error should mention both auth modes, got: {e}"
        )
        print("OK  empty secrets -> ConnectorAuthError")
    else:
        raise AssertionError("expected ConnectorAuthError on empty secrets")


def check_missing_base_url_rejected() -> None:
    cfg = ConnectorConfig(
        tenant_id="t",
        kind=ConnectorKind.SIEM,
        vendor="splunk",
        params={},
        secrets={"token": "x"},
    )
    try:
        SplunkSiemConnector(cfg)
    except ConnectorError as e:
        assert "base_url" in str(e)
        print("OK  missing base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing base_url")


def check_spl_escaping() -> None:
    # Backslashes and quotes are escaped (caller wraps in "..." outside).
    assert _escape_spl_value(r'a"b\c') == 'a\\"b\\\\c'
    assert _escape_spl_value("plain") == "plain"
    # Empty string rejected
    for bad in ("", "host\nbad", "host\x00bad", "host\tbad"):
        try:
            _escape_spl_value(bad)
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for {bad!r}")
    print("OK  SPL escaping: quotes/backslashes escaped, control chars rejected")


def check_index_validation() -> None:
    assert _validate_index("main") == "main"
    assert _validate_index("main,prod_logs") == "main,prod_logs"
    assert _validate_index("*") == "*"
    for bad in ("main;drop", "main\"", "main\nfoo", ""):
        try:
            _validate_index(bad)
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for {bad!r}")
    print("OK  index validation: legal charset enforced")


async def check_search_events_happy_path() -> None:
    fake = FakeSplunk()
    fake.next_response = {
        "results": [
            {
                "_time": "2026-06-17T10:00:00.000+00:00",
                "_raw": "should be stripped",
                "_cd": "0:1234",
                "host": "host-7",
                "sourcetype": "windows_security",
                "EventCode": "4625",
                "user": "alice",
            },
            {
                "_time": 1_750_000_000,  # epoch fallback
                "host": "host-7",
                "sourcetype": "auth",
                "signature": "Failed login",
            },
        ],
        "messages": [{"type": "INFO", "text": "search completed"}],
    }
    conn = _make_connector(fake=fake)
    try:
        out = await conn.search_events(
            entity="host-7", entity_type="host", minutes=120
        )

        # Envelope shape
        assert out["entity"] == "host-7"
        assert out["entity_type"] == "host"
        assert out["window_minutes"] == 120
        assert len(out["events"]) == 2

        # First event: type comes from EventCode (priority), _raw/_cd stripped,
        # _time -> ts ISO-8601.
        ev0 = out["events"][0]
        assert ev0["type"] == "4625", f"expected EventCode as type, got {ev0['type']}"
        assert ev0["ts"].startswith("2026-06-17T10:00:00"), ev0["ts"]
        assert "_raw" not in ev0 and "_cd" not in ev0
        assert ev0["host"] == "host-7"
        assert ev0["user"] == "alice"

        # Second event: signature wins as type, epoch -> ISO.
        ev1 = out["events"][1]
        assert ev1["type"] == "Failed login"
        assert "T" in ev1["ts"], f"epoch ts should be ISO, got {ev1['ts']}"

        # Request shape
        form = fake.last_form()
        assert form["exec_mode"] == ["oneshot"], form
        assert form["output_mode"] == ["json"], form
        assert form["count"] == ["50"], form  # max_results from config
        spl = form["search"][0]
        assert spl.startswith("search index=main "), spl
        assert '"host-7"' in spl, spl
        assert "earliest=-120m" in spl, spl
        assert "| head 50" in spl, spl

        # Path uses default app/owner namespaces.
        path = fake.requests[-1].url.path
        assert path == "/servicesNS/nobody/search/search/jobs", path

        print("OK  search_events: form fields + SPL + normalization")
    finally:
        await conn.aclose()


async def check_search_events_user_and_ip() -> None:
    fake = FakeSplunk()
    fake.next_response = {"results": []}
    conn = _make_connector(fake=fake)
    try:
        await conn.search_events(entity="alice@corp", entity_type="user", minutes=30)
        spl = fake.last_form()["search"][0]
        assert 'user="alice@corp"' in spl, spl
        assert "src_user=" in spl, spl  # default user template
        assert "earliest=-30m" in spl, spl

        await conn.search_events(entity="10.0.0.42", entity_type="ip", minutes=60)
        spl = fake.last_form()["search"][0]
        assert 'src_ip="10.0.0.42"' in spl, spl
        assert 'dest_ip="10.0.0.42"' in spl, spl
        print("OK  search_events: default templates for user/ip")
    finally:
        await conn.aclose()


async def check_unsupported_entity_type_rejected() -> None:
    fake = FakeSplunk()
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.search_events(
                entity="x", entity_type="weirdo", minutes=10
            )
        except ConnectorError as e:
            assert "entity_type" in str(e) and "weirdo" in str(e)
            print("OK  unsupported entity_type -> ConnectorError")
        else:
            raise AssertionError("expected ConnectorError")
    finally:
        await conn.aclose()


async def check_custom_template_override() -> None:
    fake = FakeSplunk()
    fake.next_response = {"results": []}
    conn = _make_connector(
        fake=fake,
        params={
            "base_url": "https://splunk.example.test:8089",
            "index": "main",
            "max_results": 25,
            # Custom template that doesn't even reference entity_type —
            # also exercises the path where entity_type isn't in
            # _DEFAULT_EVENTS_SPL but a template is provided. The
            # double-quotes around {entity} are part of the template;
            # _escape_spl_value returns *content*, not quotes.
            "events_search_template": (
                'search index={index} foo="{entity}" '
                "earliest=-{minutes}m | head {max_results}"
            ),
        },
    )
    try:
        await conn.search_events(
            entity='weird"val', entity_type="customthing", minutes=15
        )
        spl = fake.last_form()["search"][0]
        # The embedded `"` in the entity must be backslash-escaped.
        assert (
            spl == 'search index=main foo="weird\\"val" earliest=-15m | head 25'
        ), spl
        print("OK  custom events_search_template substitution + quote escaping")
    finally:
        await conn.aclose()


async def check_related_alerts_happy_path() -> None:
    fake = FakeSplunk()
    fake.next_response = {
        "results": [
            {
                "event_id": "ES-001",
                "rule_name": "Brute force suspected",
                "severity": "HIGH",
                "_time": "2026-06-17T09:00:00.000+00:00",
            },
            {
                # No event_id -> falls back through priority list.
                "savedsearch_name": "Suspicious activity",
                "signature": "anomaly",
                "urgency": "medium",
            },
        ]
    }
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_related_alerts(entity="host-7", hours=8)
        assert out["entity"] == "host-7"
        assert out["related_count"] == 2

        a0 = out["related"][0]
        assert a0["id"] == "ES-001"
        assert a0["title"] == "Brute force suspected"
        assert a0["severity"] == "high"  # lowercased

        a1 = out["related"][1]
        assert a1["id"] == "Suspicious activity", a1
        assert a1["title"] == "anomaly", a1
        assert a1["severity"] == "medium", a1

        form = fake.last_form()
        spl = form["search"][0]
        assert "index=notable " in spl, spl
        assert "earliest=-8h" in spl, spl
        print("OK  get_related_alerts: form fields + SPL + normalization")
    finally:
        await conn.aclose()


async def check_splunk_error_surfaced() -> None:
    fake = FakeSplunk()
    fake.next_response = {
        "results": [],
        "messages": [{"type": "FATAL", "text": "bad SPL syntax"}],
    }
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.search_events(
                entity="host-7", entity_type="host", minutes=10
            )
        except ConnectorError as e:
            assert "FATAL" in str(e) and "bad SPL syntax" in str(e), str(e)
            print("OK  Splunk FATAL message -> ConnectorError")
        else:
            raise AssertionError("expected ConnectorError")
    finally:
        await conn.aclose()


async def check_health_check_happy_path() -> None:
    fake = FakeSplunk()
    conn = _make_connector(fake=fake)
    try:
        info = await conn.health_check()
        assert info["ok"] is True
        assert info["vendor"] == "splunk"
        assert info["kind"] == "siem"
        assert info["server_name"] == "splunk-fake-01"
        assert info["version"] == "9.2.0"
        # The request must have hit /services/server/info with output_mode=json
        last = fake.requests[-1]
        assert last.url.path == "/services/server/info"
        assert b"output_mode=json" in last.url.query
        print("OK  health_check: /services/server/info + parsed entry")
    finally:
        await conn.aclose()


async def check_auth_error_from_http_layer() -> None:
    fake = FakeSplunk()
    fake.force_status = 401
    fake.force_body = b'{"messages":[{"type":"WARN","text":"bad creds"}]}'
    conn = _make_connector(fake=fake)
    # Reduce retries so the test runs fast — 401 isn't retried anyway.
    conn._http.max_retries = 0
    try:
        try:
            await conn.search_events(
                entity="host-7", entity_type="host", minutes=10
            )
        except ConnectorAuthError as e:
            assert e.status == 401, f"expected status=401, got {e.status}"
            print("OK  401 from Splunk -> ConnectorAuthError")
        else:
            raise AssertionError("expected ConnectorAuthError on 401")
    finally:
        await conn.aclose()


# ─── runner ──────────────────────────────────────────────────────────────


async def _main() -> None:
    # Sync checks first (cheap, fail-fast).
    check_factory_registered()
    check_construction_auth_modes()
    check_missing_secrets_rejected()
    check_missing_base_url_rejected()
    check_spl_escaping()
    check_index_validation()

    # Async checks.
    await check_search_events_happy_path()
    await check_search_events_user_and_ip()
    await check_unsupported_entity_type_rejected()
    await check_custom_template_override()
    await check_related_alerts_happy_path()
    await check_splunk_error_surfaced()
    await check_health_check_happy_path()
    await check_auth_error_from_http_layer()

    print("\nALL SPLUNK CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
