"""Smoke test for the CrowdStrikeEdrConnector.

Intercepts HTTP calls with ``httpx.MockTransport`` so the test never
hits real Falcon endpoints. Verifies:

  1. Factory is registered for ConnectorKind.EDR / vendor=crowdstrike.
  2. Construction requires ``base_url`` and rejects non-https URLs.
  3. Missing ``client_id`` / ``client_secret`` raises ConnectorAuthError.
  4. FQL escaping: control chars and empty strings rejected, single
     quotes and backslashes escaped for safe literal interpolation.
  5. ``_safe_int`` parses ints/numeric strings and returns None for
     empties / unparseables (Falcon emits PIDs both ways).
  6. ``_behaviors_to_tree`` reconstructs parent/child edges, dedupes
     repeat process_ids, and treats unknown parents as roots.
  7. ``_resolve_device_id`` trusts 32-hex AIDs, falls back to FQL
     hostname lookup, and raises on unknown hosts.
  8. ``health_check`` calls ``/devices/queries/devices/v1?limit=1``
     with a bearer token and surfaces the device total.
  9. ``get_process_tree`` returns an empty tree for hosts with no
     detections in the window.
 10. ``get_process_tree`` (populated) hits the detections query +
     summaries endpoints and reconstructs the tree.
 11. ``get_process_tree`` adds an FQL substring predicate when
     ``process_name`` is supplied.
 12. ``isolate_host`` / ``release_host`` post the right
     ``action_name`` to ``/devices-actions/v2`` and return the
     mock-compatible envelope with a synthetic ticket.
 13. ``isolate_host`` requires a non-empty reason.
 14. ``quarantine_file`` rejects bad SHA-256s, posts to
     ``/iocs/entities/indicators/v1`` with action=prevent, and
     returns the standard envelope.
 15. ``kill_process`` walks the full RTR three-phase flow: init
     session, issue ``kill {pid}``, poll until ``complete``, and
     always closes the session.
 16. ``kill_process`` polling tolerates ``complete=False`` and
     surfaces non-empty ``stderr`` as ConnectorError.
 17. ``kill_process`` surfaces a Falcon error envelope as
     ConnectorError without leaking RTR sessions.
 18. 401 from the OAuth token endpoint surfaces as
     ConnectorAuthError.

Run with:

    cd platform/backend
    python -m tests._check_crowdstrike_connector
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-crowdstrike-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "crowdstrike-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors.crowdstrike import (  # noqa: E402
    CrowdStrikeEdrConnector,
    _behaviors_to_tree,
    _escape_fql_value,
    _make_ticket,
    _safe_int,
    make_crowdstrike_edr,
)
from app.connectors.sdk.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
    ConnectorTimeoutError,
)
from app.connectors.sdk.builtin import register_builtin_factories  # noqa: E402
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402


# Canonical (random but well-shaped) values used throughout the test.
TEST_BASE_URL = "https://api.crowdstrike.com"
TEST_AID = "abcdef0123456789abcdef0123456789"  # 32 lowercase hex
TEST_HOST = "host-7.corp.local"


# ─── fake Falcon surface ────────────────────────────────────────────────


class FakeFalcon:
    """In-memory CrowdStrike Falcon stub for ``httpx.MockTransport``.

    Routes by URL path so a single transport can serve OAuth, Devices,
    Detections, IOC, and RTR endpoints. Recorded requests are exposed
    on per-endpoint lists so tests can assert headers, query params,
    and bodies.

    The default responses give a "happy path" suitable for tests that
    only care about request shape; mutate the ``next_*`` fields to
    drive specific scenarios.
    """

    def __init__(self) -> None:
        # Recorded requests, per logical endpoint.
        self.token_requests: list[httpx.Request] = []
        self.device_query_requests: list[httpx.Request] = []
        self.device_action_requests: list[httpx.Request] = []
        self.detect_query_requests: list[httpx.Request] = []
        self.detect_summary_requests: list[httpx.Request] = []
        self.ioc_requests: list[httpx.Request] = []
        self.rtr_session_post_requests: list[httpx.Request] = []
        self.rtr_session_delete_requests: list[httpx.Request] = []
        self.rtr_command_post_requests: list[httpx.Request] = []
        self.rtr_command_poll_requests: list[httpx.Request] = []

        # OAuth control.
        self.oauth_status: int = 200
        self.oauth_body: dict[str, Any] = {
            "access_token": "fake-cs-token",
            "token_type": "bearer",
            "expires_in": 1800,
        }

        # Devices query default: returns TEST_AID for any hostname.
        # Set to [] to simulate "host not found".
        self.next_device_query_resources: list[str] = [TEST_AID]
        self.next_device_query_meta: dict[str, Any] = {
            "pagination": {"total": 137}
        }
        self.next_device_query_errors: list[dict[str, Any]] = []

        # Devices-actions default response.
        self.next_action_trace_id: str = "trace-abcd-1234-5678-deadbeef"
        self.next_action_errors: list[dict[str, Any]] = []

        # Detections.
        self.next_detect_query_resources: list[str] = []
        self.next_detect_summary_resources: list[dict[str, Any]] = []

        # IOCs.
        self.next_ioc_resources: list[dict[str, Any]] = [
            {"id": "ioc-1234-id", "value": ""}
        ]
        self.next_ioc_errors: list[dict[str, Any]] = []

        # RTR.
        self.next_rtr_session_id: str | None = "rtr-session-id-xyz"
        self.next_rtr_session_errors: list[dict[str, Any]] = []
        self.next_rtr_cloud_request_id: str | None = "rtr-cloud-req-1"
        self.next_rtr_command_errors: list[dict[str, Any]] = []

        # RTR polling. Each entry is one poll response's resource dict.
        # If shorter than the poll loop, the last entry is repeated.
        self.rtr_poll_sequence: list[dict[str, Any]] = [
            {"complete": True, "stderr": "", "stdout": "killed pid 4242"}
        ]

    # ── handler ─────────────────────────────────────────────────────────

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path
        method = request.method.upper()

        # OAuth token endpoint (absolute URL but same host as MockTransport).
        if path.endswith("/oauth2/token") and method == "POST":
            self.token_requests.append(request)
            if self.oauth_status != 200:
                return _json_response(
                    self.oauth_status,
                    {"error": "invalid_client", "error_description": "bad creds"},
                )
            return _json_response(200, self.oauth_body)

        # Devices: query (hostname -> AID lookup AND health probe).
        if path == "/devices/queries/devices/v1" and method == "GET":
            self.device_query_requests.append(request)
            return _json_response(
                200,
                _falcon_envelope(
                    resources=list(self.next_device_query_resources),
                    meta=dict(self.next_device_query_meta),
                    errors=list(self.next_device_query_errors),
                ),
            )

        # Devices: actions (contain / lift_containment).
        if path == "/devices/entities/devices-actions/v2" and method == "POST":
            self.device_action_requests.append(request)
            return _json_response(
                200,
                _falcon_envelope(
                    resources=[{"id": TEST_AID, "path": "contain"}],
                    meta={"trace_id": self.next_action_trace_id},
                    errors=list(self.next_action_errors),
                ),
            )

        # Detections: query.
        if path == "/detects/queries/detects/v1" and method == "GET":
            self.detect_query_requests.append(request)
            return _json_response(
                200,
                _falcon_envelope(
                    resources=list(self.next_detect_query_resources),
                    meta={},
                ),
            )

        # Detections: summaries (POST /detects/entities/summaries/GET/v1).
        if (
            path == "/detects/entities/summaries/GET/v1"
            and method == "POST"
        ):
            self.detect_summary_requests.append(request)
            return _json_response(
                200,
                _falcon_envelope(
                    resources=list(self.next_detect_summary_resources),
                    meta={},
                ),
            )

        # IOC create.
        if path == "/iocs/entities/indicators/v1" and method == "POST":
            self.ioc_requests.append(request)
            return _json_response(
                200,
                _falcon_envelope(
                    resources=list(self.next_ioc_resources),
                    meta={},
                    errors=list(self.next_ioc_errors),
                ),
            )

        # RTR sessions.
        if path == "/real-time-response/entities/sessions/v1":
            if method == "POST":
                self.rtr_session_post_requests.append(request)
                resources: list[dict[str, Any]] = []
                if self.next_rtr_session_id is not None:
                    resources = [{"session_id": self.next_rtr_session_id}]
                return _json_response(
                    200,
                    _falcon_envelope(
                        resources=resources,
                        meta={},
                        errors=list(self.next_rtr_session_errors),
                    ),
                )
            if method == "DELETE":
                self.rtr_session_delete_requests.append(request)
                return _json_response(
                    204,
                    {},
                )

        # RTR admin command (issue + poll on same path).
        if path == "/real-time-response/entities/admin-command/v1":
            if method == "POST":
                self.rtr_command_post_requests.append(request)
                resources: list[dict[str, Any]] = []
                if self.next_rtr_cloud_request_id is not None:
                    resources = [
                        {"cloud_request_id": self.next_rtr_cloud_request_id}
                    ]
                return _json_response(
                    200,
                    _falcon_envelope(
                        resources=resources,
                        meta={},
                        errors=list(self.next_rtr_command_errors),
                    ),
                )
            if method == "GET":
                self.rtr_command_poll_requests.append(request)
                idx = min(
                    len(self.rtr_command_poll_requests) - 1,
                    len(self.rtr_poll_sequence) - 1,
                )
                resource = (
                    self.rtr_poll_sequence[idx] if self.rtr_poll_sequence else {}
                )
                return _json_response(
                    200,
                    _falcon_envelope(resources=[resource], meta={}),
                )

        return httpx.Response(
            404,
            content=b"",
            headers={"X-Test-Unhandled": f"{method} {path}"},
        )

    # ── convenience accessors ──────────────────────────────────────────

    def last_token_form(self) -> dict[str, list[str]]:
        assert self.token_requests, "no /oauth2/token requests captured"
        return parse_qs(self.token_requests[-1].content.decode("utf-8"))

    def last_device_query_filter(self) -> str | None:
        assert self.device_query_requests, "no /devices/queries requests"
        return self.device_query_requests[-1].url.params.get("filter")

    def last_device_action(self) -> tuple[str, dict[str, Any]]:
        assert self.device_action_requests, "no devices-actions/v2 requests"
        req = self.device_action_requests[-1]
        body = json.loads(req.content.decode("utf-8")) if req.content else {}
        return req.url.params.get("action_name", ""), body

    def last_detect_query_filter(self) -> str | None:
        assert self.detect_query_requests, "no detects/queries requests"
        return self.detect_query_requests[-1].url.params.get("filter")

    def last_ioc_body(self) -> dict[str, Any]:
        assert self.ioc_requests, "no IOC requests"
        return json.loads(self.ioc_requests[-1].content.decode("utf-8"))

    def last_rtr_command_body(self) -> dict[str, Any]:
        assert self.rtr_command_post_requests, "no RTR command requests"
        return json.loads(
            self.rtr_command_post_requests[-1].content.decode("utf-8")
        )


# ─── small helpers ──────────────────────────────────────────────────────


def _falcon_envelope(
    *,
    resources: list[Any],
    meta: dict[str, Any] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "meta": meta or {},
        "resources": list(resources),
        "errors": list(errors or []),
    }


def _json_response(status: int, body: Any) -> httpx.Response:
    if status == 204:
        return httpx.Response(204, content=b"")
    return httpx.Response(
        status,
        json=body,
        headers={"Content-Type": "application/json"},
    )


def _make_connector(
    *,
    fake: FakeFalcon,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> CrowdStrikeEdrConnector:
    """Build a CrowdStrikeEdrConnector wired to ``fake``'s transport.

    A single MockTransport serves both the absolute OAuth URL and the
    relative Falcon API paths (same host).
    """
    cfg = ConnectorConfig(
        tenant_id="t-crowdstrike-test",
        kind=ConnectorKind.EDR,
        vendor="crowdstrike",
        params=params
        if params is not None
        else {
            "base_url": TEST_BASE_URL,
            "detection_window_hours": 24,
            "rtr_poll_timeout_s": 1.0,
            "rtr_poll_interval_s": 0.0,
        },
        secrets=secrets
        if secrets is not None
        else {"client_id": "fake-id", "client_secret": "fake-secret"},
    )
    conn = CrowdStrikeEdrConnector(cfg)
    transport = httpx.MockTransport(fake.handler)
    conn._http._client = httpx.AsyncClient(
        base_url=TEST_BASE_URL,
        transport=transport,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    # Make failure paths fail fast — don't burn the test with retries.
    conn._http.max_retries = 0
    return conn


# ─── synchronous checks ──────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.EDR, "crowdstrike"))
    assert factory is make_crowdstrike_edr, (
        "expected make_crowdstrike_edr registered for EDR/crowdstrike, "
        f"got {factory}"
    )
    print("OK  factory registered: ConnectorKind.EDR, vendor='crowdstrike'")


def check_required_params_rejected() -> None:
    base_secrets = {"client_id": "x", "client_secret": "y"}

    # Missing base_url
    try:
        CrowdStrikeEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="crowdstrike",
                params={},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "base_url" in str(e), e
        print("OK  missing base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing base_url")

    # Non-https base_url
    try:
        CrowdStrikeEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="crowdstrike",
                params={"base_url": "http://api.crowdstrike.com"},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "https" in str(e), e
        print("OK  non-https base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on non-https base_url")

    # Out-of-range detection_window_hours
    try:
        CrowdStrikeEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="crowdstrike",
                params={
                    "base_url": TEST_BASE_URL,
                    "detection_window_hours": 9999,
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "detection_window_hours" in str(e), e
        print("OK  detection_window_hours out of range -> ConnectorError")
    else:
        raise AssertionError(
            "expected ConnectorError on huge detection_window_hours"
        )


def check_missing_secrets_rejected() -> None:
    # client_id missing
    try:
        CrowdStrikeEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="crowdstrike",
                params={"base_url": TEST_BASE_URL},
                secrets={"client_secret": "y"},
            )
        )
    except ConnectorAuthError as e:
        assert "client_id" in str(e), e
        print("OK  missing client_id -> ConnectorAuthError")
    else:
        raise AssertionError("expected ConnectorAuthError on missing client_id")

    # client_secret missing
    try:
        CrowdStrikeEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="crowdstrike",
                params={"base_url": TEST_BASE_URL},
                secrets={"client_id": "x"},
            )
        )
    except ConnectorAuthError as e:
        assert "client_secret" in str(e), e
        print("OK  missing client_secret -> ConnectorAuthError")
    else:
        raise AssertionError(
            "expected ConnectorAuthError on missing client_secret"
        )


def check_fql_escaping() -> None:
    # Backslashes and single-quotes are escaped for safe interpolation.
    assert _escape_fql_value("plain", field="host") == "plain"
    assert _escape_fql_value("a'b", field="host") == "a\\'b"
    assert _escape_fql_value(r"a\b", field="host") == r"a\\b"
    # Combined: backslash escaped first, then quote.
    assert _escape_fql_value(r"x\'y", field="host") == r"x\\\'y"

    for bad in ("", "host\nbad", "host\x00bad", "host\tbad", "\x7f"):
        try:
            _escape_fql_value(bad, field="host")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for {bad!r}")

    # Non-string types rejected.
    try:
        _escape_fql_value(123, field="host")  # type: ignore[arg-type]
    except ConnectorError:
        pass
    else:
        raise AssertionError("expected rejection for non-string FQL value")
    print(
        "OK  FQL escaping: quotes + backslashes escaped, control chars + "
        "non-strings rejected"
    )


def check_safe_int() -> None:
    assert _safe_int(None) is None
    assert _safe_int("") is None
    assert _safe_int("not-a-number") is None
    assert _safe_int(42) == 42
    assert _safe_int("42") == 42
    assert _safe_int("0") == 0
    assert _safe_int(-1) == -1
    print("OK  _safe_int: int/str round-trip, None/empty/garbage -> None")


def check_behaviors_to_tree() -> None:
    # Empty input.
    assert _behaviors_to_tree([]) == []
    assert _behaviors_to_tree([None, "garbage", {"behaviors": "not a list"}]) == []

    # Simple parent/child link within the captured set.
    summaries: list[dict[str, Any]] = [
        {
            "detection_id": "det-1",
            "behaviors": [
                {
                    "process_id": "100",
                    "filename": "explorer.exe",
                    "cmdline": "explorer.exe",
                    "user_name": "alice",
                    "parent_details": {"parent_process_id": "4"},
                },
                {
                    "process_id": "200",
                    "filename": "powershell.exe",
                    "cmdline": "powershell -enc ...",
                    "user_name": "alice",
                    "parent_details": {"parent_process_id": "100"},
                },
                # Duplicate process_id; should be dropped.
                {
                    "process_id": "200",
                    "filename": "powershell.exe",
                    "cmdline": "powershell different cmdline",
                    "parent_details": {"parent_process_id": "100"},
                },
                # Orphan: parent not in nodes -> becomes a root.
                {
                    "process_id": "300",
                    "filename": "rundll32.exe",
                    "parent_details": {"parent_process_id": "99999"},
                },
            ],
        }
    ]
    forest = _behaviors_to_tree(summaries)
    # Two roots: explorer (parent 4 not in nodes) + rundll32 (orphan).
    assert len(forest) == 2, forest
    by_pid = {n["pid"]: n for n in forest}
    assert 100 in by_pid and 300 in by_pid, by_pid
    explorer = by_pid[100]
    assert explorer["name"] == "explorer.exe"
    assert explorer["suspicious"] is True
    # One child (powershell), the dupe was dropped.
    assert len(explorer["children"]) == 1, explorer["children"]
    ps = explorer["children"][0]
    assert ps["pid"] == 200
    assert ps["name"] == "powershell.exe"
    assert ps["cmdline"].startswith("powershell -enc"), ps["cmdline"]
    print(
        "OK  _behaviors_to_tree: parent/child linkage, dedup, orphan-as-root"
    )


def check_make_ticket() -> None:
    # With trace_id, hyphens stripped, first 8 chars used.
    assert _make_ticket("ISO", "abc-defg-1234-5678", TEST_AID) == "ISO-abcdefg1"
    # Without trace_id, falls back to AID prefix.
    assert _make_ticket("REL", "", TEST_AID) == f"REL-{TEST_AID[:8]}"
    # Without either, uses 'unknown' sentinel.
    assert _make_ticket("REL", "", "") == "REL-unknown"
    print("OK  _make_ticket: trace_id / AID fallback / unknown sentinel")


# ─── async checks ────────────────────────────────────────────────────────


async def check_health_check_happy_path() -> None:
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        info = await conn.health_check()
        assert info["ok"] is True
        assert info["vendor"] == "crowdstrike"
        assert info["kind"] == "edr"
        assert info["devices_total"] == 137, info

        # Verify request shape.
        assert len(fake.device_query_requests) == 1
        req = fake.device_query_requests[-1]
        assert req.url.path == "/devices/queries/devices/v1", req.url
        # Bearer token must be present.
        assert req.headers.get("Authorization") == "Bearer fake-cs-token", (
            req.headers.get("Authorization")
        )
        # OAuth form must be client_credentials.
        assert len(fake.token_requests) == 1, fake.token_requests
        form = fake.last_token_form()
        assert form["grant_type"] == ["client_credentials"], form
        assert form["client_id"] == ["fake-id"], form
        # Falcon's token endpoint must NOT receive a scope param.
        assert "scope" not in form, form
        print("OK  health_check: /devices/queries/devices/v1 + bearer + envelope")
    finally:
        await conn.aclose()


async def check_resolve_device_id_aid_shortcut() -> None:
    """An AID-shaped host string skips the FQL lookup entirely."""
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        # Trigger via isolate_host which calls _resolve_device_id internally.
        await conn.isolate_host(host=TEST_AID.upper(), reason="testing")
        # No device-query request was issued — AID was trusted directly.
        assert fake.device_query_requests == [], (
            "AID should bypass /devices/queries lookup"
        )
        # One devices-action call landed.
        action_name, body = fake.last_device_action()
        assert action_name == "contain", action_name
        assert body["ids"] == [TEST_AID], body
        print("OK  _resolve_device_id: AID shape bypasses hostname lookup")
    finally:
        await conn.aclose()


async def check_resolve_device_id_hostname_lookup() -> None:
    fake = FakeFalcon()
    fake.next_device_query_resources = [TEST_AID]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.isolate_host(host=TEST_HOST, reason="bad behavior")
        assert out["host"] == TEST_HOST
        assert out["isolated"] is True
        assert out["reason"] == "bad behavior"
        assert out["ticket"].startswith("ISO-"), out["ticket"]

        # One hostname lookup + one device action.
        assert len(fake.device_query_requests) == 1
        fql = fake.last_device_query_filter()
        assert fql == f"hostname:'{TEST_HOST}'", fql
        action_name, body = fake.last_device_action()
        assert action_name == "contain", action_name
        assert body == {"ids": [TEST_AID]}, body
        print(
            "OK  _resolve_device_id: hostname -> AID via FQL lookup, then "
            "contain action"
        )
    finally:
        await conn.aclose()


async def check_resolve_device_id_not_found() -> None:
    fake = FakeFalcon()
    fake.next_device_query_resources = []  # no match
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.isolate_host(host="ghost-host", reason="phantom")
        except ConnectorError as e:
            assert "not found" in str(e).lower()
            assert "ghost-host" in str(e)
            print("OK  unknown hostname -> ConnectorError (not found)")
        else:
            raise AssertionError("expected ConnectorError for unknown host")
        # And we must not have invoked any device action.
        assert fake.device_action_requests == []
    finally:
        await conn.aclose()


async def check_isolate_requires_reason() -> None:
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        for bad in ("", "   ", None):
            try:
                await conn.isolate_host(host=TEST_AID, reason=bad)  # type: ignore[arg-type]
            except ConnectorError:
                pass
            else:
                raise AssertionError(
                    f"expected ConnectorError for reason={bad!r}"
                )
        assert fake.device_action_requests == [], (
            "no action should have been dispatched"
        )
        print("OK  isolate_host requires non-empty reason")
    finally:
        await conn.aclose()


async def check_release_host_happy_path() -> None:
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        out = await conn.release_host(host=TEST_AID)
        assert out["host"] == TEST_AID
        assert out["isolated"] is False
        assert out["ticket"].startswith("REL-"), out["ticket"]

        action_name, body = fake.last_device_action()
        assert action_name == "lift_containment", action_name
        assert body == {"ids": [TEST_AID]}, body
        print("OK  release_host -> action_name=lift_containment + envelope")
    finally:
        await conn.aclose()


async def check_get_process_tree_empty() -> None:
    fake = FakeFalcon()
    fake.next_detect_query_resources = []  # no detections in window
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_process_tree(host=TEST_AID)
        assert out == {"host": TEST_AID, "tree": []}, out
        # Detection summaries must not be fetched when query is empty.
        assert fake.detect_summary_requests == []
        # Verify the FQL we sent had device.device_id + behaviors.timestamp.
        fql = fake.last_detect_query_filter() or ""
        assert f"device.device_id:'{TEST_AID}'" in fql, fql
        assert "behaviors.timestamp:>=" in fql, fql
        # No process_name filter requested -> no behaviors.filename clause.
        assert "behaviors.filename" not in fql, fql
        print(
            "OK  get_process_tree (empty): summaries skipped, FQL has "
            "device + timestamp"
        )
    finally:
        await conn.aclose()


async def check_get_process_tree_populated() -> None:
    fake = FakeFalcon()
    fake.next_detect_query_resources = ["det-1", "det-2"]
    fake.next_detect_summary_resources = [
        {
            "detection_id": "det-1",
            "behaviors": [
                {
                    "process_id": "100",
                    "filename": "explorer.exe",
                    "cmdline": "explorer.exe",
                    "user_name": "alice",
                    "parent_details": {"parent_process_id": "4"},
                },
                {
                    "process_id": "200",
                    "filename": "powershell.exe",
                    "cmdline": "powershell -enc AAAA",
                    "user_name": "alice",
                    "parent_details": {"parent_process_id": "100"},
                },
            ],
        }
    ]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_process_tree(
            host=TEST_AID, process_name="powershell.exe"
        )
        assert out["host"] == TEST_AID
        forest = out["tree"]
        assert len(forest) == 1, forest
        root = forest[0]
        assert root["pid"] == 100
        assert root["name"] == "explorer.exe"
        assert len(root["children"]) == 1
        assert root["children"][0]["pid"] == 200

        # FQL must include filename substring filter.
        fql = fake.last_detect_query_filter() or ""
        assert "behaviors.filename:*'powershell.exe'*" in fql, fql

        # Summaries POST body must echo the IDs from the query response.
        body = json.loads(
            fake.detect_summary_requests[-1].content.decode("utf-8")
        )
        assert body == {"ids": ["det-1", "det-2"]}, body
        print(
            "OK  get_process_tree (populated): FQL substring filter, "
            "summaries body, parent/child tree"
        )
    finally:
        await conn.aclose()


async def check_quarantine_file_invalid_sha() -> None:
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        for bad in ("", "not-a-sha", "a" * 63, "a" * 65, "z" * 64):
            try:
                await conn.quarantine_file(sha256=bad)
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for sha={bad!r}")
        assert fake.ioc_requests == [], "no IOC request should have been made"
        print("OK  quarantine_file rejects non-SHA256 inputs")
    finally:
        await conn.aclose()


async def check_quarantine_file_happy_path() -> None:
    fake = FakeFalcon()
    sha = "ABCDEF" + "0" * 58  # mixed-case 64 hex
    fake.next_ioc_resources = [{"id": "ioc-deadbeef-1234"}]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.quarantine_file(sha256=sha)
        assert out["sha256"] == sha.lower(), out
        assert out["quarantined_on_endpoints"] == 1, out
        assert out["ticket"].startswith("QUA-"), out["ticket"]

        body = fake.last_ioc_body()
        assert "indicators" in body and len(body["indicators"]) == 1, body
        ind = body["indicators"][0]
        assert ind["type"] == "sha256"
        assert ind["value"] == sha.lower()
        assert ind["action"] == "prevent"
        assert ind["severity"] == "high"
        assert set(ind["platforms"]) == {"windows", "mac", "linux"}
        assert ind["applied_globally"] is True
        print(
            "OK  quarantine_file: lowercased SHA, prevent action, full IOC body"
        )
    finally:
        await conn.aclose()


async def check_kill_process_validation() -> None:
    fake = FakeFalcon()
    conn = _make_connector(fake=fake)
    try:
        for bad in (0, -5, True, False, "42", None):  # bool subclasses int!
            try:
                await conn.kill_process(host=TEST_AID, pid=bad)  # type: ignore[arg-type]
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for pid={bad!r}")
        assert fake.rtr_session_post_requests == [], (
            "no RTR session should have been opened"
        )
        print(
            "OK  kill_process rejects non-positive / non-int / bool pids"
        )
    finally:
        await conn.aclose()


async def check_kill_process_happy_path() -> None:
    fake = FakeFalcon()
    # First poll returns incomplete, second returns complete.
    fake.rtr_poll_sequence = [
        {"complete": False, "stderr": "", "stdout": ""},
        {"complete": True, "stderr": "", "stdout": "killed pid 4242"},
    ]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.kill_process(host=TEST_AID, pid=4242)
        assert out == {"host": TEST_AID, "pid": 4242, "terminated": True}, out

        # Full lifecycle ran.
        assert len(fake.rtr_session_post_requests) == 1, "open session"
        assert len(fake.rtr_command_post_requests) == 1, "issue kill"
        assert len(fake.rtr_command_poll_requests) >= 2, "polled at least twice"
        assert len(fake.rtr_session_delete_requests) == 1, "session closed"

        # Open session body.
        open_body = json.loads(
            fake.rtr_session_post_requests[0].content.decode("utf-8")
        )
        assert open_body == {"device_id": TEST_AID}, open_body

        # Kill command body.
        cmd_body = fake.last_rtr_command_body()
        assert cmd_body["base_command"] == "kill"
        assert cmd_body["command_string"] == "kill 4242"
        assert cmd_body["session_id"] == "rtr-session-id-xyz"

        # Close session via DELETE with session_id query param.
        close_req = fake.rtr_session_delete_requests[-1]
        assert close_req.url.params.get("session_id") == "rtr-session-id-xyz"
        print("OK  kill_process: full RTR lifecycle with polling + cleanup")
    finally:
        await conn.aclose()


async def check_kill_process_stderr_surfaced() -> None:
    fake = FakeFalcon()
    fake.rtr_poll_sequence = [
        {"complete": True, "stderr": "Access denied: ESRCH", "stdout": ""}
    ]
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.kill_process(host=TEST_AID, pid=4242)
        except ConnectorError as e:
            assert "Access denied" in str(e), str(e)
        else:
            raise AssertionError("expected ConnectorError on RTR stderr")
        # Session MUST still have been closed despite the failure.
        assert len(fake.rtr_session_delete_requests) == 1, (
            "session must be closed even on command failure"
        )
        print(
            "OK  kill_process: RTR stderr surfaces as ConnectorError + "
            "session is still closed"
        )
    finally:
        await conn.aclose()


async def check_kill_process_session_init_error() -> None:
    """A Falcon error envelope on session init must not leak a session."""
    fake = FakeFalcon()
    fake.next_rtr_session_id = None
    fake.next_rtr_session_errors = [{"code": 403, "message": "no admin scope"}]
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.kill_process(host=TEST_AID, pid=4242)
        except ConnectorError as e:
            assert "no admin scope" in str(e), str(e)
        else:
            raise AssertionError("expected ConnectorError on RTR init failure")
        # No command issued, no session to close.
        assert fake.rtr_command_post_requests == []
        assert fake.rtr_session_delete_requests == []
        print(
            "OK  kill_process: Falcon error envelope on session init "
            "surfaces + nothing to close"
        )
    finally:
        await conn.aclose()


async def check_oauth_failure_surfaced() -> None:
    fake = FakeFalcon()
    fake.oauth_status = 401
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.health_check()
        except ConnectorAuthError as e:
            assert "OAuth" in str(e) or "token" in str(e).lower(), str(e)
            print("OK  401 from /oauth2/token -> ConnectorAuthError")
        else:
            raise AssertionError("expected ConnectorAuthError on OAuth failure")
    finally:
        await conn.aclose()


async def check_device_action_error_surfaced() -> None:
    fake = FakeFalcon()
    fake.next_action_errors = [
        {"code": 409, "message": "device already contained"}
    ]
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.isolate_host(host=TEST_AID, reason="x")
        except ConnectorError as e:
            assert "already contained" in str(e), str(e)
            print(
                "OK  Falcon inline error envelope on isolate_host -> "
                "ConnectorError"
            )
        else:
            raise AssertionError("expected ConnectorError on action failure")
    finally:
        await conn.aclose()


# ─── runner ──────────────────────────────────────────────────────────────


async def _main() -> None:
    # Synchronous checks first (cheap, fail-fast).
    check_factory_registered()
    check_required_params_rejected()
    check_missing_secrets_rejected()
    check_fql_escaping()
    check_safe_int()
    check_behaviors_to_tree()
    check_make_ticket()

    # Async checks with FakeFalcon transport.
    await check_health_check_happy_path()
    await check_resolve_device_id_aid_shortcut()
    await check_resolve_device_id_hostname_lookup()
    await check_resolve_device_id_not_found()
    await check_isolate_requires_reason()
    await check_release_host_happy_path()
    await check_get_process_tree_empty()
    await check_get_process_tree_populated()
    await check_quarantine_file_invalid_sha()
    await check_quarantine_file_happy_path()
    await check_kill_process_validation()
    await check_kill_process_happy_path()
    await check_kill_process_stderr_surfaced()
    await check_kill_process_session_init_error()
    await check_oauth_failure_surfaced()
    await check_device_action_error_surfaced()

    print("\nALL CROWDSTRIKE CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
