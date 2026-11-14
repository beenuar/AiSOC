"""Smoke test for the SentinelOneEdrConnector.

Intercepts HTTP calls with ``httpx.MockTransport`` so the test never
hits real SentinelOne consoles. Verifies:

  1. Factory is registered for ConnectorKind.EDR / vendor=sentinelone.
  2. Construction requires ``base_url`` and rejects non-https URLs.
  3. Missing ``api_token`` raises ConnectorAuthError.
  4. Out-of-range ``threat_window_hours`` rejected.
  5. ``_check_entity_value`` rejects empty / non-str / control-char
     inputs.
  6. ``_safe_int`` parses ints/numeric strings, ``None`` for empties.
  7. ``_normalise_os_types`` defaults, accepts CSV + list inputs,
     rejects unknown OS types.
  8. ``_csv_param`` validates numeric scope ids.
  9. ``_threats_to_tree`` reconstructs parent/child edges, dedupes
     repeat originating pids, synthesises a parent stub from
     ``parentProcessName`` when no numeric parent pid is present.
 10. ``_make_ticket`` derives a stable agent-id-prefixed ticket.
 11. ``health_check`` hits ``/web/api/v2.1/system/info`` with the
     ``ApiToken <token>`` header.
 12. ``_resolve_agent_id`` trusts AID-shaped strings, falls back to
     ``/agents?computerName=...`` for hostnames, raises on missing.
 13. ``isolate_host`` / ``release_host`` POST to
     ``/agents/actions/disconnect`` and ``/connect`` with
     ``filter.ids`` and return the mock-compatible envelope.
 14. ``isolate_host`` requires a non-empty reason.
 15. ``get_process_tree`` returns an empty tree when no threats land
     and applies the ``createdAt__gte`` window param.
 16. ``get_process_tree`` (populated) reconstructs the tree and
     filters by ``process_name`` client-side.
 17. ``quarantine_file`` rejects bad SHA-256s, posts one
     ``black_hash`` restriction per configured OS type, and tickets
     off the first ``id`` returned.
 18. ``quarantine_file`` honours a custom ``quarantine_os_types``.
 19. ``kill_process`` rejects non-positive / non-int / bool pids and
     emits no HTTP traffic.
 20. ``kill_process`` raises when no open threat references the pid.
 21. ``kill_process`` mitigate path: queries threats, posts the
     ``mitigate/kill`` body with the matching threat ids, and
     surfaces ``affected=0`` as ConnectorError.
 22. 401 from any S1 endpoint surfaces as ConnectorAuthError.
 23. Inline ``errors[]`` envelopes on a 2xx surface as ConnectorError.
 24. ``site_ids`` config attaches ``siteIds=`` to every read query.

Run with:

    cd platform/backend
    python -m tests._check_sentinelone_connector
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-sentinelone-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "sentinelone-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors.sentinelone import (  # noqa: E402
    SentinelOneEdrConnector,
    _check_entity_value,
    _csv_param,
    _make_ticket,
    _normalise_os_types,
    _safe_int,
    _threats_to_tree,
    make_sentinelone_edr,
)
from app.connectors.sdk.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
)
from app.connectors.sdk.builtin import register_builtin_factories  # noqa: E402
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402


# Canonical (random but well-shaped) values used throughout the test.
TEST_BASE_URL = "https://usea1-partners.sentinelone.net"
TEST_AID = "987654321012345678"  # 18 digits
TEST_HOST = "host-7.corp.local"
TEST_TOKEN = "fake-s1-api-token-abcdef0123"


# ─── fake SentinelOne surface ───────────────────────────────────────────


class FakeSentinelOne:
    """In-memory SentinelOne stub for ``httpx.MockTransport``.

    Routes by URL path. Per-endpoint request lists let tests assert
    headers, query params, and JSON bodies. Default responses give a
    "happy path" suitable for tests that only care about request shape;
    mutate the ``next_*`` fields to drive specific scenarios.
    """

    def __init__(self) -> None:
        # Recorded requests, per logical endpoint.
        self.system_info_requests: list[httpx.Request] = []
        self.agent_query_requests: list[httpx.Request] = []
        self.agent_action_requests: list[httpx.Request] = []
        self.threat_query_requests: list[httpx.Request] = []
        self.threat_mitigate_requests: list[httpx.Request] = []
        self.restriction_requests: list[httpx.Request] = []

        # Force a specific HTTP status (e.g. 401) for every request.
        self.force_status: int | None = None

        # system/info default.
        self.next_system_info_data: dict[str, Any] = {
            "latestAgentVersion": "23.4.2.123"
        }

        # Agent query default: hostname -> [TEST_AID].
        # Set to [] to simulate "host not found".
        self.next_agent_query_data: list[dict[str, Any]] = [{"id": TEST_AID}]
        self.next_agent_query_total: int = 137

        # Agent action default.
        self.next_action_affected: int = 1
        self.next_action_errors: list[dict[str, Any]] = []

        # Threats query default.
        self.next_threat_query_data: list[dict[str, Any]] = []
        self.next_threat_query_errors: list[dict[str, Any]] = []

        # Threat mitigate default.
        self.next_mitigate_affected: int = 1
        self.next_mitigate_errors: list[dict[str, Any]] = []

        # Restrictions create default. Returns one resource per call.
        self.next_restriction_id: str = "restriction-1"
        self.next_restriction_errors: list[dict[str, Any]] = []
        self._restriction_counter = 0

    # ── handler ─────────────────────────────────────────────────────────

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method.upper()

        if self.force_status is not None:
            return _json_response(
                self.force_status,
                {
                    "errors": [
                        {
                            "code": self.force_status,
                            "title": "Forced",
                            "detail": "forced error",
                        }
                    ]
                },
            )

        if path == "/web/api/v2.1/system/info" and method == "GET":
            self.system_info_requests.append(request)
            return _json_response(
                200, {"data": dict(self.next_system_info_data)}
            )

        if path == "/web/api/v2.1/agents" and method == "GET":
            self.agent_query_requests.append(request)
            return _json_response(
                200,
                {
                    "data": list(self.next_agent_query_data),
                    "pagination": {"totalItems": self.next_agent_query_total},
                },
            )

        # Agent action: /agents/actions/disconnect | /connect
        if (
            path.startswith("/web/api/v2.1/agents/actions/")
            and method == "POST"
        ):
            self.agent_action_requests.append(request)
            body: dict[str, Any] = {
                "data": {"affected": self.next_action_affected}
            }
            if self.next_action_errors:
                body["errors"] = list(self.next_action_errors)
            return _json_response(200, body)

        if path == "/web/api/v2.1/threats" and method == "GET":
            self.threat_query_requests.append(request)
            body = {"data": list(self.next_threat_query_data)}
            if self.next_threat_query_errors:
                body["errors"] = list(self.next_threat_query_errors)
            return _json_response(200, body)

        if (
            path == "/web/api/v2.1/threats/mitigate/kill"
            and method == "POST"
        ):
            self.threat_mitigate_requests.append(request)
            body = {"data": {"affected": self.next_mitigate_affected}}
            if self.next_mitigate_errors:
                body["errors"] = list(self.next_mitigate_errors)
            return _json_response(200, body)

        if path == "/web/api/v2.1/restrictions" and method == "POST":
            self.restriction_requests.append(request)
            self._restriction_counter += 1
            res_id = f"{self.next_restriction_id}-{self._restriction_counter}"
            body = {"data": [{"id": res_id}]}
            if self.next_restriction_errors:
                body["errors"] = list(self.next_restriction_errors)
            return _json_response(200, body)

        return httpx.Response(
            404,
            content=b"",
            headers={"X-Test-Unhandled": f"{method} {path}"},
        )


# ─── small helpers ──────────────────────────────────────────────────────


def _json_response(status: int, body: Any) -> httpx.Response:
    return httpx.Response(
        status,
        json=body,
        headers={"Content-Type": "application/json"},
    )


def _make_connector(
    *,
    fake: FakeSentinelOne,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> SentinelOneEdrConnector:
    """Build a SentinelOneEdrConnector wired to ``fake``'s transport."""
    cfg = ConnectorConfig(
        tenant_id="t-sentinelone-test",
        kind=ConnectorKind.EDR,
        vendor="sentinelone",
        params=params
        if params is not None
        else {
            "base_url": TEST_BASE_URL,
            "threat_window_hours": 24,
        },
        secrets=secrets
        if secrets is not None
        else {"api_token": TEST_TOKEN},
    )
    conn = SentinelOneEdrConnector(cfg)
    transport = httpx.MockTransport(fake.handler)
    conn._http._client = httpx.AsyncClient(
        base_url=TEST_BASE_URL,
        transport=transport,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    # Make failure paths fail fast — don't burn the test with retries.
    conn._http.max_retries = 0
    return conn


# ─── synchronous checks ──────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.EDR, "sentinelone"))
    assert factory is make_sentinelone_edr, (
        "expected make_sentinelone_edr registered for EDR/sentinelone, "
        f"got {factory}"
    )
    print("OK  factory registered: ConnectorKind.EDR, vendor='sentinelone'")


def check_required_params_rejected() -> None:
    base_secrets = {"api_token": TEST_TOKEN}

    # Missing base_url
    try:
        SentinelOneEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="sentinelone",
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
        SentinelOneEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="sentinelone",
                params={"base_url": "http://example.sentinelone.net"},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "https" in str(e), e
        print("OK  non-https base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on non-https base_url")

    # Out-of-range threat_window_hours
    try:
        SentinelOneEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="sentinelone",
                params={
                    "base_url": TEST_BASE_URL,
                    "threat_window_hours": 9999,
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "threat_window_hours" in str(e), e
        print("OK  threat_window_hours out of range -> ConnectorError")
    else:
        raise AssertionError(
            "expected ConnectorError on huge threat_window_hours"
        )


def check_missing_secrets_rejected() -> None:
    try:
        SentinelOneEdrConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EDR,
                vendor="sentinelone",
                params={"base_url": TEST_BASE_URL},
                secrets={},
            )
        )
    except ConnectorAuthError as e:
        assert "api_token" in str(e), e
        print("OK  missing api_token -> ConnectorAuthError")
    else:
        raise AssertionError("expected ConnectorAuthError on missing api_token")


def check_entity_validation() -> None:
    # Valid pass-through.
    assert _check_entity_value("host-7", field="host") == "host-7"
    # Strip-only whitespace rejected.
    for bad in ("", "   ", "host\nbad", "host\x00bad", "host\tbad", "\x7f"):
        try:
            _check_entity_value(bad, field="host")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for {bad!r}")
    # Non-string rejected.
    try:
        _check_entity_value(123, field="host")  # type: ignore[arg-type]
    except ConnectorError:
        pass
    else:
        raise AssertionError("expected rejection for non-string entity value")
    print("OK  _check_entity_value: rejects empty / control-chars / non-str")


def check_safe_int() -> None:
    assert _safe_int(None) is None
    assert _safe_int("") is None
    assert _safe_int("not-a-number") is None
    assert _safe_int(42) == 42
    assert _safe_int("42") == 42
    assert _safe_int("0") == 0
    assert _safe_int(-1) == -1
    print("OK  _safe_int: int/str round-trip, None/empty/garbage -> None")


def check_normalise_os_types() -> None:
    assert _normalise_os_types(None) == ["windows", "macos", "linux"]
    assert _normalise_os_types("") == ["windows", "macos", "linux"]
    assert _normalise_os_types("windows,macos") == ["windows", "macos"]
    assert _normalise_os_types(["Linux", "WINDOWS"]) == ["linux", "windows"]
    # Dedupe preserves order.
    assert _normalise_os_types("windows,windows,linux") == [
        "windows",
        "linux",
    ]
    # Bad type rejected.
    try:
        _normalise_os_types(42)  # type: ignore[arg-type]
    except ConnectorError:
        pass
    else:
        raise AssertionError("expected rejection for int os_types")
    # Unknown os type rejected.
    try:
        _normalise_os_types(["windows", "solaris"])
    except ConnectorError as e:
        assert "solaris" in str(e), e
    else:
        raise AssertionError("expected rejection for unknown os type")
    print(
        "OK  _normalise_os_types: defaults, CSV/list parse, dedupe, "
        "invalid rejected"
    )


def check_csv_param() -> None:
    assert _csv_param(None) is None
    assert _csv_param("") is None
    assert _csv_param("12345678,87654321") == "12345678,87654321"
    assert _csv_param(["12345678", "87654321"]) == "12345678,87654321"
    # Non-numeric scope id rejected.
    try:
        _csv_param("abc")
    except ConnectorError as e:
        assert "numeric" in str(e), e
    else:
        raise AssertionError("expected rejection for non-numeric scope id")
    print("OK  _csv_param: CSV/list normalise + numeric validation")


def check_threats_to_tree() -> None:
    # Empty input.
    assert _threats_to_tree([]) == []
    assert _threats_to_tree([None, "garbage", {"threatInfo": "not a dict"}]) == []  # type: ignore[list-item]

    # Two-level tree with a named-only parent (no numeric pid).
    threats: list[Any] = [
        {
            "id": "th-001",
            "threatInfo": {
                "originatingProcessId": 200,
                "parentProcessName": "explorer.exe",
                "processName": "powershell.exe",
                "commandLine": "powershell -enc AAAA",
                "processUser": "alice",
                "signature": {"signedStatus": "signed"},
            },
        },
        # Duplicate originating pid; should be dropped.
        {
            "id": "th-002",
            "threatInfo": {
                "originatingProcessId": 200,
                "parentProcessName": "explorer.exe",
                "processName": "powershell.exe",
                "commandLine": "different cmdline",
            },
        },
        # Child of the above via numeric parentProcessId.
        {
            "id": "th-003",
            "threatInfo": {
                "originatingProcessId": 300,
                "parentProcessId": 200,
                "processName": "rundll32.exe",
                "commandLine": "rundll32 evil.dll",
            },
        },
        # Orphan: no parent info -> top-level root.
        {
            "id": "th-004",
            "threatInfo": {
                "originatingProcessId": 400,
                "processName": "wscript.exe",
            },
        },
    ]
    forest = _threats_to_tree(threats)
    # Two roots: synthesised "explorer.exe" stub + orphan wscript.exe.
    assert len(forest) == 2, forest
    by_name = {n["name"]: n for n in forest}
    assert "explorer.exe" in by_name, by_name
    assert "wscript.exe" in by_name, by_name
    stub = by_name["explorer.exe"]
    assert stub["pid"] is None
    # powershell child of stub.
    assert len(stub["children"]) == 1, stub["children"]
    ps = stub["children"][0]
    assert ps["pid"] == 200
    assert ps["name"] == "powershell.exe"
    assert ps["signed"] is True
    assert ps["suspicious"] is True
    # rundll32 child of powershell.
    assert len(ps["children"]) == 1, ps["children"]
    rundll = ps["children"][0]
    assert rundll["pid"] == 300
    assert rundll["name"] == "rundll32.exe"
    print(
        "OK  _threats_to_tree: numeric link, named-parent stub, dedupe, "
        "orphan-as-root, signed flag"
    )


def check_make_ticket() -> None:
    assert _make_ticket("ISO", TEST_AID, 1) == f"ISO-{TEST_AID[:8]}1"
    assert _make_ticket("REL", TEST_AID, 0) == f"REL-{TEST_AID[:8]}x"
    assert _make_ticket("ISO", "", 1) == "ISO-unknown1"
    print("OK  _make_ticket: agent-id prefix + state suffix + unknown fallback")


# ─── async checks ────────────────────────────────────────────────────────


async def check_health_check_happy_path() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        info = await conn.health_check()
        assert info["ok"] is True
        assert info["vendor"] == "sentinelone"
        assert info["kind"] == "edr"
        assert info["console_version"] == "23.4.2.123"

        assert len(fake.system_info_requests) == 1
        req = fake.system_info_requests[-1]
        assert req.url.path == "/web/api/v2.1/system/info"
        # ApiToken header.
        assert (
            req.headers.get("Authorization") == f"ApiToken {TEST_TOKEN}"
        ), req.headers.get("Authorization")
        print(
            "OK  health_check: /system/info + ApiToken header + envelope"
        )
    finally:
        await conn.aclose()


async def check_resolve_agent_id_aid_shortcut() -> None:
    """An AID-shaped host string skips the /agents lookup entirely."""
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        await conn.isolate_host(host=TEST_AID, reason="testing")
        # No /agents GET query was issued.
        assert fake.agent_query_requests == [], (
            "AID should bypass /agents lookup"
        )
        # One agent action POST landed.
        assert len(fake.agent_action_requests) == 1
        action_req = fake.agent_action_requests[-1]
        assert action_req.url.path.endswith("/disconnect")
        body = json.loads(action_req.content.decode("utf-8"))
        assert body["filter"]["ids"] == TEST_AID, body
        print("OK  _resolve_agent_id: AID shape bypasses hostname lookup")
    finally:
        await conn.aclose()


async def check_resolve_agent_id_hostname_lookup() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        out = await conn.isolate_host(host=TEST_HOST, reason="bad behavior")
        assert out["host"] == TEST_HOST
        assert out["isolated"] is True
        assert out["reason"] == "bad behavior"
        assert out["ticket"].startswith("ISO-"), out["ticket"]

        # One hostname lookup + one disconnect action.
        assert len(fake.agent_query_requests) == 1
        q = fake.agent_query_requests[-1]
        assert q.url.params.get("computerName") == TEST_HOST
        assert len(fake.agent_action_requests) == 1
        action_req = fake.agent_action_requests[-1]
        assert action_req.url.path.endswith("/disconnect")
        body = json.loads(action_req.content.decode("utf-8"))
        assert body["filter"]["ids"] == TEST_AID, body
        print(
            "OK  _resolve_agent_id: hostname -> AID via /agents query, "
            "then disconnect"
        )
    finally:
        await conn.aclose()


async def check_resolve_agent_id_not_found() -> None:
    fake = FakeSentinelOne()
    fake.next_agent_query_data = []  # no match
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
        # No action should have been dispatched.
        assert fake.agent_action_requests == []
    finally:
        await conn.aclose()


async def check_isolate_requires_reason() -> None:
    fake = FakeSentinelOne()
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
        assert fake.agent_action_requests == [], (
            "no action should have been dispatched"
        )
        print("OK  isolate_host requires non-empty reason")
    finally:
        await conn.aclose()


async def check_release_host_happy_path() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        out = await conn.release_host(host=TEST_AID)
        assert out["host"] == TEST_AID
        assert out["isolated"] is False
        assert out["ticket"].startswith("REL-"), out["ticket"]

        assert len(fake.agent_action_requests) == 1
        action_req = fake.agent_action_requests[-1]
        assert action_req.url.path.endswith("/connect"), action_req.url.path
        body = json.loads(action_req.content.decode("utf-8"))
        assert body["filter"]["ids"] == TEST_AID, body
        print("OK  release_host -> /agents/actions/connect + envelope")
    finally:
        await conn.aclose()


async def check_get_process_tree_empty() -> None:
    fake = FakeSentinelOne()
    fake.next_threat_query_data = []
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_process_tree(host=TEST_AID)
        assert out == {"host": TEST_AID, "tree": []}, out

        assert len(fake.threat_query_requests) == 1
        q = fake.threat_query_requests[-1]
        params = q.url.params
        assert params.get("agentIds") == TEST_AID, params
        # Window param applied.
        assert params.get("createdAt__gte"), params
        # Z-terminated ISO-8601 with ms.
        ca = params.get("createdAt__gte") or ""
        assert ca.endswith("Z") and ".000Z" in ca, ca
        print(
            "OK  get_process_tree (empty): /threats with agentIds + "
            "createdAt__gte"
        )
    finally:
        await conn.aclose()


async def check_get_process_tree_populated() -> None:
    fake = FakeSentinelOne()
    fake.next_threat_query_data = [
        {
            "id": "th-A",
            "threatInfo": {
                "originatingProcessId": 200,
                "parentProcessName": "explorer.exe",
                "processName": "powershell.exe",
                "commandLine": "powershell -enc AAAA",
            },
        },
        {
            "id": "th-B",
            "threatInfo": {
                "originatingProcessId": 300,
                "processName": "winword.exe",
            },
        },
    ]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_process_tree(
            host=TEST_AID, process_name="powershell"
        )
        forest = out["tree"]
        # Only the powershell branch survives the client-side filter.
        assert len(forest) == 1, forest
        root = forest[0]
        assert root["name"] == "explorer.exe"  # synthesised stub
        assert len(root["children"]) == 1
        child = root["children"][0]
        assert child["pid"] == 200
        assert child["name"] == "powershell.exe"
        print(
            "OK  get_process_tree (populated): tree built + client-side "
            "process_name filter"
        )
    finally:
        await conn.aclose()


async def check_quarantine_file_invalid_sha() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        for bad in ("", "not-a-sha", "a" * 63, "a" * 65, "z" * 64):
            try:
                await conn.quarantine_file(sha256=bad)
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for sha={bad!r}")
        assert fake.restriction_requests == [], (
            "no restriction request should have been made"
        )
        print("OK  quarantine_file rejects non-SHA256 inputs")
    finally:
        await conn.aclose()


async def check_quarantine_file_happy_path() -> None:
    fake = FakeSentinelOne()
    sha = "ABCDEF" + "0" * 58  # mixed-case 64 hex
    conn = _make_connector(fake=fake)
    try:
        out = await conn.quarantine_file(sha256=sha)
        assert out["sha256"] == sha.lower(), out
        # Default OS types: windows, macos, linux -> 3 restrictions.
        assert out["quarantined_on_endpoints"] == 3, out
        assert out["ticket"].startswith("QUA-"), out["ticket"]

        assert len(fake.restriction_requests) == 3
        # Verify each call's body has the canonical SHA + a valid os type.
        seen_os: list[str] = []
        for req in fake.restriction_requests:
            body = json.loads(req.content.decode("utf-8"))
            assert body["filter"]["tenant"] is True, body
            data = body["data"]
            assert data["value"] == sha.lower()
            assert data["type"] == "black_hash"
            assert data["osType"] in {"windows", "macos", "linux"}
            seen_os.append(data["osType"])
        assert set(seen_os) == {"windows", "macos", "linux"}, seen_os
        print(
            "OK  quarantine_file: lowercased SHA, one restriction per OS "
            "type, full body"
        )
    finally:
        await conn.aclose()


async def check_quarantine_file_custom_os_types() -> None:
    fake = FakeSentinelOne()
    sha = "f" * 64
    conn = _make_connector(
        fake=fake,
        params={
            "base_url": TEST_BASE_URL,
            "quarantine_os_types": ["windows"],
        },
    )
    try:
        out = await conn.quarantine_file(sha256=sha)
        assert out["quarantined_on_endpoints"] == 1, out
        assert len(fake.restriction_requests) == 1
        body = json.loads(fake.restriction_requests[-1].content.decode("utf-8"))
        assert body["data"]["osType"] == "windows", body
        print("OK  quarantine_file honours custom quarantine_os_types")
    finally:
        await conn.aclose()


async def check_kill_process_validation() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(fake=fake)
    try:
        for bad in (0, -5, True, False, "42", None):  # bool subclasses int!
            try:
                await conn.kill_process(host=TEST_AID, pid=bad)  # type: ignore[arg-type]
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for pid={bad!r}")
        assert fake.threat_query_requests == [], (
            "no threat query should have been issued"
        )
        assert fake.threat_mitigate_requests == []
        print(
            "OK  kill_process rejects non-positive / non-int / bool pids"
        )
    finally:
        await conn.aclose()


async def check_kill_process_no_open_threat() -> None:
    fake = FakeSentinelOne()
    fake.next_threat_query_data = []  # no threats matching pid
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.kill_process(host=TEST_AID, pid=4242)
        except ConnectorError as e:
            assert "no open threat" in str(e).lower(), str(e)
            assert "4242" in str(e)
        else:
            raise AssertionError(
                "expected ConnectorError when no threat references pid"
            )
        # Mitigate must NOT have been called.
        assert fake.threat_mitigate_requests == []
        print(
            "OK  kill_process: no open threat -> ConnectorError (no mitigate)"
        )
    finally:
        await conn.aclose()


async def check_kill_process_happy_path() -> None:
    fake = FakeSentinelOne()
    fake.next_threat_query_data = [
        {
            "id": "th-kill-1",
            "threatInfo": {
                "originatingProcessId": 4242,
                "processName": "evil.exe",
            },
        },
        # Decoy threat with different pid; must NOT be mitigated.
        {
            "id": "th-decoy",
            "threatInfo": {
                "originatingProcessId": 9999,
                "processName": "other.exe",
            },
        },
    ]
    conn = _make_connector(fake=fake)
    try:
        out = await conn.kill_process(host=TEST_AID, pid=4242)
        assert out == {"host": TEST_AID, "pid": 4242, "terminated": True}, out

        # One threat query (with mitigationStatuses filter) + one mitigate.
        assert len(fake.threat_query_requests) == 1
        q = fake.threat_query_requests[-1]
        assert q.url.params.get("agentIds") == TEST_AID
        assert "not_mitigated" in (
            q.url.params.get("mitigationStatuses") or ""
        )
        assert len(fake.threat_mitigate_requests) == 1
        mit_body = json.loads(
            fake.threat_mitigate_requests[-1].content.decode("utf-8")
        )
        assert mit_body["filter"]["ids"] == ["th-kill-1"], mit_body
        print(
            "OK  kill_process: matches pid -> threat-id, mitigates exactly "
            "the matching threat"
        )
    finally:
        await conn.aclose()


async def check_kill_process_mitigate_affected_zero() -> None:
    fake = FakeSentinelOne()
    fake.next_threat_query_data = [
        {
            "id": "th-stale",
            "threatInfo": {
                "originatingProcessId": 4242,
                "processName": "evil.exe",
            },
        }
    ]
    fake.next_mitigate_affected = 0
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.kill_process(host=TEST_AID, pid=4242)
        except ConnectorError as e:
            assert "affected=0" in str(e), str(e)
            print(
                "OK  kill_process: mitigate affected=0 surfaces as "
                "ConnectorError"
            )
        else:
            raise AssertionError(
                "expected ConnectorError when mitigate.affected==0"
            )
    finally:
        await conn.aclose()


async def check_auth_failure_surfaced() -> None:
    fake = FakeSentinelOne()
    fake.force_status = 401
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.health_check()
        except ConnectorAuthError as e:
            assert (
                "auth" in str(e).lower() or "401" in str(e) or "unauth" in str(e).lower()
            ), str(e)
            print("OK  401 -> ConnectorAuthError")
        else:
            raise AssertionError("expected ConnectorAuthError on 401")
    finally:
        await conn.aclose()


async def check_inline_error_surfaced() -> None:
    fake = FakeSentinelOne()
    # Action returns 200 but with a non-empty errors[] envelope.
    fake.next_action_errors = [
        {"code": 4040, "title": "Not Found", "detail": "agent offline"}
    ]
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.isolate_host(host=TEST_AID, reason="testing")
        except ConnectorError as e:
            assert "agent offline" in str(e), str(e)
            print(
                "OK  inline errors[] envelope -> ConnectorError (action path)"
            )
        else:
            raise AssertionError("expected ConnectorError on inline errors[]")
    finally:
        await conn.aclose()


async def check_site_ids_attached() -> None:
    fake = FakeSentinelOne()
    conn = _make_connector(
        fake=fake,
        params={
            "base_url": TEST_BASE_URL,
            "site_ids": "12345678,87654321",
        },
    )
    try:
        # Trigger a hostname lookup path that uses /agents (which attaches scope).
        await conn.get_process_tree(host=TEST_HOST)

        # Verify siteIds attached to the /agents and /threats queries.
        agent_q = fake.agent_query_requests[-1]
        assert agent_q.url.params.get("siteIds") == "12345678,87654321"
        threat_q = fake.threat_query_requests[-1]
        assert threat_q.url.params.get("siteIds") == "12345678,87654321"
        print("OK  site_ids config attached to read queries")
    finally:
        await conn.aclose()


# ─── runner ──────────────────────────────────────────────────────────────


async def _main() -> None:
    # Synchronous checks first (cheap, fail-fast).
    check_factory_registered()
    check_required_params_rejected()
    check_missing_secrets_rejected()
    check_entity_validation()
    check_safe_int()
    check_normalise_os_types()
    check_csv_param()
    check_threats_to_tree()
    check_make_ticket()

    # Async checks with FakeSentinelOne transport.
    await check_health_check_happy_path()
    await check_resolve_agent_id_aid_shortcut()
    await check_resolve_agent_id_hostname_lookup()
    await check_resolve_agent_id_not_found()
    await check_isolate_requires_reason()
    await check_release_host_happy_path()
    await check_get_process_tree_empty()
    await check_get_process_tree_populated()
    await check_quarantine_file_invalid_sha()
    await check_quarantine_file_happy_path()
    await check_quarantine_file_custom_os_types()
    await check_kill_process_validation()
    await check_kill_process_no_open_threat()
    await check_kill_process_happy_path()
    await check_kill_process_mitigate_affected_zero()
    await check_auth_failure_surfaced()
    await check_inline_error_surfaced()
    await check_site_ids_attached()

    print("\nALL SENTINELONE CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
