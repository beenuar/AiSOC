"""Smoke test for the OktaIdpConnector.

Intercepts HTTP calls with `httpx.MockTransport` so the test never hits
the real Okta org. Verifies:

  1. Factory is registered for ConnectorKind.IDP / vendor=okta.
  2. Construction requires `base_url` (must be https) and `api_token`
     secret; `disable_lifecycle` is bounded to suspend|deactivate.
  3. Identifier hygiene: control chars and empty strings are rejected.
  4. Okta IDs are not percent-encoded (`_OKTA_ID_RE`); logins with `@`,
     `+`, `.` round-trip via `quote(safe="")`.
  5. `health_check` GETs `/api/v1/users/me` with the SSWS scheme.
  6. `get_user` happy path: GET `/api/v1/users/{id}` + group/factor/log
     enrichment fan-out, with the System Log row mapped to ts/src_ip/
     country/asn/anomaly_score and the env-default `last_signin.ts`
     overwritten by the richer log event.
  7. `get_user` enrichment failures degrade gracefully (groups,
     factors, log API can each 5xx without failing the whole call).
  8. `get_user` E0000007 (user not found) → ConnectorError(status=404).
  9. `revoke_sessions` with `count_sessions=True` does a GET-then-DELETE
     pair, reports the pre-DELETE count, and the DELETE always fires
     even when the GET fails.
 10. `revoke_sessions` includes `oauthTokens=true` on the DELETE.
 11. `disable_user` suspend (default) — POSTs `/lifecycle/suspend`.
 12. `disable_user` deactivate variant — POSTs `/lifecycle/deactivate`.
 13. `disable_user` E0000016 (already suspended) is idempotent success.
 14. `disable_user` requires a non-empty reason.
 15. `reset_password` POSTs `/lifecycle/reset_password?sendEmail=true`
     and never surfaces the reset URL.
 16. 401 from any endpoint → ConnectorAuthError.

Run with:

    cd platform/backend
    python -m tests._check_okta_connector
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs as _parse_qs_raw


def parse_qs(q: Any) -> dict[str, list[str]]:
    """parse_qs that tolerates bytes-style query strings from httpx."""
    if isinstance(q, (bytes, bytearray)):
        q = q.decode("utf-8")
    return _parse_qs_raw(q)

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-okta-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "okta-test.db")
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
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402
from app.connectors.okta import (  # noqa: E402
    OktaIdpConnector,
    _check_identifier,
    _encode_path_id,
    _extract_signin_event,
    _make_ticket,
    _risk_to_score,
    make_okta_idp,
)


OKTA_BASE = "https://example.okta.com"
TEST_USER_ID = "00u1abcdefghijklmnop"  # 20-char Okta-style id
TEST_LOGIN = "alice@corp.com"


# ─── fake Okta surface ───────────────────────────────────────────────────


class FakeOkta:
    """In-memory Okta REST stub for httpx MockTransport.

    Records every request, returns pre-loaded responses keyed by
    ``(method, path)``. Tests assert on:
      * captured Authorization header (SSWS scheme),
      * query params (e.g. ``oauthTokens=true``, ``sendEmail=true``),
      * which paths were called and in what order.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        # ``responses`` maps (METHOD, PATH) → response factory or static
        # tuple. Factories receive the request so they can vary by
        # query params or attempt count.
        self.responses: dict[tuple[str, str], Any] = {}
        # Optional global override: force a status on *every* request.
        self.force_status: int | None = None
        self.force_body: bytes = b""

    def set(
        self,
        method: str,
        path: str,
        *,
        status: int = 200,
        body: Any = None,
    ) -> None:
        self.responses[(method.upper(), path)] = (status, body)

    def set_callable(
        self, method: str, path: str, fn: Any
    ) -> None:
        self.responses[(method.upper(), path)] = fn

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)

        if self.force_status is not None:
            return httpx.Response(
                self.force_status,
                content=self.force_body,
                headers={"Content-Type": "application/json"},
            )

        key = (request.method.upper(), request.url.path)
        spec = self.responses.get(key)
        if spec is None:
            return httpx.Response(
                404,
                json={
                    "errorCode": "E0000007",
                    "errorSummary": (
                        f"FakeOkta: unhandled {request.method} "
                        f"{request.url.path}"
                    ),
                },
            )
        if callable(spec):
            return spec(request)
        status, body = spec
        if body is None:
            return httpx.Response(status, content=b"")
        if isinstance(body, (bytes, bytearray)):
            return httpx.Response(status, content=bytes(body))
        return httpx.Response(status, json=body)

    def request_for(
        self, method: str, path: str
    ) -> httpx.Request | None:
        for r in self.requests:
            if (
                r.method.upper() == method.upper()
                and r.url.path == path
            ):
                return r
        return None

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]


def _make_connector(
    *,
    fake: FakeOkta,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> OktaIdpConnector:
    """Build an OktaIdpConnector wired to the FakeOkta transport."""
    cfg = ConnectorConfig(
        tenant_id="t-okta-test",
        kind=ConnectorKind.IDP,
        vendor="okta",
        params=params
        if params is not None
        else {
            "base_url": OKTA_BASE,
            "include_groups": True,
            "include_factors": True,
            "include_signin_log": True,
            "count_sessions": True,
        },
        secrets=secrets
        if secrets is not None
        else {"api_token": "fake-okta-token"},
    )
    conn = OktaIdpConnector(cfg)
    transport = httpx.MockTransport(fake.handler)
    # Hot-swap the inner httpx.AsyncClient with one bound to MockTransport.
    conn._http._client = httpx.AsyncClient(
        base_url=OKTA_BASE,
        transport=transport,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    return conn


# ─── synchronous checks ──────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.IDP, "okta"))
    assert factory is make_okta_idp, (
        f"expected make_okta_idp registered for IDP/okta, got {factory}"
    )
    print("OK  factory registered: ConnectorKind.IDP, vendor='okta'")


def check_required_params_rejected() -> None:
    # Missing base_url
    try:
        OktaIdpConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.IDP,
                vendor="okta",
                params={},
                secrets={"api_token": "x"},
            )
        )
    except ConnectorError as e:
        assert "base_url" in str(e), e
        print("OK  missing base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing base_url")

    # Non-https base_url
    try:
        OktaIdpConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.IDP,
                vendor="okta",
                params={"base_url": "http://insecure.okta.com"},
                secrets={"api_token": "x"},
            )
        )
    except ConnectorError as e:
        assert "https" in str(e), e
        print("OK  non-https base_url -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on non-https base_url")

    # Bad disable_lifecycle value
    try:
        OktaIdpConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.IDP,
                vendor="okta",
                params={
                    "base_url": OKTA_BASE,
                    "disable_lifecycle": "nuke",
                },
                secrets={"api_token": "x"},
            )
        )
    except ConnectorError as e:
        assert "disable_lifecycle" in str(e), e
        print("OK  bad disable_lifecycle -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on bad disable_lifecycle")


def check_missing_api_token_rejected() -> None:
    try:
        OktaIdpConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.IDP,
                vendor="okta",
                params={"base_url": OKTA_BASE},
                secrets={},
            )
        )
    except ConnectorError as e:
        # secret() raises ConnectorAuthError → also a ConnectorError.
        msg = str(e).lower()
        assert "api_token" in msg or "token" in msg, e
        print("OK  missing api_token -> ConnectorError")
    else:
        raise AssertionError("expected ConnectorError on missing api_token")


def check_identifier_hygiene() -> None:
    assert _check_identifier("alice@corp", field="user") == "alice@corp"
    assert _check_identifier("  alice  ", field="user") == "alice"

    for bad in ("", "   ", "alice\nbad", "alice\x00bad", "alice\tbad", 42):
        try:
            _check_identifier(bad, field="user")  # type: ignore[arg-type]
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected rejection for identifier {bad!r}")
    print("OK  _check_identifier: empty/control/non-str rejected")


def check_path_encoding() -> None:
    # Pure Okta ID (alphanumeric) — passes through unmolested.
    assert _encode_path_id(TEST_USER_ID) == TEST_USER_ID
    # Login with email-style chars — every URL-unsafe char gets percent-
    # encoded (including ``@``, ``.``, ``+``).
    encoded = _encode_path_id("alice+1@corp.com")
    assert "@" not in encoded and "+" not in encoded, encoded
    assert encoded.startswith("alice%2B1%40corp"), encoded
    print("OK  _encode_path_id: IDs untouched, logins percent-encoded")


def check_ticket_generation() -> None:
    t1 = _make_ticket("REVOKE", TEST_USER_ID)
    assert t1.startswith("REVOKE-"), t1
    assert t1.split("-")[1].isalnum(), t1
    # Logins: ticket uses last 8 chars of the encoded form, uppercased.
    t2 = _make_ticket("RESET", "alice@corp.com")
    assert t2.startswith("RESET-"), t2
    assert len(t2.split("-")[1]) > 0, t2
    print("OK  _make_ticket: stable, printable, vendor-correlatable")


def check_risk_score_mapping() -> None:
    assert _risk_to_score("LOW") == 0.15
    assert _risk_to_score("medium") == 0.55  # case-insensitive
    assert _risk_to_score(" HIGH ") == 0.85  # whitespace tolerant
    assert _risk_to_score("UNKNOWN") == 0.0
    assert _risk_to_score("garbage") == 0.0
    print("OK  _risk_to_score: Okta riskLevel → anomaly_score band")


def check_signin_extractor_shapes() -> None:
    # Empty / non-list inputs collapse to {}.
    assert _extract_signin_event(None) == {}
    assert _extract_signin_event([]) == {}
    assert _extract_signin_event([None]) == {}

    # Full shape: ts + src_ip + country + ASN + risk → anomaly_score.
    out = _extract_signin_event([
        {
            "published": "2026-06-16T22:00:00.123Z",
            "client": {
                "ipAddress": "203.0.113.7",
                "geographicalContext": {"country": "Russia"},
            },
            "securityContext": {
                "asNumber": 64500,
                "asOrg": "Example AS",
                "riskLevel": "HIGH",
            },
        }
    ])
    assert out["ts"] == "2026-06-16T22:00:00.123Z", out
    assert out["src_ip"] == "203.0.113.7", out
    assert out["country"] == "Russia", out
    assert out["asn"] == "AS64500 Example AS", out
    assert out["anomaly_score"] == 0.85, out

    # ITP fallback path: no riskLevel, but threat_suspected="true".
    out2 = _extract_signin_event([
        {
            "published": "2026-06-15T10:00:00Z",
            "debugContext": {
                "debugData": {"threat_suspected": "true"},
            },
        }
    ])
    assert out2["anomaly_score"] == 0.75, out2
    print("OK  _extract_signin_event: ts/ip/geo/asn/anomaly_score + ITP fallback")


# ─── async checks ────────────────────────────────────────────────────────


async def check_health_check_happy_path() -> None:
    fake = FakeOkta()
    fake.set(
        "GET",
        "/api/v1/users/me",
        status=200,
        body={
            "id": TEST_USER_ID,
            "profile": {"login": "soc-svc@corp.com"},
        },
    )
    conn = _make_connector(fake=fake)
    try:
        info = await conn.health_check()
        assert info["ok"] is True
        assert info["vendor"] == "okta"
        assert info["kind"] == "idp"
        assert info["service_account_id"] == TEST_USER_ID
        assert info["service_account_login"] == "soc-svc@corp.com"

        req = fake.request_for("GET", "/api/v1/users/me")
        assert req is not None
        # SSWS scheme, not Bearer.
        assert req.headers.get("Authorization") == "SSWS fake-okta-token", (
            req.headers.get("Authorization")
        )
        print("OK  health_check: /users/me + SSWS auth scheme")
    finally:
        await conn.aclose()


async def check_get_user_happy_path() -> None:
    fake = FakeOkta()
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}",
        status=200,
        body={
            "id": TEST_USER_ID,
            "status": "ACTIVE",
            "lastLogin": "2026-06-16T09:00:00.000Z",
            "profile": {
                "login": "alice@corp.com",
                "email": "alice@corp.com",
                "department": "Engineering",
                "managerId": "00u9MANAGERID00000000",
            },
        },
    )
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}/groups",
        status=200,
        body=[
            {"profile": {"name": "Everyone"}},
            {"profile": {"name": "engineering"}},
            {"profile": {}},  # no name -> filtered
            "not-a-dict",  # skipped
        ],
    )
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}/factors",
        status=200,
        body=[
            {"factorType": "push"},
            {"factorType": "webauthn"},
            {"factorType": ""},  # filtered (falsy)
        ],
    )
    fake.set(
        "GET",
        "/api/v1/logs",
        status=200,
        body=[
            {
                "published": "2026-06-17T12:00:00.456Z",
                "client": {
                    "ipAddress": "198.51.100.10",
                    "geographicalContext": {"country": "US"},
                },
                "securityContext": {
                    "asNumber": 15169,
                    "asOrg": "Google",
                    "riskLevel": "MEDIUM",
                },
            }
        ],
    )
    conn = _make_connector(fake=fake)
    try:
        result = await conn.get_user(user=TEST_USER_ID)

        # Profile core.
        assert result["user"] == TEST_USER_ID
        assert result["email"] == "alice@corp.com"
        assert result["department"] == "Engineering"
        assert result["manager"] == "00u9MANAGERID00000000"
        assert result["status"] == "ACTIVE"
        # Groups + factors with garbage rows filtered.
        assert result["groups"] == ["Everyone", "engineering"], result["groups"]
        assert result["mfa_factors"] == ["push", "webauthn"], result["mfa_factors"]
        # last_signin: log event timestamp overrode lastLogin; geo/ASN/risk all present.
        signin = result["last_signin"]
        assert signin["ts"] == "2026-06-17T12:00:00.456Z", signin
        assert signin["src_ip"] == "198.51.100.10", signin
        assert signin["country"] == "US", signin
        assert signin["asn"] == "AS15169 Google", signin
        assert signin["anomaly_score"] == 0.55, signin

        # /logs filter must scope to the user_id and session.start event.
        log_req = fake.request_for("GET", "/api/v1/logs")
        assert log_req is not None
        q = parse_qs(log_req.url.query)
        assert q.get("sortOrder") == ["DESCENDING"], q
        assert q.get("limit") == ["1"], q
        assert TEST_USER_ID in q["filter"][0], q
        assert "user.session.start" in q["filter"][0], q

        # Auth applied on every fan-out.
        for r in fake.requests:
            assert r.headers.get("Authorization") == "SSWS fake-okta-token"
        print("OK  get_user: profile + groups + factors + log event enrichment")
    finally:
        await conn.aclose()


async def check_get_user_login_form_encodes_path() -> None:
    """When called with a login (email), the URL must be percent-encoded.

    httpx normalizes ``request.url.path`` back to the decoded form, but
    ``raw_path`` (or ``str(request.url)``) preserves the wire form. We
    register under the decoded path for dispatch and assert on the raw
    bytes to prove the connector actually encoded.
    """
    fake = FakeOkta()
    encoded = _encode_path_id(TEST_LOGIN)
    # Register under the *decoded* path because httpx.URL.path is decoded.
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_LOGIN}",
        status=200,
        body={
            "id": TEST_USER_ID,
            "status": "ACTIVE",
            "profile": {"login": TEST_LOGIN, "email": TEST_LOGIN},
        },
    )
    fake.set("GET", f"/api/v1/users/{TEST_USER_ID}/groups", status=200, body=[])
    fake.set("GET", f"/api/v1/users/{TEST_USER_ID}/factors", status=200, body=[])
    fake.set("GET", "/api/v1/logs", status=200, body=[])

    conn = _make_connector(fake=fake)
    try:
        out = await conn.get_user(user=TEST_LOGIN)
        assert out["user"] == TEST_LOGIN
        first = fake.requests[0]
        # The raw_path (bytes) preserves the percent-encoded form put on the wire.
        raw = first.url.raw_path.decode("ascii")
        assert f"/api/v1/users/{encoded}" in raw, raw
        assert "%40" in raw, raw  # @ encoded
        print("OK  get_user: login form is percent-encoded on the wire")
    finally:
        await conn.aclose()


async def check_get_user_enrichment_degrades_gracefully() -> None:
    """Fan-out 5xxs must NOT fail the top-level get_user call."""
    fake = FakeOkta()
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}",
        status=200,
        body={
            "id": TEST_USER_ID,
            "status": "ACTIVE",
            "lastLogin": "2026-06-16T09:00:00.000Z",
            "profile": {"login": "alice@corp.com", "email": "alice@corp.com"},
        },
    )
    fake.set("GET", f"/api/v1/users/{TEST_USER_ID}/groups", status=500, body={
        "errorCode": "E0000009", "errorSummary": "internal"
    })
    fake.set("GET", f"/api/v1/users/{TEST_USER_ID}/factors", status=500, body={
        "errorCode": "E0000009", "errorSummary": "internal"
    })
    fake.set("GET", "/api/v1/logs", status=429, body={
        "errorCode": "E0000047", "errorSummary": "rate limit"
    })
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0  # don't retry the 5xxs in the test
    try:
        result = await conn.get_user(user=TEST_USER_ID)
        assert result["user"] == TEST_USER_ID
        assert result["status"] == "ACTIVE"
        # Enrichment failures: empty defaults preserved.
        assert result["groups"] == []
        assert result["mfa_factors"] == []
        # last_signin falls back to the lastLogin scalar.
        assert result["last_signin"] == {"ts": "2026-06-16T09:00:00.000Z"}, result
        print("OK  get_user: enrichment 5xx/429 degrades, profile still returned")
    finally:
        await conn.aclose()


async def check_get_user_not_found() -> None:
    fake = FakeOkta()
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}",
        status=404,
        body={
            "errorCode": "E0000007",
            "errorSummary": (
                f"Not found: Resource not found: {TEST_USER_ID} (User)"
            ),
        },
    )
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0
    try:
        try:
            await conn.get_user(user=TEST_USER_ID)
        except ConnectorError as e:
            assert "not found" in str(e).lower(), str(e)
            assert getattr(e, "status", None) == 404, e
            print("OK  get_user: E0000007 -> ConnectorError(status=404)")
        else:
            raise AssertionError("expected ConnectorError on E0000007")
    finally:
        await conn.aclose()


async def check_revoke_sessions_happy_path() -> None:
    fake = FakeOkta()
    sessions_listed: list[dict[str, Any]] = [
        {"id": "session-1"},
        {"id": "session-2"},
        {"id": "session-3"},
    ]
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}/sessions",
        status=200,
        body=sessions_listed,
    )
    fake.set(
        "DELETE",
        f"/api/v1/users/{TEST_USER_ID}/sessions",
        status=204,
        body=None,
    )
    conn = _make_connector(fake=fake)
    try:
        out = await conn.revoke_sessions(user=TEST_USER_ID)
        assert out["user"] == TEST_USER_ID
        assert out["sessions_revoked"] == 3, out
        assert out["ticket"].startswith("REVOKE-"), out

        # DELETE must include ``oauthTokens=true`` to flush OIDC too.
        del_req = fake.request_for(
            "DELETE", f"/api/v1/users/{TEST_USER_ID}/sessions"
        )
        assert del_req is not None
        q = parse_qs(del_req.url.query)
        assert q.get("oauthTokens") == ["true"], q

        # GET-then-DELETE pair, in that order.
        seen = fake.paths()
        get_idx = seen.index(
            f"GET /api/v1/users/{TEST_USER_ID}/sessions"
        )
        del_idx = seen.index(
            f"DELETE /api/v1/users/{TEST_USER_ID}/sessions"
        )
        assert get_idx < del_idx, seen
        print("OK  revoke_sessions: GET-then-DELETE + oauthTokens=true + pre-count")
    finally:
        await conn.aclose()


async def check_revoke_sessions_list_failure_does_not_block_delete() -> None:
    fake = FakeOkta()
    fake.set(
        "GET",
        f"/api/v1/users/{TEST_USER_ID}/sessions",
        status=403,
        body={"errorCode": "E0000006", "errorSummary": "forbidden"},
    )
    fake.set(
        "DELETE",
        f"/api/v1/users/{TEST_USER_ID}/sessions",
        status=204,
        body=None,
    )
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0
    try:
        out = await conn.revoke_sessions(user=TEST_USER_ID)
        # Count unknown -> 0; DELETE still happened.
        assert out["sessions_revoked"] == 0, out
        assert fake.request_for(
            "DELETE", f"/api/v1/users/{TEST_USER_ID}/sessions"
        ) is not None
        print("OK  revoke_sessions: GET 403 doesn't block the containment DELETE")
    finally:
        await conn.aclose()


async def check_disable_user_suspend_default() -> None:
    fake = FakeOkta()
    fake.set(
        "POST",
        f"/api/v1/users/{TEST_USER_ID}/lifecycle/suspend",
        status=200,
        body={},
    )
    conn = _make_connector(fake=fake)
    try:
        out = await conn.disable_user(user=TEST_USER_ID, reason="phishing")
        assert out["user"] == TEST_USER_ID
        assert out["disabled"] is True
        assert out["reason"] == "phishing"
        assert out["lifecycle"] == "suspend", out

        req = fake.request_for(
            "POST", f"/api/v1/users/{TEST_USER_ID}/lifecycle/suspend"
        )
        assert req is not None
        # Lifecycle endpoints take an empty body.
        assert req.content in (b"", b"null"), req.content
        print("OK  disable_user: suspend (default reversible lifecycle)")
    finally:
        await conn.aclose()


async def check_disable_user_deactivate_variant() -> None:
    fake = FakeOkta()
    fake.set(
        "POST",
        f"/api/v1/users/{TEST_USER_ID}/lifecycle/deactivate",
        status=200,
        body={},
    )
    conn = _make_connector(
        fake=fake,
        params={
            "base_url": OKTA_BASE,
            "disable_lifecycle": "deactivate",
        },
    )
    try:
        out = await conn.disable_user(
            user=TEST_USER_ID, reason="terminated employee"
        )
        assert out["lifecycle"] == "deactivate"
        assert fake.request_for(
            "POST", f"/api/v1/users/{TEST_USER_ID}/lifecycle/deactivate"
        ) is not None
        # And nothing was posted to /suspend.
        assert fake.request_for(
            "POST", f"/api/v1/users/{TEST_USER_ID}/lifecycle/suspend"
        ) is None
        print("OK  disable_user: deactivate variant via config opt-in")
    finally:
        await conn.aclose()


async def check_disable_user_idempotent_already_suspended() -> None:
    """E0000016 (already suspended) is treated as success — idempotent."""
    fake = FakeOkta()
    fake.set(
        "POST",
        f"/api/v1/users/{TEST_USER_ID}/lifecycle/suspend",
        status=400,
        body={
            "errorCode": "E0000016",
            "errorSummary": "Activation failed because user is already suspended",
        },
    )
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0
    try:
        out = await conn.disable_user(
            user=TEST_USER_ID, reason="already-contained"
        )
        assert out["disabled"] is True
        assert out["lifecycle"] == "suspend"
        print("OK  disable_user: E0000016 treated as idempotent success")
    finally:
        await conn.aclose()


async def check_disable_user_empty_reason_rejected() -> None:
    fake = FakeOkta()
    conn = _make_connector(fake=fake)
    try:
        for bad in ("", "   ", None, 42):
            try:
                await conn.disable_user(user=TEST_USER_ID, reason=bad)  # type: ignore[arg-type]
            except ConnectorError as e:
                assert "reason" in str(e), e
            else:
                raise AssertionError(
                    f"expected ConnectorError for reason={bad!r}"
                )
        # No HTTP traffic at all — validation runs before the network.
        assert fake.requests == [], fake.paths()
        print("OK  disable_user: empty reason rejected before any HTTP call")
    finally:
        await conn.aclose()


async def check_reset_password_happy_path() -> None:
    fake = FakeOkta()

    def _capture(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    fake.set_callable(
        "POST",
        f"/api/v1/users/{TEST_USER_ID}/lifecycle/reset_password",
        _capture,
    )
    conn = _make_connector(fake=fake)
    try:
        out = await conn.reset_password(user=TEST_USER_ID)
        assert out["user"] == TEST_USER_ID
        assert out["reset_email_sent"] is True
        assert out["ticket"].startswith("RESET-"), out
        # Never echo any reset URL into the tool envelope.
        assert "reset_url" not in out
        assert "resetPasswordUrl" not in out

        req = fake.request_for(
            "POST", f"/api/v1/users/{TEST_USER_ID}/lifecycle/reset_password"
        )
        assert req is not None
        q = parse_qs(req.url.query)
        assert q.get("sendEmail") == ["true"], q
        print("OK  reset_password: sendEmail=true + reset URL not leaked to LLM")
    finally:
        await conn.aclose()


async def check_auth_error_surfaced() -> None:
    """A 401 on any endpoint → ConnectorAuthError."""
    fake = FakeOkta()
    fake.force_status = 401
    fake.force_body = json.dumps(
        {"errorCode": "E0000011", "errorSummary": "Invalid token"}
    ).encode()
    conn = _make_connector(fake=fake)
    conn._http.max_retries = 0
    try:
        try:
            await conn.health_check()
        except ConnectorAuthError as e:
            assert "401" in str(e) or "auth" in str(e).lower() or "invalid" in str(e).lower(), str(e)
            print("OK  401 from Okta -> ConnectorAuthError")
        else:
            raise AssertionError("expected ConnectorAuthError on 401")
    finally:
        await conn.aclose()


# ─── runner ──────────────────────────────────────────────────────────────


async def _main() -> None:
    # Sync checks first (cheap, fail-fast).
    check_factory_registered()
    check_required_params_rejected()
    check_missing_api_token_rejected()
    check_identifier_hygiene()
    check_path_encoding()
    check_ticket_generation()
    check_risk_score_mapping()
    check_signin_extractor_shapes()

    # Async checks.
    await check_health_check_happy_path()
    await check_get_user_happy_path()
    await check_get_user_login_form_encodes_path()
    await check_get_user_enrichment_degrades_gracefully()
    await check_get_user_not_found()
    await check_revoke_sessions_happy_path()
    await check_revoke_sessions_list_failure_does_not_block_delete()
    await check_disable_user_suspend_default()
    await check_disable_user_deactivate_variant()
    await check_disable_user_idempotent_already_suspended()
    await check_disable_user_empty_reason_rejected()
    await check_reset_password_happy_path()
    await check_auth_error_surfaced()

    print("\nALL OKTA CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
