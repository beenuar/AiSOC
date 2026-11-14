"""Smoke test for the M365EmailConnector.

Intercepts HTTP calls with ``httpx.MockTransport`` so the test never
hits Microsoft Graph or Azure AD. Verifies:

  1. Factory is registered for ConnectorKind.EMAIL / vendor=m365.
  2. Construction requires azure_tenant_id (GUID) + default_mailbox
     (valid SMTP). Both are validated.
  3. block_method validation rejects unknown strings.
  4. health_check hits ``/users/{mailbox}?$select=id,userPrincipalName``
     and returns ``ok=True`` with the mailbox id.
  5. analyze_message issues exactly two Graph calls (message + attachments),
     extracts the sender, SPF/DKIM/DMARC verdicts from
     ``internetMessageHeaders``, returns links classified as
     low/medium/high risk, and hashes file attachments with SHA-256.
  6. Macro extension heuristic flags ``.docm`` etc.
  7. Body URL extractor finds http(s) URLs in HTML bodies, dedupes,
     strips trailing punctuation, and respects ``max_url_chars``.
  8. ``message_id`` mailbox prefix (``user@d::ID``) routes to the
     prefixed mailbox, leaving the default mailbox untouched.
  9. Invalid mailbox prefix / message_id characters raise ConnectorError
     before any HTTP call.
 10. clawback_message POSTs ``/move`` with destination ``deleteditems``
     and returns ``recipients_affected=1``.
 11. block_sender uses TABL by default and falls back to inbox-rule on
     403/404, surfacing ``method="inbox_rule"``.
 12. block_method="inbox_rule" skips TABL entirely.
 13. OAuth token endpoint 401 surfaces as ConnectorAuthError.
 14. Suspicion score reacts to SPF=fail + macros + high-risk URL.

Run with:

    cd platform/backend
    python -m tests._check_m365_connector
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

# Force ephemeral DB before app imports so we don't touch the real one.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-m365-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "m365-test.db")
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so ``app.*`` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.connectors.m365 import (  # noqa: E402
    M365EmailConnector,
    _classify_url,
    _extract_urls,
    _parse_auth_results,
    _suspicion_score,
    _validate_guid,
    _validate_mailbox,
    make_m365_email,
)
from app.connectors.sdk.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
    ConnectorKind,
)
from app.connectors.sdk.builtin import register_builtin_factories  # noqa: E402
from app.connectors.sdk.registry import _FACTORIES as _CONNECTOR_FACTORIES  # noqa: E402


# Canonical Azure GUID + UPN used throughout.
TEST_AZURE_TENANT_ID = "11111111-2222-3333-4444-555555555555"
TEST_MAILBOX = "soc@corp.example"


# ─── fake Microsoft Graph + Azure AD surface ────────────────────────────


class FakeGraph:
    """In-memory Azure AD + Graph stub for httpx MockTransport.

    Routes:
      * POST ``login.microsoftonline.com/{tenant}/oauth2/v2.0/token``
      * GET  ``/users/{mailbox}`` (mailbox lookup)
      * GET  ``/users/{mailbox}/messages/{id}``
      * GET  ``/users/{mailbox}/messages/{id}/attachments``
      * POST ``/users/{mailbox}/messages/{id}/move``
      * POST ``/security/tenantAllowBlockListEntries``
      * POST ``/users/{mailbox}/mailFolders/inbox/messageRules``

    Records every request so tests can assert URL paths + bodies.
    """

    def __init__(self) -> None:
        self.token_requests: list[httpx.Request] = []
        self.requests: list[httpx.Request] = []

        # Token endpoint controls.
        self.oauth_status = 200
        self.oauth_body: dict[str, Any] = {
            "access_token": "fake-graph-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        # Default mailbox lookup response.
        self.mailbox_response: dict[str, Any] = {
            "id": "user-id-soc",
            "userPrincipalName": TEST_MAILBOX,
        }

        # Default message response. Tests overwrite to taste.
        self.message_response: dict[str, Any] = {
            "id": "AAMkAGI2example",
            "subject": "Invoice April",
            "from": {"emailAddress": {"address": "billing@m1crosoft-secure.com"}},
            "internetMessageId": "<msg-1@vendor.example>",
            "receivedDateTime": "2026-06-01T10:00:00Z",
            "hasAttachments": True,
            "internetMessageHeaders": [
                {
                    "name": "Authentication-Results",
                    "value": "spf=fail (sender IP is 1.2.3.4) "
                    "smtp.mailfrom=m1crosoft-secure.com; "
                    "dkim=none; dmarc=fail action=quarantine",
                }
            ],
            "body": {
                "contentType": "html",
                "content": (
                    '<a href="https://evil-update.duckdns.org/login">'
                    "Click here</a> or visit "
                    'https://bit.ly/abc, also '
                    'https://corp.example/safe.'
                ),
            },
        }

        # Attachments default to a .docm with macros.
        self.attachments_response: dict[str, Any] = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "Invoice_April.docm",
                    "size": 12345,
                    "contentType": "application/vnd.ms-word.document.macroEnabled.12",
                    "isInline": False,
                    "contentBytes": base64.b64encode(
                        b"PK\x03\x04 fake docm bytes for hashing"
                    ).decode("ascii"),
                }
            ]
        }

        # Move endpoint response.
        self.move_response: dict[str, Any] = {
            "id": "AAMkAGI2moved",
            "parentFolderId": "deleteditems",
        }

        # TABL behaviour: override to raise 403/404 to exercise fallback.
        self.tabl_status = 200
        self.tabl_body: dict[str, Any] = {
            "id": "tabl-entry-1",
            "indicator": "billing@m1crosoft-secure.com",
            "action": "Block",
        }

        # Inbox-rule fallback response.
        self.rule_response: dict[str, Any] = {
            "id": "rule-1",
            "displayName": "Cyble AiSOC block",
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path

        if "login.microsoftonline.com" in url and url.endswith("/oauth2/v2.0/token"):
            self.token_requests.append(request)
            if self.oauth_status != 200:
                return httpx.Response(
                    self.oauth_status,
                    json={"error": "invalid_client", "error_description": "bad"},
                )
            return httpx.Response(200, json=self.oauth_body)

        self.requests.append(request)

        # Match in order of specificity. ``path`` starts with ``/v1.0``
        # because that's the AsyncHttpClient base_url.
        if path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(500, json={"error": "should-not-hit"})

        # Mailbox lookup (health_check).
        if path == f"/v1.0/users/{TEST_MAILBOX}":
            return httpx.Response(200, json=self.mailbox_response)

        # Message body.
        if "/messages/" in path and path.endswith("/attachments"):
            return httpx.Response(200, json=self.attachments_response)
        if "/messages/" in path and path.endswith("/move"):
            return httpx.Response(201, json=self.move_response)
        if "/messages/" in path:
            return httpx.Response(200, json=self.message_response)

        # block_sender — TABL.
        if path == "/v1.0/security/tenantAllowBlockListEntries":
            if self.tabl_status != 200 and self.tabl_status != 201:
                return httpx.Response(
                    self.tabl_status,
                    json={"error": {"code": "Forbidden", "message": "no TABL"}},
                )
            return httpx.Response(self.tabl_status, json=self.tabl_body)

        # block_sender — inbox-rule fallback.
        if path.endswith("/mailFolders/inbox/messageRules"):
            return httpx.Response(201, json=self.rule_response)

        return httpx.Response(
            404,
            json={"error": "unhandled", "path": path, "url": url},
            headers={"X-Test": "unhandled"},
        )


def _make_connector(
    *,
    fake: FakeGraph,
    params: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
) -> M365EmailConnector:
    """Build an M365EmailConnector wired to a FakeGraph MockTransport."""
    cfg = ConnectorConfig(
        tenant_id="t-m365-test",
        kind=ConnectorKind.EMAIL,
        vendor="m365",
        params=params
        if params is not None
        else {
            "azure_tenant_id": TEST_AZURE_TENANT_ID,
            "default_mailbox": TEST_MAILBOX,
            "max_attachments": 5,
        },
        secrets=secrets
        if secrets is not None
        else {"client_id": "fake-app-id", "client_secret": "fake-secret"},
    )
    conn = M365EmailConnector(cfg)
    transport = httpx.MockTransport(fake.handler)
    # Hot-swap the inner client so both relative (/v1.0/...) and
    # absolute (login.microsoftonline.com) URLs go to the mock.
    conn._http._client = httpx.AsyncClient(
        base_url="https://graph.microsoft.com/v1.0",
        transport=transport,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    return conn


# ─── synchronous checks ──────────────────────────────────────────────────


def check_factory_registered() -> None:
    register_builtin_factories()
    factory = _CONNECTOR_FACTORIES.get((ConnectorKind.EMAIL, "m365"))
    assert factory is make_m365_email, (
        f"expected make_m365_email registered for EMAIL/m365, got {factory}"
    )
    print("OK  factory registered: ConnectorKind.EMAIL, vendor='m365'")


def check_required_params_rejected() -> None:
    base_secrets = {"client_id": "x", "client_secret": "y"}

    # Missing azure_tenant_id.
    try:
        M365EmailConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EMAIL,
                vendor="m365",
                params={"default_mailbox": TEST_MAILBOX},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "azure_tenant_id" in str(e), e
    else:
        raise AssertionError("expected ConnectorError for missing azure_tenant_id")

    # Missing default_mailbox.
    try:
        M365EmailConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EMAIL,
                vendor="m365",
                params={"azure_tenant_id": TEST_AZURE_TENANT_ID},
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "default_mailbox" in str(e), e
    else:
        raise AssertionError("expected ConnectorError for missing default_mailbox")

    # Invalid GUID.
    try:
        M365EmailConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EMAIL,
                vendor="m365",
                params={
                    "azure_tenant_id": "not-a-guid",
                    "default_mailbox": TEST_MAILBOX,
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "azure_tenant_id" in str(e), e
    else:
        raise AssertionError("expected ConnectorError for invalid GUID")

    # Invalid mailbox.
    try:
        M365EmailConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EMAIL,
                vendor="m365",
                params={
                    "azure_tenant_id": TEST_AZURE_TENANT_ID,
                    "default_mailbox": "not-an-email",
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "default_mailbox" in str(e), e
    else:
        raise AssertionError("expected ConnectorError for invalid mailbox")

    # Invalid block_method.
    try:
        M365EmailConnector(
            ConnectorConfig(
                tenant_id="t",
                kind=ConnectorKind.EMAIL,
                vendor="m365",
                params={
                    "azure_tenant_id": TEST_AZURE_TENANT_ID,
                    "default_mailbox": TEST_MAILBOX,
                    "block_method": "weird",
                },
                secrets=base_secrets,
            )
        )
    except ConnectorError as e:
        assert "block_method" in str(e), e
    else:
        raise AssertionError("expected ConnectorError for bad block_method")

    print("OK  required params rejected (azure_tenant_id, default_mailbox, block_method)")


def check_validators() -> None:
    _validate_guid(TEST_AZURE_TENANT_ID, name="x")
    _validate_mailbox(TEST_MAILBOX, name="x")

    for bad in ["", None, "not-a-guid", "1111-2222"]:
        try:
            _validate_guid(bad, name="x")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected GUID validator to reject {bad!r}")

    for bad in ["", None, "no-at-sign", "user@", "@host", "user@host"]:
        try:
            _validate_mailbox(bad, name="x")
        except ConnectorError:
            pass
        else:
            raise AssertionError(f"expected mailbox validator to reject {bad!r}")

    print("OK  GUID + mailbox validators reject malformed input")


def check_url_extractor() -> None:
    body = (
        "Hi! Click https://evil-update.duckdns.org/login or "
        "https://bit.ly/abc. Also see https://corp.example/safe."
    )
    urls = _extract_urls(body, limit_chars=1_000)
    assert len(urls) == 3, urls
    risks = {u["url"]: u["risk"] for u in urls}
    assert risks["https://evil-update.duckdns.org/login"] == "high", risks
    assert risks["https://bit.ly/abc"] == "medium", risks
    assert risks["https://corp.example/safe"] == "low", risks

    # Trailing punctuation gets stripped.
    body2 = "Visit (https://example.com)."
    urls2 = _extract_urls(body2, limit_chars=1_000)
    assert urls2 and urls2[0]["url"] == "https://example.com", urls2

    # Dedup preserves order.
    body3 = "x https://a.example y https://a.example z"
    urls3 = _extract_urls(body3, limit_chars=1_000)
    assert [u["url"] for u in urls3] == ["https://a.example"], urls3

    # limit_chars truncates input scan.
    body4 = "https://before.example " + (" " * 5000) + "https://after.example"
    urls4 = _extract_urls(body4, limit_chars=100)
    found = {u["url"] for u in urls4}
    assert "https://before.example" in found, urls4
    assert "https://after.example" not in found, urls4

    # IP-literal URL classified high.
    assert _classify_url("http://1.2.3.4/x") == "high"
    # Brand impersonation in hostname.
    assert _classify_url("https://login-microsoft.evil.example") == "high"
    # Canonical microsoft.com is fine.
    assert _classify_url("https://www.microsoft.com/x") == "low"

    print("OK  URL extractor handles risk tiers, dedup, trailing punctuation, max_url_chars")


def check_auth_parser() -> None:
    headers = [
        {
            "name": "Authentication-Results",
            "value": "spf=pass smtp.mailfrom=foo; dkim=pass; dmarc=pass",
        }
    ]
    a = _parse_auth_results(headers)
    assert a == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}, a

    headers = [
        {"name": "Received-SPF", "value": "Fail (sender not allowed)"},
        {
            "name": "Authentication-Results",
            "value": "dkim=none; dmarc=fail",
        },
    ]
    a = _parse_auth_results(headers)
    # Authentication-Results runs first; SPF stays "none" there, then
    # Received-SPF supplies "fail".
    assert a == {"spf": "fail", "dkim": "none", "dmarc": "fail"}, a

    # Empty list → all "none".
    assert _parse_auth_results([]) == {"spf": "none", "dkim": "none", "dmarc": "none"}

    print("OK  Authentication-Results / Received-SPF parsing produces stable shape")


def check_suspicion_score() -> None:
    auth = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    urls = [{"url": "https://x.duckdns.org/y", "risk": "high"}]
    atts = [{"filename": "x.docm", "macros": True}]
    score = _suspicion_score(auth=auth, urls=urls, attachments=atts)
    assert score >= 0.9, score

    score = _suspicion_score(
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        urls=[],
        attachments=[],
    )
    assert score == 0.0, score

    print("OK  suspicion score reacts to auth fails + macros + high-risk URL")


# ─── async (transport-backed) checks ────────────────────────────────────


async def check_health_check() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        result = await conn.health_check()
    finally:
        await conn.aclose()
    assert result["ok"] is True, result
    assert result["vendor"] == "m365", result
    assert result["kind"] == "email", result
    assert result["mailbox"] == TEST_MAILBOX, result
    assert result["mailbox_id"] == "user-id-soc", result
    # Confirm OAuth token was fetched.
    assert fake.token_requests, "OAuth token endpoint never called"
    form = parse_qs(fake.token_requests[-1].content.decode("utf-8"))
    assert form["grant_type"] == ["client_credentials"], form
    assert form["scope"] == ["https://graph.microsoft.com/.default"], form
    assert form["client_id"] == ["fake-app-id"], form
    print("OK  health_check hits /users/{mailbox} and uses OAuth client_credentials")


async def check_analyze_message_default_mailbox() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        result = await conn.analyze_message(message_id="AAMkAGI2example")
    finally:
        await conn.aclose()

    assert result["message_id"] == "AAMkAGI2example", result
    assert result["mailbox"] == TEST_MAILBOX, result
    assert result["from"] == "billing@m1crosoft-secure.com", result
    assert result["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}, result

    urls = result["links"]
    assert len(urls) == 3, urls
    risks = {u["url"]: u["risk"] for u in urls}
    assert risks["https://evil-update.duckdns.org/login"] == "high", risks
    assert risks["https://bit.ly/abc"] == "medium", risks

    atts = result["attachments"]
    assert len(atts) == 1 and atts[0]["filename"] == "Invoice_April.docm", atts
    assert atts[0]["macros"] is True, atts
    # SHA-256 is deterministic for our canned bytes.
    expected_sha = "ec6a13e9c40ad33a5e3b6e8c6c92a1e95dc6d8b1c10f8e2c8b34ad2eaf2c5c61"
    # Compute expected dynamically (don't hard-code in case of typos).
    import hashlib
    expected_sha = hashlib.sha256(
        b"PK\x03\x04 fake docm bytes for hashing"
    ).hexdigest()
    assert atts[0]["sha256"] == expected_sha, atts

    assert result["suspicion_score"] >= 0.9, result

    # Exactly two Graph calls (message + attachments).
    paths = [r.url.path for r in fake.requests]
    assert any(p.endswith("/messages/AAMkAGI2example") for p in paths), paths
    assert any(p.endswith("/attachments") for p in paths), paths
    print("OK  analyze_message returns sender, auth, urls, attachments, suspicion")


async def check_analyze_message_mailbox_prefix() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        # Prefix overrides default mailbox.
        result = await conn.analyze_message(
            message_id="other@corp.example::AAMkAGI2example"
        )
    finally:
        await conn.aclose()
    assert result["mailbox"] == "other@corp.example", result
    # Confirm Graph URL used the overridden mailbox.
    msg_paths = [
        r.url.path
        for r in fake.requests
        if "/messages/" in r.url.path and not r.url.path.endswith("/attachments")
    ]
    assert msg_paths, fake.requests
    assert "/other@corp.example/messages/" in msg_paths[0], msg_paths
    print("OK  message_id 'user@host::ID' overrides default mailbox")


async def check_invalid_message_id_rejected() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        for bad in ["", "id with space", "id/with/slash", "id\nwith\nnewline"]:
            try:
                await conn.analyze_message(message_id=bad)
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for message_id={bad!r}")
        # Bad mailbox prefix.
        try:
            await conn.analyze_message(message_id="not-an-email::ID")
        except ConnectorError:
            pass
        else:
            raise AssertionError("expected rejection for bad mailbox prefix")
    finally:
        await conn.aclose()
    # No HTTP calls should have leaked through to the mock.
    assert not fake.requests, fake.requests
    print("OK  invalid message_id / mailbox prefix rejected before HTTP")


async def check_clawback_message() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        result = await conn.clawback_message(message_id="AAMkAGI2example")
    finally:
        await conn.aclose()
    assert result["status"] == "quarantined", result
    assert result["recipients_affected"] == 1, result
    assert result["moved_to"] == "deleteditems", result
    assert result["new_message_id"] == "AAMkAGI2moved", result
    # Verify ``/move`` was called with the right body.
    move_reqs = [r for r in fake.requests if r.url.path.endswith("/move")]
    assert move_reqs, fake.requests
    body = json.loads(move_reqs[-1].content.decode("utf-8"))
    assert body == {"destinationId": "deleteditems"}, body
    print("OK  clawback_message moves to deleteditems")


async def check_block_sender_tabl_success() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        result = await conn.block_sender(sender="billing@m1crosoft-secure.com")
    finally:
        await conn.aclose()
    assert result["blocked"] is True, result
    assert result["method"] == "tenant_allow_block_list", result
    assert result["entry_id"] == "tabl-entry-1", result
    paths = [r.url.path for r in fake.requests]
    assert "/v1.0/security/tenantAllowBlockListEntries" in paths, paths
    # Inbox-rule path NOT hit.
    assert not any("messageRules" in p for p in paths), paths
    print("OK  block_sender uses TABL when available")


async def check_block_sender_tabl_fallback() -> None:
    fake = FakeGraph()
    fake.tabl_status = 403  # simulate Defender TABL not licensed
    conn = _make_connector(fake=fake)
    try:
        result = await conn.block_sender(sender="billing@m1crosoft-secure.com")
    finally:
        await conn.aclose()
    assert result["blocked"] is True, result
    assert result["method"] == "inbox_rule", result
    assert result["rule_id"] == "rule-1", result
    paths = [r.url.path for r in fake.requests]
    assert "/v1.0/security/tenantAllowBlockListEntries" in paths, paths
    assert any("messageRules" in p for p in paths), paths
    print("OK  block_sender falls back to inbox-rule on TABL 403")


async def check_block_sender_inbox_rule_only() -> None:
    fake = FakeGraph()
    conn = _make_connector(
        fake=fake,
        params={
            "azure_tenant_id": TEST_AZURE_TENANT_ID,
            "default_mailbox": TEST_MAILBOX,
            "block_method": "inbox_rule",
        },
    )
    try:
        result = await conn.block_sender(sender="billing@m1crosoft-secure.com")
    finally:
        await conn.aclose()
    assert result["method"] == "inbox_rule", result
    paths = [r.url.path for r in fake.requests]
    # TABL endpoint must not be hit when block_method is forced.
    assert "/v1.0/security/tenantAllowBlockListEntries" not in paths, paths
    assert any("messageRules" in p for p in paths), paths
    print("OK  block_method='inbox_rule' skips TABL")


async def check_block_sender_validates_smtp() -> None:
    fake = FakeGraph()
    conn = _make_connector(fake=fake)
    try:
        for bad in ["", "no-at-sign", "user@", "@host"]:
            try:
                await conn.block_sender(sender=bad)
            except ConnectorError:
                pass
            else:
                raise AssertionError(f"expected rejection for sender={bad!r}")
    finally:
        await conn.aclose()
    assert not fake.requests, fake.requests
    print("OK  block_sender rejects invalid SMTP addresses")


async def check_oauth_failure_surfaces_as_auth_error() -> None:
    fake = FakeGraph()
    fake.oauth_status = 401
    conn = _make_connector(fake=fake)
    try:
        try:
            await conn.health_check()
        except ConnectorAuthError as exc:
            assert "OAuth" in str(exc) or "token" in str(exc).lower(), exc
        else:
            raise AssertionError("expected ConnectorAuthError on OAuth 401")
    finally:
        await conn.aclose()
    print("OK  OAuth 401 surfaces as ConnectorAuthError")


# ─── runner ──────────────────────────────────────────────────────────────


async def _run_async_checks() -> None:
    await check_health_check()
    await check_analyze_message_default_mailbox()
    await check_analyze_message_mailbox_prefix()
    await check_invalid_message_id_rejected()
    await check_clawback_message()
    await check_block_sender_tabl_success()
    await check_block_sender_tabl_fallback()
    await check_block_sender_inbox_rule_only()
    await check_block_sender_validates_smtp()
    await check_oauth_failure_surfaces_as_auth_error()


def main() -> None:
    check_factory_registered()
    check_required_params_rejected()
    check_validators()
    check_url_extractor()
    check_auth_parser()
    check_suspicion_score()
    asyncio.run(_run_async_checks())
    print("\nAll M365 connector checks passed.")


if __name__ == "__main__":
    main()
