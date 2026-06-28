"""
Phase 3.4 wire-shape tests for the new IdP clients.

These mock httpx with respx so they don't touch Microsoft Graph or
Google's token endpoint. The point is: when AiSOC fires a verb,
does the Graph / Directory request payload look exactly like the
vendor docs say it should? If those shapes silently drift on
upgrade, an SRE finds out at 3am during an incident — these tests
catch it on PR.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx
from app.clients.azure_entra_client import AzureEntraClient
from app.clients.google_workspace_client import GoogleWorkspaceClient

# --------------------------- Entra ---------------------------


def _add_entra_token_route(mock: respx.MockRouter) -> respx.Route:
    return mock.post("https://login.microsoftonline.com/tenant-uuid/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "entra-token", "expires_in": 3600})
    )


@pytest.mark.asyncio
async def test_entra_disable_user_patches_account_enabled_false() -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        patch = mock.patch("https://graph.microsoft.com/v1.0/users/alice@corp.com").mock(return_value=httpx.Response(204))

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        result = await client.disable_user("alice@corp.com")

        assert result["success"] is True
        assert result["action"] == "disable_user"
        body = json.loads(patch.calls[0].request.content)
        assert body == {"accountEnabled": False}
        assert patch.calls[0].request.headers["Authorization"] == "Bearer entra-token"


@pytest.mark.asyncio
async def test_entra_enable_user_patches_account_enabled_true() -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        patch = mock.patch("https://graph.microsoft.com/v1.0/users/alice@corp.com").mock(return_value=httpx.Response(204))

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        result = await client.enable_user("alice@corp.com")

        assert result["success"] is True
        body = json.loads(patch.calls[0].request.content)
        assert body == {"accountEnabled": True}


@pytest.mark.asyncio
async def test_entra_revoke_sessions_posts_to_revoke_endpoint() -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        revoke = mock.post("https://graph.microsoft.com/v1.0/users/alice@corp.com/revokeSignInSessions").mock(
            return_value=httpx.Response(200, json={"value": True})
        )

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        result = await client.revoke_sessions("alice@corp.com")

        assert result["success"] is True
        assert result["value"] is True
        assert revoke.called


@pytest.mark.asyncio
async def test_entra_reset_password_does_not_leak_temp_password_in_output() -> None:
    """The temp password we generate must never be reflected back
    to the caller — playbook timelines are an attractive target for
    secondary attackers."""
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        patch = mock.patch("https://graph.microsoft.com/v1.0/users/alice@corp.com").mock(return_value=httpx.Response(204))

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        result = await client.reset_password("alice@corp.com")

        # The wire request must carry the password, but the
        # response object we return upstream must not.
        body = json.loads(patch.calls[0].request.content)
        assert body["passwordProfile"]["forceChangePasswordNextSignIn"] is True
        assert "password" in body["passwordProfile"]
        assert "password" not in result
        assert "temp_password" not in result


@pytest.mark.asyncio
async def test_entra_require_mfa_uses_beta_strong_auth_endpoint() -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        patch = mock.patch("https://graph.microsoft.com/beta/users/alice@corp.com").mock(return_value=httpx.Response(204))

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        result = await client.require_mfa("alice@corp.com")

        assert result["success"] is True
        body = json.loads(patch.calls[0].request.content)
        assert body["strongAuthenticationRequirements"][0]["state"] == "enforced"


@pytest.mark.asyncio
async def test_entra_raises_on_graph_error() -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_entra_token_route(mock)
        mock.patch("https://graph.microsoft.com/v1.0/users/alice@corp.com").mock(
            return_value=httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}})
        )

        client = AzureEntraClient(tenant_id="tenant-uuid", client_id="cid", client_secret="csec")
        with pytest.raises(httpx.HTTPStatusError):
            await client.disable_user("alice@corp.com")


# --------------------------- Google Workspace ---------------------------


# Minimal RSA key for JWT signing in tests. Generated once with
#   openssl genrsa 2048
# and pinned here. This is a throwaway key — never used outside
# the test process.
_FAKE_SERVICE_ACCOUNT = {
    "type": "service_account",
    "client_email": "aisoc@aisoc-test.iam.gserviceaccount.com",
    "private_key_id": "fakekey-id",
    # The private_key is the only field that matters at runtime
    # because we sign a JWT with it. We import it lazily below
    # rather than committing it inline.
    "private_key": None,
}


@pytest.fixture(scope="module")
def gws_service_account() -> dict:
    """Generate a one-shot RSA key the test JWT path can sign with."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    sa = dict(_FAKE_SERVICE_ACCOUNT)
    sa["private_key"] = pem
    return sa


def _add_gws_token_route(mock: respx.MockRouter) -> respx.Route:
    return mock.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "gws-token", "expires_in": 3600})
    )


@pytest.mark.asyncio
async def test_gws_suspend_user_patches_suspended_true(gws_service_account: dict) -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_gws_token_route(mock)
        patch = mock.patch("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com").mock(
            return_value=httpx.Response(200, json={"primaryEmail": "bob@corp.com", "suspended": True})
        )

        client = GoogleWorkspaceClient(
            service_account_key=gws_service_account,
            subject_email="admin@corp.com",
        )
        result = await client.suspend_user("bob@corp.com")

        assert result["success"] is True
        body = json.loads(patch.calls[0].request.content)
        assert body == {"suspended": True}
        assert patch.calls[0].request.headers["Authorization"] == "Bearer gws-token"


@pytest.mark.asyncio
async def test_gws_revoke_sessions_posts_signout(gws_service_account: dict) -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_gws_token_route(mock)
        signout = mock.post("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com/signOut").mock(
            return_value=httpx.Response(204)
        )

        client = GoogleWorkspaceClient(
            service_account_key=gws_service_account,
            subject_email="admin@corp.com",
        )
        result = await client.revoke_sessions("bob@corp.com")

        assert result["success"] is True
        assert result["action"] == "revoke_sessions"
        assert signout.called


@pytest.mark.asyncio
async def test_gws_reset_password_does_not_leak_temp_password(gws_service_account: dict) -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_gws_token_route(mock)
        patch = mock.patch("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com").mock(
            return_value=httpx.Response(200, json={"primaryEmail": "bob@corp.com"})
        )

        client = GoogleWorkspaceClient(
            service_account_key=gws_service_account,
            subject_email="admin@corp.com",
        )
        result = await client.reset_password("bob@corp.com")

        body = json.loads(patch.calls[0].request.content)
        assert body["changePasswordAtNextLogin"] is True
        assert "password" in body
        assert "password" not in result
        assert "temp_password" not in result


@pytest.mark.asyncio
async def test_gws_enforce_2sv_patches_flag(gws_service_account: dict) -> None:
    with respx.mock(assert_all_called=True) as mock:
        _add_gws_token_route(mock)
        patch = mock.patch("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com").mock(
            return_value=httpx.Response(200, json={})
        )

        client = GoogleWorkspaceClient(
            service_account_key=gws_service_account,
            subject_email="admin@corp.com",
        )
        result = await client.enforce_2sv("bob@corp.com")

        assert result["success"] is True
        body = json.loads(patch.calls[0].request.content)
        assert body == {"enforced2Sv": True}


@pytest.mark.asyncio
async def test_gws_service_account_key_accepts_json_string(gws_service_account: dict) -> None:
    """Operators may pass the key as a JSON string (e.g. from a
    sealed secret env var) rather than a dict — both must work."""
    with respx.mock(assert_all_called=True) as mock:
        _add_gws_token_route(mock)
        mock.patch("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com").mock(return_value=httpx.Response(200, json={}))

        client = GoogleWorkspaceClient(
            service_account_key=json.dumps(gws_service_account),
            subject_email="admin@corp.com",
        )
        result = await client.suspend_user("bob@corp.com")
        assert result["success"] is True


@pytest.mark.asyncio
async def test_gws_token_signing_jwt_carries_subject_email(gws_service_account: dict) -> None:
    """The JWT we send to the token endpoint must impersonate the
    configured admin via the `sub` claim — that's what unlocks
    domain-wide-delegation."""
    captured: dict = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        # The JWT is the `assertion` form field.
        body = request.content.decode()
        # querystring-encoded body, but we just want the assertion.
        for kv in body.split("&"):
            if kv.startswith("assertion="):
                jwt_token = kv.split("=", 1)[1]
                _, claims_b64, _ = jwt_token.split(".")
                claims_b64 += "=" * (-len(claims_b64) % 4)
                captured["claims"] = json.loads(base64.urlsafe_b64decode(claims_b64))
                break
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})

    with respx.mock(assert_all_called=True) as mock:
        mock.post("https://oauth2.googleapis.com/token").mock(side_effect=_capture)
        mock.patch("https://admin.googleapis.com/admin/directory/v1/users/bob@corp.com").mock(return_value=httpx.Response(200, json={}))

        client = GoogleWorkspaceClient(
            service_account_key=gws_service_account,
            subject_email="admin@corp.com",
        )
        await client.suspend_user("bob@corp.com")

    assert captured["claims"]["sub"] == "admin@corp.com"
    assert captured["claims"]["iss"] == "aisoc@aisoc-test.iam.gserviceaccount.com"
    assert "admin.directory.user" in captured["claims"]["scope"]
