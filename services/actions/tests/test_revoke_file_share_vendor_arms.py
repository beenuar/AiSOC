"""`revoke_file_share` reaches the vendor it names, verifies, and rolls back.

What this closes
---------------------------------------------------
A leaked document's blast radius is its sharing grants, and the product had
no verb for them: no executor touched Drive, OneDrive/SharePoint, Box or
Dropbox permissions at all. This file pins the three properties the new
capability's contract declares, per vendor, against mock vendor servers
driven through the real clients:

* **Prior grants are captured before the write** — the executor's first
  request is the listing, and ``rollback_data`` carries exactly what the
  pre-write listing returned.
* **The write is verified by read-back** — a vendor that answers 2xx on the
  DELETE but still lists the grant afterwards FAILS the action naming what
  it still sees, because a 2xx is the vendor accepting the request, not the
  estate changing.
* **Rollback restores the captured grants** and returns ``False`` when the
  vendor refuses; a re-created sharing link on Graph/Box/Dropbox is a new
  URL (vendor fact) and the restore happens through the link-creation call,
  never through a pretended un-revoke.
* ``dry_run`` through the builtin adapter strips credentials, so the mock
  vendor sees **zero requests**.
* The independent post-action probe answers gone/present/unverifiable
  honestly.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest
from app.executors.fileshare import RevokeFileShareExecutor
from app.live_actions.builtins import (
    BoxRevokeFileShare,
    DropboxRevokeFileShare,
    GoogleDriveRevokeFileShare,
    M365RevokeFileShare,
)
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.models.action import ActionRequest, ActionStatus, ActionType
from app.services.verification import _probe_revoke_file_share

FILE = "file-123"


def _request(params: dict[str, Any]) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.REVOKE_FILE_SHARE,
        target=FILE,
        parameters=params,
        requested_by="tester",
        rationale="",
    )


# ---------------------------------------------------------------------------
# Google Drive
# ---------------------------------------------------------------------------


class _DriveVendor:
    """Drive v3 permissions, stateful; `frozen=True` simulates the lying
    vendor whose DELETE answers 204 and deletes nothing."""

    def __init__(self, *, frozen: bool = False) -> None:
        self.permissions: dict[str, dict[str, Any]] = {
            "p-owner": {"id": "p-owner", "type": "user", "role": "owner", "emailAddress": "owner@example.com"},
            "p-mallory": {"id": "p-mallory", "type": "user", "role": "writer", "emailAddress": "mallory@example.com"},
            "p-anyone": {"id": "p-anyone", "type": "anyone", "role": "reader"},
        }
        self.frozen = frozen
        self.requests: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url.path}")
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        if request.method == "GET" and path.endswith("/permissions"):
            return httpx.Response(200, json={"permissions": list(self.permissions.values())})
        if request.method == "DELETE" and "/permissions/" in path:
            perm_id = path.rsplit("/", 1)[-1]
            if not self.frozen:
                self.permissions.pop(perm_id, None)
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/permissions"):
            import json as _json

            body = _json.loads(request.content)
            new_id = f"p-restored-{len(self.permissions)}"
            self.permissions[new_id] = {"id": new_id, **body}
            return httpx.Response(200, json=self.permissions[new_id])
        return httpx.Response(404, json={"error": path})


@pytest.fixture(scope="module")
def sa_key() -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return {"client_email": "svc@example.iam.gserviceaccount.com", "private_key": pem}


def _drive_params(vendor: _DriveVendor, sa_key: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "gws_service_account_key": sa_key,
        "gws_subject_email": "admin@example.com",
        "_transport": httpx.MockTransport(vendor.handle),
        **extra,
    }


class TestGoogleDriveArm:
    @pytest.mark.asyncio
    async def test_revokes_a_grantee_with_capture_and_readback(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        result = await RevokeFileShareExecutor().execute(
            _request(_drive_params(vendor, sa_key, revoke="grantee", grantee_email="mallory@example.com"))
        )
        assert result.status == ActionStatus.COMPLETED, result.error
        assert result.output["verified_by_readback"] is True
        # capture-before-write: the first vendor call after auth is the listing
        api_calls = [r for r in vendor.requests if "/token" not in r]
        assert api_calls[0].startswith("GET"), api_calls
        # the captured prior grants are the rollback payload
        captured = {g["id"] for g in result.rollback_data["grants"]}
        assert captured == {"p-mallory"}
        # the owner and the link survived a grantee-scoped revocation
        assert "p-owner" in vendor.permissions and "p-anyone" in vendor.permissions
        assert "p-mallory" not in vendor.permissions

    @pytest.mark.asyncio
    async def test_links_mode_removes_the_anyone_grant_only(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        result = await RevokeFileShareExecutor().execute(_request(_drive_params(vendor, sa_key, revoke="links")))
        assert result.status == ActionStatus.COMPLETED, result.error
        assert "p-anyone" not in vendor.permissions
        assert "p-mallory" in vendor.permissions

    @pytest.mark.asyncio
    async def test_a_lying_vendor_fails_the_action(self, sa_key: dict[str, Any]) -> None:
        """204 on the DELETE, grant still listed — the read-back is the check."""
        vendor = _DriveVendor(frozen=True)
        result = await RevokeFileShareExecutor().execute(
            _request(_drive_params(vendor, sa_key, revoke="grantee", grantee_email="mallory@example.com"))
        )
        assert result.status == ActionStatus.FAILED
        assert "read-back still shows" in (result.error or "")

    @pytest.mark.asyncio
    async def test_rollback_restores_the_captured_grant(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        params = _drive_params(vendor, sa_key, revoke="grantee", grantee_email="mallory@example.com")
        executor = RevokeFileShareExecutor()
        result = await executor.execute(_request(params))
        assert result.status == ActionStatus.COMPLETED
        assert await executor.rollback(result, params) is True
        emails = {p.get("emailAddress") for p in vendor.permissions.values()}
        assert "mallory@example.com" in emails

    @pytest.mark.asyncio
    async def test_nothing_matching_is_a_failure_not_a_silent_success(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        result = await RevokeFileShareExecutor().execute(
            _request(_drive_params(vendor, sa_key, revoke="grantee", grantee_email="nobody@example.com"))
        )
        assert result.status == ActionStatus.FAILED
        assert "nothing was revoked" in (result.error or "")

    @pytest.mark.asyncio
    async def test_probe_answers_gone_and_present(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        params = _drive_params(vendor, sa_key, revoke="grantee", grantee_email="mallory@example.com")
        assert await _probe_revoke_file_share(FILE, params) is False  # still present
        del vendor.permissions["p-mallory"]
        assert await _probe_revoke_file_share(FILE, params) is True  # gone
        assert await _probe_revoke_file_share(FILE, {"revoke": "grantee"}) is None  # unverifiable


# ---------------------------------------------------------------------------
# Microsoft Graph (OneDrive / SharePoint)
# ---------------------------------------------------------------------------


class _GraphVendor:
    def __init__(self) -> None:
        self.permissions: dict[str, dict[str, Any]] = {
            "g-owner": {"id": "g-owner", "roles": ["owner"], "grantedToV2": {"user": {"email": "owner@example.com"}}},
            "g-mallory": {"id": "g-mallory", "roles": ["write"], "grantedToV2": {"user": {"email": "mallory@example.com"}}},
            "g-link": {"id": "g-link", "roles": ["read"], "link": {"type": "view", "scope": "anonymous", "webUrl": "https://1drv.ms/old"}},
        }
        self.requests: list[str] = []
        self.invited: list[dict[str, Any]] = []
        self.links_created: list[dict[str, Any]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        import json as _json

        self.requests.append(f"{request.method} {request.url.path}")
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        if request.method == "GET" and path.endswith("/permissions"):
            return httpx.Response(200, json={"value": list(self.permissions.values())})
        if request.method == "DELETE" and "/permissions/" in path:
            self.permissions.pop(path.rsplit("/", 1)[-1], None)
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/invite"):
            body = _json.loads(request.content)
            self.invited.append(body)
            new_id = f"g-reinvited-{len(self.invited)}"
            self.permissions[new_id] = {
                "id": new_id,
                "roles": body["roles"],
                "grantedToV2": {"user": {"email": body["recipients"][0]["email"]}},
            }
            return httpx.Response(200, json={"value": [self.permissions[new_id]]})
        if request.method == "POST" and path.endswith("/createLink"):
            body = _json.loads(request.content)
            self.links_created.append(body)
            new_id = f"g-newlink-{len(self.links_created)}"
            self.permissions[new_id] = {
                "id": new_id,
                "roles": ["read"],
                "link": {"type": body["type"], "scope": body["scope"], "webUrl": "https://1drv.ms/NEW"},
            }
            return httpx.Response(201, json=self.permissions[new_id])
        return httpx.Response(404, json={"error": path})


def _graph_params(vendor: _GraphVendor, **extra: Any) -> dict[str, Any]:
    return {
        "azure_tenant_id": "t",
        "azure_client_id": "c",
        "azure_client_secret": "s",
        "drive_id": "drv-1",
        "_transport": httpx.MockTransport(vendor.handle),
        **extra,
    }


class TestGraphArm:
    @pytest.mark.asyncio
    async def test_revokes_links_and_rolls_back_with_a_new_url(self) -> None:
        vendor = _GraphVendor()
        params = _graph_params(vendor, revoke="links")
        executor = RevokeFileShareExecutor()
        result = await executor.execute(_request(params))
        assert result.status == ActionStatus.COMPLETED, result.error
        assert "g-link" not in vendor.permissions
        assert "g-mallory" in vendor.permissions  # scoped to links
        # the honest note travels on the result
        assert any("new URL" in n for n in result.output["notes"])
        # rollback re-creates the link (a NEW url, through createLink)
        assert await executor.rollback(result, params) is True
        assert vendor.links_created and vendor.links_created[0]["type"] == "view"

    @pytest.mark.asyncio
    async def test_grantee_rollback_restores_via_invite_without_mail(self) -> None:
        vendor = _GraphVendor()
        params = _graph_params(vendor, revoke="grantee", grantee_email="mallory@example.com")
        executor = RevokeFileShareExecutor()
        result = await executor.execute(_request(params))
        assert result.status == ActionStatus.COMPLETED, result.error
        assert await executor.rollback(result, params) is True
        assert vendor.invited and vendor.invited[0]["sendInvitation"] is False

    @pytest.mark.asyncio
    async def test_missing_drive_id_is_refused(self) -> None:
        vendor = _GraphVendor()
        params = _graph_params(vendor, revoke="links")
        params.pop("drive_id")
        result = await RevokeFileShareExecutor().execute(_request(params))
        assert result.status == ActionStatus.FAILED
        assert "drive_id" in (result.error or "")


# ---------------------------------------------------------------------------
# Box
# ---------------------------------------------------------------------------


class _BoxVendor:
    def __init__(self) -> None:
        self.collabs: dict[str, dict[str, Any]] = {
            "c-owner": {"id": "c-owner", "role": "owner", "accessible_by": {"type": "user", "login": "owner@example.com"}},
            "c-mallory": {"id": "c-mallory", "role": "editor", "accessible_by": {"type": "user", "login": "mallory@example.com"}},
        }
        self.shared_link: dict[str, Any] | None = {"url": "https://box.com/s/old", "access": "open"}
        self.requests: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        import json as _json

        self.requests.append(f"{request.method} {request.url.path}")
        path = request.url.path
        if request.method == "GET" and path.endswith("/collaborations"):
            return httpx.Response(200, json={"entries": list(self.collabs.values())})
        if request.method == "DELETE" and "/collaborations/" in path:
            self.collabs.pop(path.rsplit("/", 1)[-1], None)
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/collaborations"):
            body = _json.loads(request.content)
            new_id = f"c-restored-{len(self.collabs)}"
            self.collabs[new_id] = {"id": new_id, "role": body["role"], "accessible_by": body["accessible_by"]}
            return httpx.Response(201, json=self.collabs[new_id])
        if request.method == "GET" and f"/files/{FILE}" in path:
            return httpx.Response(200, json={"shared_link": self.shared_link})
        if request.method == "PUT" and f"/files/{FILE}" in path:
            body = _json.loads(request.content)
            if body.get("shared_link") is None:
                self.shared_link = None
            else:
                self.shared_link = {"url": "https://box.com/s/NEW", **body["shared_link"]}
            return httpx.Response(200, json={"shared_link": self.shared_link})
        return httpx.Response(404, json={"error": path})


class TestBoxArm:
    @pytest.mark.asyncio
    async def test_all_mode_revokes_collaboration_and_link_then_rolls_back(self) -> None:
        vendor = _BoxVendor()
        params = {"box_access_token": "tok", "_transport": httpx.MockTransport(vendor.handle), "revoke": "all"}
        executor = RevokeFileShareExecutor()
        result = await executor.execute(_request(params))
        assert result.status == ActionStatus.COMPLETED, result.error
        assert list(vendor.collabs) == ["c-owner"]  # owner survives "all"
        assert vendor.shared_link is None
        assert await executor.rollback(result, params) is True
        logins = {(c.get("accessible_by") or {}).get("login") for c in vendor.collabs.values()}
        assert "mallory@example.com" in logins
        assert vendor.shared_link is not None and vendor.shared_link["url"].endswith("NEW")


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------


class _DropboxVendor:
    def __init__(self) -> None:
        self.members: dict[str, str] = {"owner@example.com": "owner", "mallory@example.com": "editor"}
        self.links: list[str] = ["https://db.tt/old"]
        self.requests: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        import json as _json

        self.requests.append(request.url.path)
        path = request.url.path
        body = _json.loads(request.content) if request.content else {}
        if path.endswith("/list_file_members"):
            return httpx.Response(
                200,
                json={"users": [{"user": {"email": e}, "access_type": {".tag": level}} for e, level in self.members.items()]},
            )
        if path.endswith("/remove_file_member_2"):
            self.members.pop(body["member"]["email"], None)
            return httpx.Response(200, json={".tag": "success"})
        if path.endswith("/add_file_member"):
            self.members[body["members"][0]["email"]] = body["access_level"]
            return httpx.Response(200, json=[{"result": {".tag": "success"}}])
        if path.endswith("/list_shared_links"):
            return httpx.Response(200, json={"links": [{"url": u} for u in self.links]})
        if path.endswith("/revoke_shared_link"):
            self.links = [u for u in self.links if u != body["url"]]
            return httpx.Response(200)
        if path.endswith("/create_shared_link_with_settings"):
            self.links.append("https://db.tt/NEW")
            return httpx.Response(200, json={"url": "https://db.tt/NEW"})
        return httpx.Response(404, json={"error": path})


class TestDropboxArm:
    @pytest.mark.asyncio
    async def test_all_mode_revokes_member_and_link_then_rolls_back(self) -> None:
        vendor = _DropboxVendor()
        params = {"dropbox_access_token": "tok", "_transport": httpx.MockTransport(vendor.handle), "revoke": "all"}
        executor = RevokeFileShareExecutor()
        result = await executor.execute(_request(params))
        assert result.status == ActionStatus.COMPLETED, result.error
        assert list(vendor.members) == ["owner@example.com"]
        assert vendor.links == []
        assert any("new URL" in n for n in result.output["notes"])
        assert await executor.rollback(result, params) is True
        assert "mallory@example.com" in vendor.members
        assert vendor.links == ["https://db.tt/NEW"]


# ---------------------------------------------------------------------------
# The governed surface
# ---------------------------------------------------------------------------


class TestGovernance:
    def test_the_contract_declares_probe_and_reverse(self) -> None:
        contract = CAPABILITY_CONTRACTS["revoke_file_share"]
        assert contract.has_verification_probe is True
        assert contract.reverse_capability == "revoke_file_share"

    @pytest.mark.asyncio
    async def test_dry_run_through_the_builtin_touches_no_vendor(self, sa_key: dict[str, Any]) -> None:
        vendor = _DriveVendor()
        adapter = GoogleDriveRevokeFileShare()
        result = await adapter.execute(
            LiveActionRequest(
                request_id=uuid4(),
                capability="revoke_file_share",
                vendor_id="google_workspace",
                target=FILE,
                params=_drive_params(vendor, sa_key, revoke="grantee", grantee_email="mallory@example.com"),
                dry_run=True,
                requested_by="tester",
            )
        )
        assert result.status == LiveActionStatus.SIMULATED
        assert vendor.requests == [], "a dry run must not touch the vendor"

    def test_all_four_adapters_share_the_executor_and_the_capability(self) -> None:
        adapters = [GoogleDriveRevokeFileShare, M365RevokeFileShare, BoxRevokeFileShare, DropboxRevokeFileShare]
        assert {a.capability for a in adapters} == {"revoke_file_share"}
        assert {a.vendor_id for a in adapters} == {"google_workspace", "m365", "box", "dropbox"}
