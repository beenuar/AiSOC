"""Share-permission clients for the four file-sharing estates (WS4.5).

One capability — ``revoke_file_share`` — four vendors, and the client layer
holds only the vendor verbs the executor composes: list the grants on a
file, delete one, and re-create one (the rollback half). Every method shape
is taken from the vendor's own published contract, cited per class; nothing
is guessed, and a field the vendor does not publish is not invented.

Two vendor facts the executor's honesty depends on, recorded here because
they are vendor facts rather than implementation choices:

* **A revoked sharing link cannot be un-revoked.** Google Drive is the
  exception (an ``anyone`` grant is an ordinary permission that restores
  like any other); Microsoft Graph, Box and Dropbox all mint a **new URL**
  when a link is re-created, so a rollback of a link revocation restores
  *access shape*, not the circulating URL — the executor reports exactly
  that instead of claiming a restore it cannot make.
* **Capture must come before the write**, because none of these APIs offers
  a recycle bin for permissions: the pre-write listing is the only record
  of what to restore.

All clients take an optional ``transport`` so tests drive the real request
construction against a mock vendor (the house seam, per
``test_sync_detection_rule_vendor_arms.py``).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.clients.google_workspace_client import GoogleWorkspaceClient

logger = structlog.get_logger()

_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Google Drive (Drive API v3)
# ---------------------------------------------------------------------------

_DRIVE = "https://www.googleapis.com/drive/v3"

#: Full Drive scope: permission deletes and creates are writes. Domain-wide
#: delegation must authorize this scope for the service account; it is a
#: separate grant from the Admin SDK scopes the parent client mints.
_DRIVE_SCOPES = "https://www.googleapis.com/auth/drive"


class GoogleDriveShareClient(GoogleWorkspaceClient):
    """Drive v3 permissions, per Google's published reference.

    Contract: ``GET/POST /drive/v3/files/{fileId}/permissions`` and
    ``DELETE /drive/v3/files/{fileId}/permissions/{permissionId}``
    (https://developers.google.com/drive/api/reference/rest/v3/permissions).
    ``supportsAllDrives=true`` rides every call so shared-drive items work;
    an ``anyone`` permission is Drive's spelling of a sharing link.
    """

    _scopes = _DRIVE_SCOPES

    def __init__(
        self,
        service_account_key: str | dict,
        subject_email: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(service_account_key, subject_email)
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=self._transport)

    async def list_permissions(self, file_id: str) -> list[dict[str, Any]]:
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_DRIVE}/files/{file_id}/permissions",
                headers=self._headers(),
                params={
                    "supportsAllDrives": "true",
                    "fields": "permissions(id,type,role,emailAddress,domain,allowFileDiscovery,expirationTime)",
                },
            )
            resp.raise_for_status()
            return list(resp.json().get("permissions") or [])

    async def delete_permission(self, file_id: str, permission_id: str) -> None:
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.delete(
                f"{_DRIVE}/files/{file_id}/permissions/{permission_id}",
                headers=self._headers(),
                params={"supportsAllDrives": "true"},
            )
            resp.raise_for_status()

    async def create_permission(self, file_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """The rollback half. ``sendNotificationEmail=false`` — restoring a
        grant during an investigation must not mail the grantee."""
        params: dict[str, str] = {"supportsAllDrives": "true"}
        # Drive refuses sendNotificationEmail=false for `anyone`; only
        # user/group grants accept it (the reference's own constraint).
        if body.get("type") in ("user", "group"):
            params["sendNotificationEmail"] = "false"
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_DRIVE}/files/{file_id}/permissions",
                headers=self._headers(),
                params=params,
                json=body,
            )
            resp.raise_for_status()
            return dict(resp.json())


# ---------------------------------------------------------------------------
# OneDrive / SharePoint (Microsoft Graph)
# ---------------------------------------------------------------------------

_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


class GraphDriveClient:
    """DriveItem permissions, per Microsoft Graph's published reference.

    Contract: ``GET /drives/{drive-id}/items/{item-id}/permissions``,
    ``DELETE .../permissions/{perm-id}``, restore of user/group grants via
    ``POST .../invite`` and of links via ``POST .../createLink``
    (https://learn.microsoft.com/graph/api/driveitem-list-permissions,
    driveitem-invite, driveitem-createlink). A re-created link is a **new
    URL** — Graph has no un-revoke.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._tenant = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=self._transport)

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if self._token:
            return
        resp = await client.post(
            _GRAPH_LOGIN.format(tenant=self._tenant),
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        self._token = str(resp.json()["access_token"])

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def list_permissions(self, drive_id: str, item_id: str) -> list[dict[str, Any]]:
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/drives/{drive_id}/items/{item_id}/permissions",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return list(resp.json().get("value") or [])

    async def delete_permission(self, drive_id: str, item_id: str, permission_id: str) -> None:
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.delete(
                f"{_GRAPH}/drives/{drive_id}/items/{item_id}/permissions/{permission_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()

    async def invite(self, drive_id: str, item_id: str, *, emails: list[str], roles: list[str]) -> dict[str, Any]:
        """Restore a user/group grant. ``sendInvitation=false`` +
        ``requireSignIn=true`` — a rollback must not mail anyone."""
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_GRAPH}/drives/{drive_id}/items/{item_id}/invite",
                headers=self._headers(),
                json={
                    "recipients": [{"email": e} for e in emails],
                    "roles": roles,
                    "requireSignIn": True,
                    "sendInvitation": False,
                },
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def create_link(self, drive_id: str, item_id: str, *, link_type: str, scope: str) -> dict[str, Any]:
        async with self._client() as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_GRAPH}/drives/{drive_id}/items/{item_id}/createLink",
                headers=self._headers(),
                json={"type": link_type, "scope": scope},
            )
            resp.raise_for_status()
            return dict(resp.json())


# ---------------------------------------------------------------------------
# Box
# ---------------------------------------------------------------------------

_BOX = "https://api.box.com/2.0"


class BoxShareClient:
    """File collaborations + shared links, per Box's published reference.

    Contract: ``GET /2.0/files/{id}/collaborations``,
    ``DELETE /2.0/collaborations/{id}``, ``POST /2.0/collaborations``
    (https://developer.box.com/reference/get-files-id-collaborations,
    delete-collaborations-id, post-collaborations); the shared link lives
    on the file object itself — read with a ``fields=shared_link`` GET,
    remove by ``PUT`` with ``{"shared_link": null}``, re-create by ``PUT``
    with settings (put-files-id). A re-created link is a **new URL**.
    """

    def __init__(self, access_token: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._token = access_token
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=self._transport)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def list_collaborations(self, file_id: str) -> list[dict[str, Any]]:
        async with self._client() as client:
            resp = await client.get(f"{_BOX}/files/{file_id}/collaborations", headers=self._headers())
            resp.raise_for_status()
            return list(resp.json().get("entries") or [])

    async def delete_collaboration(self, collaboration_id: str) -> None:
        async with self._client() as client:
            resp = await client.delete(f"{_BOX}/collaborations/{collaboration_id}", headers=self._headers())
            resp.raise_for_status()

    async def create_collaboration(self, file_id: str, *, login: str, role: str) -> dict[str, Any]:
        async with self._client() as client:
            resp = await client.post(
                f"{_BOX}/collaborations",
                headers=self._headers(),
                json={
                    "item": {"type": "file", "id": file_id},
                    "accessible_by": {"type": "user", "login": login},
                    "role": role,
                },
                params={"notify": "false"},
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def get_shared_link(self, file_id: str) -> dict[str, Any] | None:
        async with self._client() as client:
            resp = await client.get(
                f"{_BOX}/files/{file_id}",
                headers=self._headers(),
                params={"fields": "shared_link"},
            )
            resp.raise_for_status()
            return resp.json().get("shared_link")

    async def remove_shared_link(self, file_id: str) -> None:
        async with self._client() as client:
            resp = await client.put(
                f"{_BOX}/files/{file_id}",
                headers=self._headers(),
                params={"fields": "shared_link"},
                json={"shared_link": None},
            )
            resp.raise_for_status()

    async def set_shared_link(self, file_id: str, settings: dict[str, Any]) -> dict[str, Any]:
        async with self._client() as client:
            resp = await client.put(
                f"{_BOX}/files/{file_id}",
                headers=self._headers(),
                params={"fields": "shared_link"},
                json={"shared_link": settings},
            )
            resp.raise_for_status()
            return dict(resp.json())


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------

_DROPBOX = "https://api.dropboxapi.com/2"


class DropboxShareClient:
    """File members + shared links, per Dropbox's published reference.

    Contract: ``POST /2/sharing/list_file_members``,
    ``POST /2/sharing/remove_file_member_2``,
    ``POST /2/sharing/add_file_member`` (``quiet=true`` — no mail on
    rollback), ``POST /2/sharing/list_shared_links`` (``direct_only``),
    ``POST /2/sharing/revoke_shared_link``,
    ``POST /2/sharing/create_shared_link_with_settings``
    (https://www.dropbox.com/developers/documentation/http/documentation).
    Dropbox states revoked links cannot be re-enabled; a re-created link is
    a **new URL**.
    """

    def __init__(self, access_token: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._token = access_token
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=_TIMEOUT, transport=self._transport)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        async with self._client() as client:
            resp = await client.post(f"{_DROPBOX}{path}", headers=self._headers(), json=body)
            resp.raise_for_status()
            if resp.content:
                return resp.json()
            return None

    async def list_file_members(self, file_id: str) -> dict[str, Any]:
        return dict(await self._post("/sharing/list_file_members", {"file": file_id}))

    async def remove_file_member(self, file_id: str, member_email: str) -> dict[str, Any]:
        out = await self._post(
            "/sharing/remove_file_member_2",
            {"file": file_id, "member": {".tag": "email", "email": member_email}},
        )
        return dict(out or {})

    async def add_file_member(self, file_id: str, member_email: str, access_level: str) -> dict[str, Any]:
        out = await self._post(
            "/sharing/add_file_member",
            {
                "file": file_id,
                "members": [{".tag": "email", "email": member_email}],
                "access_level": access_level,
                "quiet": True,
            },
        )
        return {"result": out}

    async def list_shared_links(self, file_id: str) -> list[dict[str, Any]]:
        out = await self._post("/sharing/list_shared_links", {"path": file_id, "direct_only": True})
        return list((out or {}).get("links") or [])

    async def revoke_shared_link(self, url: str) -> None:
        await self._post("/sharing/revoke_shared_link", {"url": url})

    async def create_shared_link(self, file_id: str) -> dict[str, Any]:
        out = await self._post(
            "/sharing/create_shared_link_with_settings",
            {"path": file_id, "settings": {"audience": {".tag": "public"}}},
        )
        return dict(out or {})
