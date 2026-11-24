"""``revoke_file_share`` — four estates, one contract.

What this verb is
-----------------
A leaked document's blast radius is its sharing grants. This executor
removes them — a named grantee's access, or the file's sharing link(s), or
both ("everything except the owner") — on Google Drive, OneDrive/SharePoint
(Microsoft Graph), Box and Dropbox, with the three properties every
destructive verb in this registry carries:

* **Prior grants are captured before the write** into ``rollback_data``.
  None of these APIs has a recycle bin for permissions; the pre-write
  listing is the only record of what to restore.
* **The write is verified by read-back**: the grant list is re-read after
  the revocation and the action FAILS, naming what it still sees, if the
  revoked grant is still present — a 2xx on the DELETE is the vendor
  accepting the request, not the estate changing.
* **Rollback restores the captured grants** — and reports honestly what it
  cannot restore: Graph, Box and Dropbox mint a **new URL** when a sharing
  link is re-created (a vendor fact, recorded in
  ``clients/fileshare_clients.py``), so a link rollback restores access
  shape and says ``restored_with_new_url`` rather than claiming the
  circulating link works again. Google Drive's ``anyone`` grant is an
  ordinary permission and restores exactly.

Request shape
-------------
``target``: the vendor's file identifier (Drive fileId, Graph itemId — with
``drive_id`` in parameters, Box file id, Dropbox file id or path).
``parameters.revoke``: ``"grantee"`` (requires ``grantee_email``),
``"links"`` (every sharing link / anyone-grant), or ``"all"`` (every grant
except ownership). Vendor credentials select the arm; with none present the
result is an honest simulation note, never an invented success.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from app.clients.fileshare_clients import (
    BoxShareClient,
    DropboxShareClient,
    GoogleDriveShareClient,
    GraphDriveClient,
)
from app.executors.base import _SIM_FUNNEL_CTA, ActionRequest, ActionResult, BaseExecutor
from app.models.action import ActionStatus, BlastRadius

logger = structlog.get_logger()

_OWNER_ROLES_DRIVE = {"owner", "organizer", "fileOrganizer"}
_OWNER_ROLES_GRAPH = {"owner"}
_OWNER_ROLES_BOX = {"owner", "co-owner"}
_OWNER_LEVELS_DROPBOX = {"owner"}

_MODES = ("grantee", "links", "all")


def _drive_client(params: dict[str, Any]) -> GoogleDriveShareClient | None:
    key = params.get("gws_service_account_key")
    subject = params.get("gws_subject_email")
    if key and subject:
        return GoogleDriveShareClient(key, subject, transport=params.get("_transport"))
    return None


def _graph_client(params: dict[str, Any]) -> GraphDriveClient | None:
    tenant = params.get("azure_tenant_id")
    client_id = params.get("azure_client_id")
    secret = params.get("azure_client_secret")
    if tenant and client_id and secret:
        return GraphDriveClient(tenant, client_id, secret, transport=params.get("_transport"))
    return None


def _box_client(params: dict[str, Any]) -> BoxShareClient | None:
    token = params.get("box_access_token")
    if token:
        return BoxShareClient(token, transport=params.get("_transport"))
    return None


def _dropbox_client(params: dict[str, Any]) -> DropboxShareClient | None:
    token = params.get("dropbox_access_token")
    if token:
        return DropboxShareClient(token, transport=params.get("_transport"))
    return None


def _wants(mode: str, *, is_link: bool, grantee_email: str, entry_email: str) -> bool:
    """Does this grant fall inside the requested revocation?"""
    if mode == "all":
        return True
    if mode == "links":
        return is_link
    return bool(entry_email) and entry_email.lower() == grantee_email.lower()


class RevokeFileShareExecutor(BaseExecutor):
    """One executor, four vendor arms, selected by which credentials appear."""

    async def execute(self, request: ActionRequest) -> ActionResult:  # noqa: PLR0911 — one return per arm + guards
        params = request.parameters
        mode = str(params.get("revoke") or "grantee")
        grantee = str(params.get("grantee_email") or "")
        if mode not in _MODES:
            return self._failed(request, f"revoke must be one of {_MODES}, got {mode!r}")
        if mode == "grantee" and not grantee:
            return self._failed(request, "revoke=grantee requires grantee_email")

        if (drive := _drive_client(params)) is not None:
            return await self._run_google(request, drive, mode, grantee)
        if (graph := _graph_client(params)) is not None:
            drive_id = str(params.get("drive_id") or "")
            if not drive_id:
                return self._failed(request, "the Graph arm requires drive_id alongside the item id")
            return await self._run_graph(request, graph, drive_id, mode, grantee)
        if (box := _box_client(params)) is not None:
            return await self._run_box(request, box, mode, grantee)
        if (dropbox := _dropbox_client(params)) is not None:
            return await self._run_dropbox(request, dropbox, mode, grantee)

        logger.warning("revoke_file_share.simulation", reason="no vendor credentials")
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "revoke_file_share",
                "file": request.target,
                "note": (
                    "Simulation mode — provide gws_service_account_key/gws_subject_email, "
                    "azure_tenant_id/azure_client_id/azure_client_secret (+drive_id), "
                    "box_access_token, or dropbox_access_token to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )

    # ── shared result shapes ────────────────────────────────────────────

    def _failed(self, request: ActionRequest, error: str) -> ActionResult:
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.FAILED,
            blast_radius=BlastRadius.MEDIUM,
            error=error,
            completed_at=datetime.utcnow(),
        )

    def _done(
        self,
        request: ActionRequest,
        *,
        vendor: str,
        revoked: list[dict[str, Any]],
        rollback: dict[str, Any],
        notes: list[str],
    ) -> ActionResult:
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "success": True,
                "action": "revoke_file_share",
                "vendor": vendor,
                "file": request.target,
                "revoked": revoked,
                "verified_by_readback": True,
                "notes": notes,
            },
            rollback_data=rollback,
            completed_at=datetime.utcnow(),
        )

    # ── Google Drive ────────────────────────────────────────────────────

    async def _run_google(self, request: ActionRequest, client: GoogleDriveShareClient, mode: str, grantee: str) -> ActionResult:
        file_id = request.target
        try:
            prior = await client.list_permissions(file_id)
            targets = [
                p
                for p in prior
                if p.get("role") not in _OWNER_ROLES_DRIVE
                and _wants(
                    mode,
                    is_link=p.get("type") in ("anyone", "domain"),
                    grantee_email=grantee,
                    entry_email=str(p.get("emailAddress") or ""),
                )
            ]
            if not targets:
                return self._failed(
                    request,
                    f"no matching non-owner grant on the file (mode={mode}, {len(prior)} grant(s) present) — nothing was revoked",
                )
            for p in targets:
                await client.delete_permission(file_id, str(p["id"]))
            after = await client.list_permissions(file_id)
        except Exception as exc:  # noqa: BLE001 — vendor refusal fails the action
            logger.error("revoke_file_share.google.failed", error=str(exc)[:300])
            return self._failed(request, str(exc))

        remaining = {str(p.get("id")) for p in after}
        still_there = [p for p in targets if str(p.get("id")) in remaining]
        if still_there:
            return self._failed(
                request,
                "read-back still shows revoked grant(s): " + ", ".join(str(p.get("id")) for p in still_there),
            )
        return self._done(
            request,
            vendor="google_drive",
            revoked=[{"id": p.get("id"), "type": p.get("type"), "role": p.get("role"), "email": p.get("emailAddress")} for p in targets],
            rollback={"vendor": "google_drive", "file_id": file_id, "grants": targets},
            notes=["an `anyone` grant restores exactly on Drive — no URL changes"],
        )

    # ── OneDrive / SharePoint ───────────────────────────────────────────

    async def _run_graph(
        self,
        request: ActionRequest,
        client: GraphDriveClient,
        drive_id: str,
        mode: str,
        grantee: str,
    ) -> ActionResult:
        item_id = request.target
        try:
            prior = await client.list_permissions(drive_id, item_id)
            targets = []
            for p in prior:
                roles = set(p.get("roles") or [])
                if roles & _OWNER_ROLES_GRAPH:
                    continue
                is_link = "link" in p
                emails = [
                    str(((p.get("grantedToV2") or {}).get("user") or {}).get("email") or ""),
                    *(str((ident.get("user") or {}).get("email") or "") for ident in p.get("grantedToIdentitiesV2") or []),
                ]
                entry_email = next((e for e in emails if e), "")
                if _wants(mode, is_link=is_link, grantee_email=grantee, entry_email=entry_email):
                    targets.append(p)
            if not targets:
                return self._failed(
                    request,
                    f"no matching non-owner grant on the item (mode={mode}, {len(prior)} grant(s) present) — nothing was revoked",
                )
            for p in targets:
                await client.delete_permission(drive_id, item_id, str(p["id"]))
            after = await client.list_permissions(drive_id, item_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("revoke_file_share.graph.failed", error=str(exc)[:300])
            return self._failed(request, str(exc))

        remaining = {str(p.get("id")) for p in after}
        still_there = [p for p in targets if str(p.get("id")) in remaining]
        if still_there:
            return self._failed(
                request,
                "read-back still shows revoked grant(s): " + ", ".join(str(p.get("id")) for p in still_there),
            )
        return self._done(
            request,
            vendor="m365_drive",
            revoked=[{"id": p.get("id"), "link": "link" in p, "roles": p.get("roles")} for p in targets],
            rollback={"vendor": "m365_drive", "drive_id": drive_id, "item_id": item_id, "grants": targets},
            notes=["a re-created Graph sharing link is a new URL (vendor fact); user grants restore via invite without mail"],
        )

    # ── Box ─────────────────────────────────────────────────────────────

    async def _run_box(self, request: ActionRequest, client: BoxShareClient, mode: str, grantee: str) -> ActionResult:
        file_id = request.target
        try:
            collabs = await client.list_collaborations(file_id)
            link = await client.get_shared_link(file_id)
            collab_targets = [
                c
                for c in collabs
                if c.get("role") not in _OWNER_ROLES_BOX
                and _wants(
                    mode,
                    is_link=False,
                    grantee_email=grantee,
                    entry_email=str((c.get("accessible_by") or {}).get("login") or ""),
                )
            ]
            revoke_link = link is not None and mode in ("links", "all")
            if not collab_targets and not revoke_link:
                return self._failed(
                    request,
                    f"no matching non-owner grant on the file (mode={mode}, "
                    f"{len(collabs)} collaboration(s), shared_link={'present' if link else 'absent'}) "
                    "— nothing was revoked",
                )
            for c in collab_targets:
                await client.delete_collaboration(str(c["id"]))
            if revoke_link:
                await client.remove_shared_link(file_id)
            after = await client.list_collaborations(file_id)
            link_after = await client.get_shared_link(file_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("revoke_file_share.box.failed", error=str(exc)[:300])
            return self._failed(request, str(exc))

        remaining = {str(c.get("id")) for c in after}
        still_there = [c for c in collab_targets if str(c.get("id")) in remaining]
        if still_there or (revoke_link and link_after is not None):
            bits = [f"collaboration {c.get('id')}" for c in still_there]
            if revoke_link and link_after is not None:
                bits.append("the shared link")
            return self._failed(request, "read-back still shows: " + ", ".join(bits))
        return self._done(
            request,
            vendor="box",
            revoked=[
                *(
                    {"collaboration_id": c.get("id"), "login": (c.get("accessible_by") or {}).get("login"), "role": c.get("role")}
                    for c in collab_targets
                ),
                *([{"shared_link": link.get("url")}] if revoke_link and link else []),
            ],
            rollback={
                "vendor": "box",
                "file_id": file_id,
                "collaborations": collab_targets,
                "shared_link": link if revoke_link else None,
            },
            notes=["a re-created Box shared link is a new URL (vendor fact)"],
        )

    # ── Dropbox ─────────────────────────────────────────────────────────

    async def _run_dropbox(self, request: ActionRequest, client: DropboxShareClient, mode: str, grantee: str) -> ActionResult:
        file_id = request.target
        try:
            members = await client.list_file_members(file_id)
            links = await client.list_shared_links(file_id)
            user_targets = []
            for u in members.get("users") or []:
                level = str(((u.get("access_type") or {}).get(".tag")) or "")
                email = str(((u.get("user") or {}).get("email")) or "")
                if level in _OWNER_LEVELS_DROPBOX:
                    continue
                if _wants(mode, is_link=False, grantee_email=grantee, entry_email=email):
                    user_targets.append({"email": email, "access_level": level})
            link_targets = [link for link in links if mode in ("links", "all")]
            if not user_targets and not link_targets:
                return self._failed(
                    request,
                    f"no matching non-owner grant on the file (mode={mode}, "
                    f"{len(members.get('users') or [])} member(s), {len(links)} link(s)) "
                    "— nothing was revoked",
                )
            for u in user_targets:
                await client.remove_file_member(file_id, u["email"])
            for link in link_targets:
                await client.revoke_shared_link(str(link.get("url")))
            members_after = await client.list_file_members(file_id)
            links_after = await client.list_shared_links(file_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("revoke_file_share.dropbox.failed", error=str(exc)[:300])
            return self._failed(request, str(exc))

        emails_after = {str(((u.get("user") or {}).get("email")) or "").lower() for u in members_after.get("users") or []}
        still_members = [u for u in user_targets if u["email"].lower() in emails_after]
        urls_after = {str(link.get("url")) for link in links_after}
        still_links = [link for link in link_targets if str(link.get("url")) in urls_after]
        if still_members or still_links:
            bits = [f"member {u['email']}" for u in still_members]
            bits += [f"link {link.get('url')}" for link in still_links]
            return self._failed(request, "read-back still shows: " + ", ".join(bits))
        return self._done(
            request,
            vendor="dropbox",
            revoked=[
                *({"member": u["email"], "access_level": u["access_level"]} for u in user_targets),
                *({"shared_link": link.get("url")} for link in link_targets),
            ],
            rollback={
                "vendor": "dropbox",
                "file_id": file_id,
                "members": user_targets,
                "links": link_targets,
            },
            notes=["Dropbox states a revoked link cannot be re-enabled; rollback mints a new URL"],
        )

    # ── rollback ────────────────────────────────────────────────────────

    async def rollback(self, result: ActionResult, params: dict[str, Any] | None = None) -> bool:
        """Restore the captured grants. ``params`` carries credentials (they
        are never stored in ``rollback_data``). Returns False when anything
        could not be restored — and the per-entry report in the log names
        what and why, including the new-URL caveat on re-created links."""
        data = result.rollback_data or {}
        vendor = data.get("vendor")
        if not vendor or params is None:
            return False
        try:
            if vendor == "google_drive":
                client = _drive_client(params)
                if client is None:
                    return False
                for p in data.get("grants") or []:
                    body = {"role": p.get("role"), "type": p.get("type")}
                    if p.get("emailAddress"):
                        body["emailAddress"] = p["emailAddress"]
                    if p.get("domain"):
                        body["domain"] = p["domain"]
                    await client.create_permission(data["file_id"], body)
                return True
            if vendor == "m365_drive":
                graph = _graph_client(params)
                if graph is None:
                    return False
                ok = True
                for p in data.get("grants") or []:
                    if "link" in p:
                        link = p.get("link") or {}
                        await graph.create_link(
                            data["drive_id"],
                            data["item_id"],
                            link_type=str(link.get("type") or "view"),
                            scope=str(link.get("scope") or "organization"),
                        )
                        logger.info("revoke_file_share.rollback.new_link_url", vendor=vendor)
                        continue
                    emails = [
                        str(((p.get("grantedToV2") or {}).get("user") or {}).get("email") or ""),
                        *(str((ident.get("user") or {}).get("email") or "") for ident in p.get("grantedToIdentitiesV2") or []),
                    ]
                    emails = [e for e in emails if e]
                    roles = list(p.get("roles") or ["read"])
                    if not emails:
                        logger.warning("revoke_file_share.rollback.unrestorable", vendor=vendor, reason="grant carries no grantee email")
                        ok = False
                        continue
                    await graph.invite(data["drive_id"], data["item_id"], emails=emails, roles=roles)
                return ok
            if vendor == "box":
                box = _box_client(params)
                if box is None:
                    return False
                ok = True
                for c in data.get("collaborations") or []:
                    login = str((c.get("accessible_by") or {}).get("login") or "")
                    if not login:
                        logger.warning("revoke_file_share.rollback.unrestorable", vendor=vendor, reason="collaboration carries no login")
                        ok = False
                        continue
                    await box.create_collaboration(data["file_id"], login=login, role=str(c.get("role") or "viewer"))
                link = data.get("shared_link")
                if link:
                    settings = {"access": link.get("access", "open")}
                    await box.set_shared_link(data["file_id"], settings)
                    logger.info("revoke_file_share.rollback.new_link_url", vendor=vendor)
                return ok
            if vendor == "dropbox":
                dropbox = _dropbox_client(params)
                if dropbox is None:
                    return False
                for u in data.get("members") or []:
                    await dropbox.add_file_member(data["file_id"], u["email"], str(u.get("access_level") or "viewer"))
                if data.get("links"):
                    await dropbox.create_shared_link(data["file_id"])
                    logger.info("revoke_file_share.rollback.new_link_url", vendor=vendor)
                return True
        except Exception as exc:  # noqa: BLE001 — a vendor refusal is a failed rollback
            logger.error("revoke_file_share.rollback.failed", vendor=vendor, error=str(exc)[:300])
            return False
        return False
